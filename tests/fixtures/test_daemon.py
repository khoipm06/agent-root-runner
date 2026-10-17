"""Standalone Reference Test Daemon for Agent Root Runner.

Implements the complete IPC protocol, fail-closed Arm/Disarm state machine,
auto-lock timer, guardrails evaluator, subprocess execution with killpg,
and structured NDJSON audit logging in user space without requiring sudo.
"""

import argparse
import asyncio
import json
import os
import re
import shlex
import signal
import socket
import struct
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

CLEAN_ENV = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "USER": os.environ.get("USER", "root"),
    "HOME": os.environ.get("HOME", "/root"),
    "SHELL": "/bin/bash",
    "TERM": "xterm-256color",
}

FORBIDDEN_ENV_PREFIXES = ("LD_", "PYTHON", "PERL", "RUBY", "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS")


class TestGuardrailEvaluator:
    """Evaluates commands against Destabilization Guardrails (R4)."""

    PROTECTED_DISKS = (
        "/dev/nvme0n1",
        "/dev/nvme0n1p",
        "/dev/sda",
        "/dev/vda",
        "/dev/mapper/",
        "/dev/root",
        "/dev/boot",
    )

    PROTECTED_AUTH_PATHS = (
        "/etc/pam.d",
        "/etc/pam.conf",
        "/etc/security",
        "/etc/sudoers",
        "/etc/shadow",
        "/etc/passwd",
        "/etc/group",
        "/root/.ssh",
        "/.ssh/authorized_keys",
    )

    FORBIDDEN_NETWORK_PATTERNS = [
        re.compile(r"\biptables\s+(-[FX]|--flush|--delete-chain)\b"),
        re.compile(r"\bip6tables\s+(-[FX]|--flush)\b"),
        re.compile(r"\bnft\s+flush\s+ruleset\b"),
        re.compile(r"\bnft\s+delete\s+table\b"),
        re.compile(r"\bip\s+link\s+set\s+.*\s+down\b"),
        re.compile(r"\bsystemctl\s+(stop|disable|mask)\s+(NetworkManager|systemd-networkd|firewalld)\b"),
        re.compile(r"\bnmcli\s+networking\s+off\b"),
        re.compile(r"\bnmcli\s+radio\s+all\s+off\b"),
    ]

    FORBIDDEN_BOOTLOADER_PATTERNS = [
        re.compile(r"\bgrub2?-install\b"),
        re.compile(r"\bgrub2?-mkconfig\b"),
        re.compile(r"\befibootmgr\s+.*-[Bo]\b"),
        re.compile(r"\brm\s+.*-(r|f|rf|fr).*\s+/boot\b"),
        re.compile(r"\brm\s+.*-(r|f|rf|fr).*\s+/sys/firmware/efi/efivars\b"),
        re.compile(r"\bostree\s+admin\s+(unlock|undeploy|cleanup)\b"),
        re.compile(r"\brmmod\b"),
        re.compile(r"\binsmod\b"),
        re.compile(r"\bmodprobe\s+(-r|--remove)\b"),
    ]

    @classmethod
    def evaluate(cls, cmd_str: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """Returns (allowed, rule_name, reason)."""
        stripped = cmd_str.strip()
        if not stripped:
            return True, None, None

        # 1. Pipe-to-shell stream evasion
        if re.search(r"\|\s*(sh|bash|zsh|python3?)\s*($|[;&|])", stripped):
            return False, "RULE_EVASION_PIPE_SHELL", "Piping arbitrary stream into shell interpreter is prohibited"

        # 2. Fork bomb detection
        if ":(){ :|:& };:" in stripped or re.search(r"\w+\(\)\s*\{\s*\w+\s*\|\s*\w+\s*&\s*\};\s*\w+", stripped):
            return False, "RULE_RESOURCE_FORK_BOMB", "Fork bomb pattern detected"

        # 3. Unresolvable variables in destructive commands
        if re.search(r"\b(dd|rm|mkfs|wipefs|fdisk)\b.*\$[A-Za-z_]", stripped):
            return False, "RULE_EVASION_UNRESOLVED_VAR", "Unresolvable variable expansion in destructive command"

        # 4. Raw block device / disk writes
        # Check dd of=...
        dd_match = re.search(r"\bdd\s+.*of=([^\s]+)", stripped)
        if dd_match:
            target = dd_match.group(1)
            for disk in cls.PROTECTED_DISKS:
                if disk in target:
                    return False, "RULE_BLOCK_DEV_RAW_WRITE", f"Raw write to protected block device {target} blocked"

        # Check mkfs
        if re.search(r"\bmkfs(\.[a-z0-9]+)?\s+", stripped):
            for disk in cls.PROTECTED_DISKS:
                if disk in stripped:
                    return False, "RULE_BLOCK_DEV_FORMAT", f"Formatting protected block device {disk} blocked"

        # Check fdisk / parted / wipefs / blkdiscard (unless read-only -l / print)
        if re.search(r"\bfdisk\b", stripped) and not re.search(r"\b-[l]\b|--list", stripped):
            for disk in cls.PROTECTED_DISKS:
                if disk in stripped:
                    return False, "RULE_BLOCK_DEV_PARTITION", f"Destructive fdisk on {disk} blocked"

        if re.search(r"\bparted\b", stripped) and not re.search(r"\bprint\b", stripped):
            for disk in cls.PROTECTED_DISKS:
                if disk in stripped:
                    return False, "RULE_BLOCK_DEV_PARTITION", f"Destructive parted on {disk} blocked"

        if re.search(r"\b(wipefs|blkdiscard)\b", stripped):
            for disk in cls.PROTECTED_DISKS:
                if disk in stripped:
                    return False, "RULE_BLOCK_DEV_PARTITION", f"Wiping block device {disk} blocked"

        # Check raw redirection to block device (> /dev/...)
        redir_match = re.search(r">\s*([^\s]+)", stripped)
        if redir_match:
            target = redir_match.group(1)
            for disk in cls.PROTECTED_DISKS:
                if disk in target:
                    return False, "RULE_BLOCK_DEV_RAW_WRITE", f"Redirection to protected block device {target} blocked"

        # 5. Critical Auth and Access Files Defense
        for auth_path in cls.PROTECTED_AUTH_PATHS:
            if auth_path in stripped:
                # Disallow mutation: rm, sed -i, truncate, chmod, chown, mv, cp, redirection
                if re.search(r"\b(rm|unlink|truncate|chmod|chown|chgrp|mv|cp)\b", stripped) or "sed -i" in stripped or ">" in stripped:
                    return False, "RULE_AUTH_FILE_MUTATION", f"Modification of critical authentication asset {auth_path} blocked"

        # 6. Network Isolation Defense
        for pattern in cls.FORBIDDEN_NETWORK_PATTERNS:
            if pattern.search(stripped):
                return False, "RULE_NETWORK_ISOLATION", f"Destructive network isolation command blocked: {stripped}"

        # 7. Bootloader & Kernel Tampering Defense
        for pattern in cls.FORBIDDEN_BOOTLOADER_PATTERNS:
            if pattern.search(stripped):
                return False, "RULE_BOOTLOADER_TAMPERING", f"Bootloader or kernel modification blocked: {stripped}"

        return True, None, None


class TestAuditLogger:
    """Appends structured NDJSON records to audit log."""

    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)

    def log(self, event_type: str, details: Dict[str, Any]) -> None:
        record = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event_type": event_type,
            "pid": os.getpid(),
            "uid": os.getuid(),
            "gid": os.getgid(),
            **details,
        }
        line = json.dumps(record) + "\n"
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()


class TestDaemonServer:
    """Asyncio Unix domain socket JSON-RPC 2.0 daemon for test automation."""

    def __init__(
        self,
        socket_path: str,
        audit_log_path: str,
        allow_user_arm: bool = True,
    ):
        self.socket_path = socket_path
        self.audit_logger = TestAuditLogger(audit_log_path)
        self.allow_user_arm = allow_user_arm

        self.state = "DISARMED"
        self.session_id: Optional[str] = None
        self.armed_at: Optional[float] = None
        self.expires_at_monotonic: Optional[float] = None
        self.duration_seconds: int = 900
        self.quota_remaining: Optional[int] = None
        self.commands_executed: int = 0

        self._lock = asyncio.Lock()
        self._timer_task: Optional[asyncio.Task] = None
        self._server: Optional[asyncio.AbstractServer] = None
        self._running = False

    async def _auto_lock_countdown(self, seconds: float):
        try:
            await asyncio.sleep(seconds)
            async with self._lock:
                if self.state == "ARMED":
                    self.state = "DISARMED"
                    self.audit_logger.log(
                        "TIMEOUT_LOCK",
                        {"session_id": self.session_id, "reason": "auto_lock_expired"},
                    )
                    self.session_id = None
        except asyncio.CancelledError:
            pass

    async def arm(self, duration_seconds: int = 900, quota: Optional[int] = None, caller_uid: int = 0) -> Dict[str, Any]:
        async with self._lock:
            if not self.allow_user_arm and caller_uid != 0:
                raise PermissionError("Arming requires root privileges (sudo)")

            if self._timer_task:
                self._timer_task.cancel()

            self.state = "ARMED"
            self.session_id = f"arm_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            self.armed_at = time.time()
            self.duration_seconds = duration_seconds
            self.expires_at_monotonic = time.monotonic() + duration_seconds
            self.quota_remaining = quota
            self.commands_executed = 0

            self._timer_task = asyncio.create_task(self._auto_lock_countdown(duration_seconds))
            self.audit_logger.log(
                "ARM",
                {
                    "session_id": self.session_id,
                    "duration_seconds": duration_seconds,
                    "quota": quota,
                    "caller_uid": caller_uid,
                },
            )
            return {
                "state": "ARMED",
                "session_id": self.session_id,
                "duration_seconds": duration_seconds,
                "quota": quota,
            }

    async def disarm(self) -> Dict[str, Any]:
        async with self._lock:
            if self._timer_task:
                self._timer_task.cancel()
                self._timer_task = None
            self.state = "DISARMED"
            self.audit_logger.log("DISARM", {"session_id": self.session_id, "reason": "manual_disarm"})
            self.session_id = None
            return {"state": "DISARMED", "message": "Service successfully disarmed and locked."}

    async def get_status(self) -> Dict[str, Any]:
        async with self._lock:
            # Passive check
            if self.state == "ARMED" and self.expires_at_monotonic and time.monotonic() >= self.expires_at_monotonic:
                self.state = "DISARMED"
                self.session_id = None

            remaining = 0.0
            if self.state == "ARMED" and self.expires_at_monotonic:
                remaining = max(0.0, self.expires_at_monotonic - time.monotonic())

            return {
                "state": self.state,
                "session_id": self.session_id,
                "remaining_seconds": remaining,
                "quota_remaining": self.quota_remaining,
                "commands_executed": self.commands_executed,
                "socket_path": self.socket_path,
                "daemon_pid": os.getpid(),
            }

    async def execute_command(
        self,
        command: str,
        timeout_seconds: int = 60,
        workdir: str = "/",
        env: Optional[Dict[str, str]] = None,
        caller_uid: int = 1000,
    ) -> Dict[str, Any]:
        async with self._lock:
            # 1. Passive auto-lock check
            if self.state == "ARMED" and self.expires_at_monotonic and time.monotonic() >= self.expires_at_monotonic:
                self.state = "DISARMED"
                self.audit_logger.log(
                    "TIMEOUT_LOCK",
                    {"session_id": self.session_id, "reason": "passive_expiry"},
                )
                self.session_id = None

            # 2. Check armed state
            if self.state != "ARMED":
                self.audit_logger.log(
                    "EXEC_REJECTED",
                    {"command": command, "reason": "DISARMED", "caller_uid": caller_uid},
                )
                return {
                    "is_error": True,
                    "error_code": -32001,
                    "message": "Service is DISARMED. Run 'sudo agent-root-runner arm' to enable.",
                    "data": {"reason": "DISARMED"},
                }

            # 3. Check quota
            if self.quota_remaining is not None and self.quota_remaining <= 0:
                self.state = "DISARMED"
                self.audit_logger.log(
                    "QUOTA_LOCK",
                    {"session_id": self.session_id, "reason": "quota_exhausted"},
                )
                self.session_id = None
                return {
                    "is_error": True,
                    "error_code": -32001,
                    "message": "Session quota exhausted. Service locked.",
                    "data": {"reason": "QUOTA_EXHAUSTED"},
                }

            # 4. Check Guardrails
            allowed, rule, reason = TestGuardrailEvaluator.evaluate(command)
            if not allowed:
                self.audit_logger.log(
                    "EXEC_BLOCKED",
                    {
                        "command": command,
                        "rule": rule,
                        "reason": reason,
                        "session_id": self.session_id,
                        "caller_uid": caller_uid,
                    },
                )
                return {
                    "is_error": True,
                    "error_code": -32002,
                    "message": f"Destabilization guardrail violation: {reason}",
                    "data": {"rule": rule, "reason": reason},
                }

        # 5. Execute Subprocess outside state lock
        clean_env = CLEAN_ENV.copy()
        if env:
            for k, v in env.items():
                if not any(k.startswith(prefix) for prefix in FORBIDDEN_ENV_PREFIXES):
                    clean_env[k] = str(v)

        target_dir = workdir if os.path.isdir(workdir) else None
        start_t = time.perf_counter()

        try:
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.DEVNULL,
                cwd=target_dir,
                env=clean_env,
                start_new_session=True,
            )
            try:
                stdout_b, stderr_b = await asyncio.wait_for(
                    proc.communicate(), timeout=float(timeout_seconds)
                )
                duration_ms = int((time.perf_counter() - start_t) * 1000)
                exit_code = proc.returncode

                async with self._lock:
                    self.commands_executed += 1
                    if self.quota_remaining is not None:
                        self.quota_remaining -= 1
                        if self.quota_remaining <= 0:
                            self.state = "DISARMED"

                self.audit_logger.log(
                    "EXEC_ALLOWED",
                    {
                        "command": command,
                        "exit_code": exit_code,
                        "duration_ms": duration_ms,
                        "session_id": self.session_id,
                        "caller_uid": caller_uid,
                    },
                )
                return {
                    "is_error": False,
                    "result": {
                        "exit_code": exit_code,
                        "stdout": stdout_b.decode("utf-8", errors="replace"),
                        "stderr": stderr_b.decode("utf-8", errors="replace"),
                        "duration_ms": duration_ms,
                    },
                }
            except asyncio.TimeoutError:
                # Kill process group
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    pass
                duration_ms = int((time.perf_counter() - start_t) * 1000)
                self.audit_logger.log(
                    "EXEC_TIMEOUT",
                    {
                        "command": command,
                        "duration_ms": duration_ms,
                        "session_id": self.session_id,
                    },
                )
                return {
                    "is_error": True,
                    "error_code": -32004,
                    "message": f"Execution timed out after {timeout_seconds}s",
                    "data": {"timeout_seconds": timeout_seconds},
                }
        except Exception as exc:
            return {
                "is_error": True,
                "error_code": -32000,
                "message": f"Internal daemon error during execution: {exc}",
                "data": {},
            }

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            # Extract peer creds if supported
            sock = writer.get_extra_info("socket")
            caller_uid = 1000
            try:
                if hasattr(socket, "SO_PEERCRED"):
                    cred = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                    _, caller_uid, _ = struct.unpack("3i", cred)
            except Exception:
                pass

            while True:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").strip()
                if not text:
                    continue

                req_id = 1
                try:
                    req = json.loads(text)
                except json.JSONDecodeError:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
                    }
                    writer.write(json.dumps(resp).encode("utf-8") + b"\n")
                    await writer.drain()
                    continue

                if not isinstance(req, dict) or req.get("jsonrpc") != "2.0" or "method" not in req:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req.get("id") if isinstance(req, dict) else None,
                        "error": {"code": -32600, "message": "Invalid Request: malformed JSON-RPC 2.0"},
                    }
                    writer.write(json.dumps(resp).encode("utf-8") + b"\n")
                    await writer.drain()
                    continue

                req_id = req.get("id", 1)
                method = req.get("method")
                params = req.get("params") or {}

                if method == "ping":
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "result": {"status": "ok", "version": "1.0.0"},
                    }
                elif method == "status":
                    res = await self.get_status()
                    resp = {"jsonrpc": "2.0", "id": req_id, "result": res}
                elif method == "arm":
                    dur = params.get("duration_seconds", params.get("timeout_seconds", 900))
                    quota = params.get("quota")
                    try:
                        res = await self.arm(duration_seconds=dur, quota=quota, caller_uid=caller_uid)
                        resp = {"jsonrpc": "2.0", "id": req_id, "result": res}
                    except PermissionError as exc:
                        resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {"code": -32003, "message": str(exc)},
                        }
                elif method == "disarm":
                    res = await self.disarm()
                    resp = {"jsonrpc": "2.0", "id": req_id, "result": res}
                elif method == "exec":
                    cmd = params.get("command") or params.get("cmd") or ""
                    tout = params.get("timeout_seconds", params.get("timeout", 60))
                    workdir = params.get("workdir", "/")
                    env = params.get("env")
                    res = await self.execute_command(
                        command=cmd,
                        timeout_seconds=tout,
                        workdir=workdir,
                        env=env,
                        caller_uid=caller_uid,
                    )
                    if res.get("is_error"):
                        resp = {
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "error": {
                                "code": res["error_code"],
                                "message": res["message"],
                                "data": res.get("data", {}),
                            },
                        }
                    else:
                        resp = {"jsonrpc": "2.0", "id": req_id, "result": res["result"]}
                else:
                    resp = {
                        "jsonrpc": "2.0",
                        "id": req_id,
                        "error": {"code": -32601, "message": f"Method '{method}' not found"},
                    }

                writer.write(json.dumps(resp).encode("utf-8") + b"\n")
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def start(self):
        os.makedirs(os.path.dirname(os.path.abspath(self.socket_path)), exist_ok=True)
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass

        self._server = await asyncio.start_unix_server(
            self._handle_client, path=self.socket_path
        )
        self._running = True
        self.audit_logger.log(
            "DAEMON_START",
            {"socket_path": self.socket_path, "allow_user_arm": self.allow_user_arm},
        )

    async def stop(self):
        self._running = False
        if self._timer_task:
            self._timer_task.cancel()
        if self._server:
            self._server.close()
            await self._server.wait_closed()
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except Exception:
                pass
        self.audit_logger.log("DAEMON_STOP", {})


def run_daemon_main():
    parser = argparse.ArgumentParser(description="Agent Root Runner Standalone Test Daemon")
    parser.add_argument(
        "--socket",
        default=os.environ.get("AGENT_ROOT_RUNNER_SOCKET", "/tmp/agent-root-runner.sock"),
        help="Unix socket path",
    )
    parser.add_argument(
        "--audit-log",
        default=os.environ.get("AGENT_ROOT_RUNNER_AUDIT_LOG", "/tmp/agent-root-runner-audit.log"),
        help="Audit log path",
    )
    parser.add_argument("--allow-user-arm", action="store_true", default=True)
    args = parser.parse_args()

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server = TestDaemonServer(
        socket_path=args.socket,
        audit_log_path=args.audit_log,
        allow_user_arm=args.allow_user_arm,
    )

    loop.run_until_complete(server.start())

    def _shutdown(sig, frame):
        loop.create_task(server.stop())
        loop.stop()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    try:
        loop.run_forever()
    finally:
        loop.run_until_complete(server.stop())
        loop.close()


def start_daemon_process(
    socket_path: str,
    audit_log_path: str,
    allow_user_arm: bool = True,
    timeout: float = 5.0,
) -> subprocess.Popen:
    """Launch the test daemon in a background subprocess and wait for socket readiness."""
    import sys
    from tests.fixtures.client import SocketRpcClient

    proc = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "tests.fixtures.test_daemon",
            "--socket",
            socket_path,
            "--audit-log",
            audit_log_path,
            *(["--allow-user-arm"] if allow_user_arm else []),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(socket_path):
            try:
                with SocketRpcClient(socket_path=socket_path, timeout=0.5) as client:
                    resp = client.ping()
                    if resp.get("result", {}).get("status") == "ok":
                        return proc
            except Exception:
                pass
        time.sleep(0.05)

    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except Exception:
        proc.kill()
    raise RuntimeError(f"Daemon failed to bind and respond on {socket_path} within {timeout}s")


def stop_daemon_process(proc: Optional[subprocess.Popen]):
    """Cleanly terminate daemon subprocess."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass


if __name__ == "__main__":
    run_daemon_main()
