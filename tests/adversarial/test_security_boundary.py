"""Empirical Adversarial Test Suite for Milestone 1 Security Boundaries.

Target Security Verification:
1. Unauthorized arming rejection when allow_user_arm=False and peer_uid != 0 (SO_PEERCRED enforcement).
2. Environment variable scrubbing (attempting injection of LD_PRELOAD, BASH_ENV, PYTHONPATH, etc.).
3. Audit log integrity, file mode 0600, single-line NDJSON format, and concurrency stress.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import stat
import tempfile
import time
import unittest

from src.daemon.audit import AuditLogger
from src.daemon.auth import (
    AuthenticationError,
    PeerCredentials,
    check_arm_permission,
    check_disarm_permission,
    get_peer_credentials,
    is_arm_authorized,
)
from src.daemon.executor import (
    ExecutionResult,
    InvalidEnvironmentError,
    SubprocessExecutor,
)
from src.daemon.server import AgentRootRunnerDaemon
from src.daemon.state import RunnerState, RunnerStateMachine


class TestAdversarialArmingRejection(unittest.IsolatedAsyncioTestCase):
    """Stress-test authentication and authorization boundary for daemon arming."""

    def test_direct_auth_unauthorized_uids(self):
        """Verify is_arm_authorized strictly rejects non-root when allow_user_arm=False."""
        # Test various non-root UIDs
        for uid in [1, 1000, 1001, 65534, 99999]:
            self.assertFalse(
                is_arm_authorized(uid, allow_user_arm=False),
                f"UID {uid} should be rejected in production mode",
            )
        # Negative UID
        self.assertFalse(is_arm_authorized(-1, allow_user_arm=False))
        # Root UID must be allowed
        self.assertTrue(is_arm_authorized(0, allow_user_arm=False))

    def test_check_arm_permission_rejection(self):
        """Verify check_arm_permission returns False and actionable rejection message."""
        creds = PeerCredentials(pid=1234, uid=1000, gid=1000)
        allowed, msg = check_arm_permission(creds, allow_user_arm=False)
        self.assertFalse(allowed)
        self.assertIn("requires root privileges", msg)
        self.assertIn("peer_uid == 0", msg)

    async def test_statemachine_arm_rejection_fail_closed(self):
        """Verify RunnerStateMachine fails closed when non-root requests arming."""
        sm = RunnerStateMachine()
        self.assertEqual(sm.state, RunnerState.DISARMED)

        for non_root_uid in [1, 1000, 1001, 65534]:
            with self.assertRaises(PermissionError):
                await sm.arm(
                    duration_seconds=300,
                    requester_uid=non_root_uid,
                    allow_user_arm=False,
                )
            self.assertEqual(sm.state, RunnerState.DISARMED)
            self.assertFalse(await sm.is_armed())

    async def test_socket_ipc_unauthorized_arm_rejection(self):
        """Empirically test live Unix domain socket IPC rejection of arming when allow_user_arm=False."""
        tmpdir = tempfile.mkdtemp(prefix="test_adv_auth_")
        sock_path = os.path.join(tmpdir, "runner.sock")
        audit_path = os.path.join(tmpdir, "audit.log")

        # Daemon started with production mode: allow_user_arm=False
        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=False,
        )
        await daemon.start()

        try:
            # Client connects over real Unix domain socket (client has UID 1000 != 0)
            reader, writer = await asyncio.open_unix_connection(sock_path)

            # 1. Attempt arming with standard params
            req = {
                "jsonrpc": "2.0",
                "id": "req-arm-1",
                "method": "arm",
                "params": {"duration_seconds": 600},
            }
            writer.write(json.dumps(req).encode("utf-8") + b"\n")
            await writer.drain()

            resp_line = await reader.readline()
            resp = json.loads(resp_line.decode("utf-8"))

            # Must be rejected with code -32003 (Permission Denied)
            self.assertIn("error", resp)
            self.assertEqual(resp["error"]["code"], -32003)
            self.assertEqual(resp["error"]["data"]["reason"], "PERMISSION_DENIED")
            self.assertIn("requires root privileges", resp["error"]["message"])

            # 2. Attempt arming with parameter spoofing (trying to claim uid=0 in JSON payload)
            spoofed_req = {
                "jsonrpc": "2.0",
                "id": "req-arm-spoof",
                "method": "arm",
                "params": {"duration_seconds": 600, "uid": 0, "peer_uid": 0},
            }
            writer.write(json.dumps(spoofed_req).encode("utf-8") + b"\n")
            await writer.drain()

            resp_spoof_line = await reader.readline()
            resp_spoof = json.loads(resp_spoof_line.decode("utf-8"))
            self.assertIn("error", resp_spoof)
            self.assertEqual(resp_spoof["error"]["code"], -32003)

            # 3. Verify daemon status remains strictly DISARMED
            status_req = {
                "jsonrpc": "2.0",
                "id": "req-status",
                "method": "status",
                "params": {},
            }
            writer.write(json.dumps(status_req).encode("utf-8") + b"\n")
            await writer.drain()

            resp_status_line = await reader.readline()
            resp_status = json.loads(resp_status_line.decode("utf-8"))
            self.assertEqual(resp_status["result"]["state"], "DISARMED")
            self.assertFalse(resp_status["result"]["is_armed"])

            # 4. Verify command execution is rejected as DISARMED (-32001)
            exec_req = {
                "jsonrpc": "2.0",
                "id": "req-exec",
                "method": "exec",
                "params": {"command": "whoami"},
            }
            writer.write(json.dumps(exec_req).encode("utf-8") + b"\n")
            await writer.drain()

            resp_exec_line = await reader.readline()
            resp_exec = json.loads(resp_exec_line.decode("utf-8"))
            self.assertIn("error", resp_exec)
            self.assertEqual(resp_exec["error"]["code"], -32001)

            writer.close()
            await writer.wait_closed()

        finally:
            await daemon.stop()
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestAdversarialEnvScrubbing(unittest.IsolatedAsyncioTestCase):
    """Stress-test environment variable scrubbing, injection vectors, and subprocess isolation."""

    async def asyncSetUp(self):
        self.executor = SubprocessExecutor(is_user_mode=True)
        self.tmpdir = tempfile.mkdtemp(prefix="test_adv_env_")

    async def asyncTearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_injection_ld_preload_blocked(self):
        """Verify LD_PRELOAD injection is strictly blocked."""
        with self.assertRaises(InvalidEnvironmentError) as ctx:
            self.executor.sanitize_environment({"LD_PRELOAD": "/evil/hack.so"})
        self.assertIn("LD_PRELOAD", str(ctx.exception))

        with self.assertRaises(InvalidEnvironmentError):
            await self.executor.execute(
                "echo hacked",
                env={"LD_PRELOAD": "/evil/hack.so"},
            )

    async def test_injection_bash_env_blocked(self):
        """Verify BASH_ENV injection is strictly blocked."""
        with self.assertRaises(InvalidEnvironmentError) as ctx:
            self.executor.sanitize_environment({"BASH_ENV": "/evil/payload.sh"})
        self.assertIn("BASH_ENV", str(ctx.exception))

        with self.assertRaises(InvalidEnvironmentError):
            await self.executor.execute(
                "echo hacked",
                env={"BASH_ENV": "/evil/payload.sh"},
            )

    async def test_injection_pythonpath_blocked(self):
        """Verify PYTHONPATH injection is strictly blocked."""
        with self.assertRaises(InvalidEnvironmentError) as ctx:
            self.executor.sanitize_environment({"PYTHONPATH": "/evil/site-packages"})
        self.assertIn("PYTHONPATH", str(ctx.exception))

        with self.assertRaises(InvalidEnvironmentError):
            await self.executor.execute(
                "echo hacked",
                env={"PYTHONPATH": "/evil/site-packages"},
            )

    async def test_injection_comprehensive_blacklist(self):
        """Test exhaustive suite of known dangerous and hijacking variables."""
        dangerous_vars = [
            # Linker & dynamic loading
            ("LD_LIBRARY_PATH", "/tmp/lib"),
            ("LD_AUDIT", "/tmp/audit.so"),
            ("LD_DEBUG", "all"),
            # Language runtimes
            ("PYTHONHOME", "/tmp/python"),
            ("PYTHONOPTIMIZE", "1"),
            ("PERL5LIB", "/tmp/perl"),
            ("RUBYLIB", "/tmp/ruby"),
            ("NODE_OPTIONS", "--inspect"),
            ("LUA_PATH", "/tmp/lua"),
            # Shell hijacking
            ("PATH", "/tmp/evil/bin"),
            ("SHELL", "/tmp/evil/bash"),
            ("ENV", "/tmp/evil"),
            ("IFS", ":"),
            ("PROMPT_COMMAND", "rm -rf /"),
            ("SHELLOPTS", "xtrace"),
            ("BASHOPTS", "cmdhist"),
            ("GLOBIGNORE", "*"),
            # Sudo and user identity
            ("SUDO_COMMAND", "/bin/sh"),
            ("SUDO_USER", "root"),
            ("SUDO_UID", "0"),
            ("SUDO_GID", "0"),
            ("HOME", "/root"),
            ("USER", "root"),
            # Kerberos & resolver
            ("KRB5_CONFIG", "/tmp/krb5.conf"),
            ("RESOLV_CONF", "/tmp/resolv.conf"),
        ]

        for var_name, var_val in dangerous_vars:
            with self.subTest(var=var_name):
                with self.assertRaises(InvalidEnvironmentError, msg=f"Failed to block {var_name}"):
                    self.executor.sanitize_environment({var_name: var_val})

    async def test_malformed_and_null_byte_env_injection(self):
        """Verify malformed variable names, null bytes, and non-string types are blocked."""
        # Null bytes
        with self.assertRaises(InvalidEnvironmentError):
            self.executor.sanitize_environment({"VAR\x00NAME": "val"})
        with self.assertRaises(InvalidEnvironmentError):
            self.executor.sanitize_environment({"VARNAME": "val\x00ue"})

        # Malformed identifiers
        invalid_keys = ["", "123BAD", "VAR-NAME", "VAR=VAL", "VAR NAME", "VAR;RM"]
        for key in invalid_keys:
            with self.subTest(key=key):
                with self.assertRaises(InvalidEnvironmentError):
                    self.executor.sanitize_environment({key: "val"})

        # Non-string types
        with self.assertRaises(InvalidEnvironmentError):
            self.executor.sanitize_environment({"NUM_KEY": 123})  # type: ignore
        with self.assertRaises(InvalidEnvironmentError):
            self.executor.sanitize_environment({123: "val"})  # type: ignore

    async def test_subprocess_actual_environment_oracle(self):
        """Oracle test: run subprocess and inspect actual child process environment."""
        # 1. Execute script that outputs all environment variables
        res = await self.executor.execute(
            'python3 -c "import os, json; print(json.dumps(dict(os.environ)))"',
            env={"PERMITTED_APP_FLAG": "activated_123"},
        )
        self.assertEqual(res.exit_code, 0)
        child_env = json.loads(res.stdout.strip())

        # Permitted variable must be present
        self.assertEqual(child_env.get("PERMITTED_APP_FLAG"), "activated_123")

        # Dangerous variables must NOT be present
        for blocked in ["LD_PRELOAD", "BASH_ENV", "PYTHONPATH", "LD_LIBRARY_PATH"]:
            self.assertNotIn(blocked, child_env)

        # Baseline PATH must be sanitized default, not host's custom PATH
        self.assertEqual(
            child_env.get("PATH"),
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )

    async def test_socket_ipc_env_injection_rejection(self):
        """Verify socket IPC endpoint cleanly rejects execution with invalid env vars and refunds quota."""
        sock_path = os.path.join(self.tmpdir, "runner.sock")
        audit_path = os.path.join(self.tmpdir, "audit.log")

        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=True,
        )
        await daemon.start()

        try:
            reader, writer = await asyncio.open_unix_connection(sock_path)

            # Arm daemon with quota = 2
            arm_req = {
                "jsonrpc": "2.0",
                "id": "arm-1",
                "method": "arm",
                "params": {"duration_seconds": 300, "quota": 2},
            }
            writer.write(json.dumps(arm_req).encode("utf-8") + b"\n")
            await writer.drain()
            arm_resp = json.loads((await reader.readline()).decode("utf-8"))
            self.assertEqual(arm_resp["result"]["state"], "ARMED")

            # Attempt injection via exec
            inject_req = {
                "jsonrpc": "2.0",
                "id": "exec-inject-ld",
                "method": "exec",
                "params": {
                    "command": "echo should_not_run",
                    "env": {"LD_PRELOAD": "/evil.so"},
                },
            }
            writer.write(json.dumps(inject_req).encode("utf-8") + b"\n")
            await writer.drain()
            inject_resp = json.loads((await reader.readline()).decode("utf-8"))

            self.assertIn("error", inject_resp)
            self.assertEqual(inject_resp["error"]["code"], -32602)
            self.assertIn("LD_PRELOAD", inject_resp["error"]["message"])

            # Verify quota was refunded and service is still armed
            status_req = {"jsonrpc": "2.0", "id": "stat-1", "method": "status", "params": {}}
            writer.write(json.dumps(status_req).encode("utf-8") + b"\n")
            await writer.drain()
            stat_resp = json.loads((await reader.readline()).decode("utf-8"))
            self.assertEqual(stat_resp["result"]["quota_remaining"], 2)
            self.assertEqual(stat_resp["result"]["state"], "ARMED")

            writer.close()
            await writer.wait_closed()

        finally:
            await daemon.stop()


class TestAdversarialAuditLogIntegrity(unittest.IsolatedAsyncioTestCase):
    """Stress-test audit logging permissions, NDJSON framing, and concurrency integrity."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_adv_audit_")

    async def asyncTearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_file_mode_0600_fresh_creation(self):
        """Verify newly created audit log has strict 0600 file permissions."""
        log_path = os.path.join(self.tmpdir, "audit_fresh.log")
        logger = AuditLogger(log_path=log_path, force_user_mode=True)
        try:
            self.assertTrue(os.path.exists(log_path))
            mode = stat.S_IMODE(os.stat(log_path).st_mode)
            self.assertEqual(mode, 0o600, f"Expected 0600, got {oct(mode)}")
        finally:
            logger.close()

    def test_file_mode_0600_tightens_preexisting_insecure_file(self):
        """Verify pre-existing file with insecure permissions (0666/0644) is tightened to 0600."""
        log_path = os.path.join(self.tmpdir, "audit_insecure.log")
        # Create with world-writable 0666
        with open(log_path, "w", encoding="utf-8") as f:
            f.write("# dummy log\n")
        os.chmod(log_path, 0o666)
        self.assertEqual(stat.S_IMODE(os.stat(log_path).st_mode), 0o666)

        # Initialize AuditLogger on this file
        logger = AuditLogger(log_path=log_path, force_user_mode=True)
        try:
            mode = stat.S_IMODE(os.stat(log_path).st_mode)
            self.assertEqual(
                mode,
                0o600,
                f"AuditLogger failed to tighten insecure pre-existing permissions: got {oct(mode)}",
            )
        finally:
            logger.close()

    async def test_single_line_ndjson_with_multiline_and_complex_data(self):
        """Verify events with newlines, control chars, and unicode produce strictly 1 line per entry."""
        log_path = os.path.join(self.tmpdir, "audit_multiline.log")
        logger = AuditLogger(log_path=log_path, force_user_mode=True)

        complex_cases = [
            ("multiline_cmd", "echo line1\necho line2\r\necho line3"),
            ("json_payload_cmd", 'echo \'{"nested": [1, 2, 3], "newline": "a\\nb"}\''),
            ("quotes_and_backslashes", 'printf "%s\\t%s\\n" "foo\\"bar" "back\\\\slash"'),
            ("unicode_and_emojis", "echo '🔥 Hoàn thành kiểm tra bảo mật 🛡️'"),
            ("control_chars", "echo \x01\x02\x03\t\r"),
        ]

        try:
            for event_type, cmd in complex_cases:
                await logger.log_event(
                    event_type=event_type,
                    peer_pid=1001,
                    peer_uid=1000,
                    peer_gid=1000,
                    peer_comm="bash",
                    command=cmd,
                    decision="ALLOWED",
                    exit_code=0,
                )

            # Verify file format
            with open(log_path, "r", encoding="utf-8") as f:
                raw_lines = f.readlines()

            # Must be exactly 1 line per logged event (no stray line breaks)
            self.assertEqual(
                len(raw_lines),
                len(complex_cases),
                f"Expected {len(complex_cases)} lines, got {len(raw_lines)}. Multiline splitting detected!",
            )

            # Every line must be valid NDJSON
            for idx, line in enumerate(raw_lines):
                self.assertFalse(line.endswith("\r\n"))
                self.assertTrue(line.endswith("\n"))
                parsed = json.loads(line)
                self.assertIn("timestamp", parsed)
                self.assertIn("event_id", parsed)
                self.assertIn("event_type", parsed)
                self.assertEqual(parsed["pid"], 1001)
                self.assertEqual(parsed["uid"], 1000)
                self.assertEqual(parsed["command"], complex_cases[idx][1])

        finally:
            logger.close()

    async def test_concurrent_logging_stress_integrity(self):
        """Concurrently write 100 events across 10 tasks to verify NDJSON integrity and no torn lines."""
        log_path = os.path.join(self.tmpdir, "audit_concurrent.log")
        logger = AuditLogger(log_path=log_path, force_user_mode=True)

        TOTAL_TASKS = 10
        EVENTS_PER_TASK = 10
        EXPECTED_TOTAL = TOTAL_TASKS * EVENTS_PER_TASK

        async def worker_task(task_id: int):
            for i in range(EVENTS_PER_TASK):
                await logger.log_event(
                    event_type="CONCURRENT_EVENT",
                    peer_pid=1000 + task_id,
                    peer_uid=1000,
                    peer_gid=1000,
                    peer_comm=f"worker_{task_id}",
                    command=f"echo task_{task_id}_event_{i}",
                    exit_code=0,
                    task_index=task_id,
                    event_index=i,
                )

        try:
            tasks = [asyncio.create_task(worker_task(t)) for t in range(TOTAL_TASKS)]
            await asyncio.gather(*tasks)

            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            self.assertEqual(
                len(lines),
                EXPECTED_TOTAL,
                f"Expected {EXPECTED_TOTAL} total lines, found {len(lines)}",
            )

            # Every single line must be cleanly parseable JSON
            for line_no, line in enumerate(lines, 1):
                try:
                    record = json.loads(line)
                    self.assertEqual(record["event_type"], "CONCURRENT_EVENT")
                    self.assertIn("timestamp", record)
                    self.assertIn("event_id", record)
                except json.JSONDecodeError as err:
                    self.fail(f"Line {line_no} failed JSON decode (torn/interleaved line): {err} -> {line!r}")

        finally:
            logger.close()


if __name__ == "__main__":
    unittest.main()
