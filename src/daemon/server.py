"""Unix Domain Socket Daemon Server and JSON-RPC 2.0 Dispatcher.

Part of Milestone 1 (M1) of Agent Root Runner.
Provides connection lifecycle management, 0660 filesystem permissions,
stale socket detection and recovery, line-delimited JSON-RPC 2.0 handling,
and clean signal-driven shutdown.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import os
import signal
import socket
import stat
import sys
import time
from typing import Any, Dict, Optional, Set, Tuple

from src import __version__
from src.daemon.audit import AuditLogger
from src.daemon.auth import PeerCredentials, get_peer_credentials
from src.daemon.executor import (
    ExecutionResult,
    InvalidEnvironmentError,
    InvalidWorkdirError,
    SubprocessExecutor,
)
from src.daemon.state import RunnerStateMachine

try:
    from src.guardrails.analyzer import CommandAnalyzer, evaluate_command
except ImportError:
    CommandAnalyzer = None  # type: ignore
    evaluate_command = None  # type: ignore


SYSTEM_SOCKET_PATH = "/run/agent-root-runner/runner.sock"
MAX_TIMEOUT_SECONDS = 3600


def resolve_socket_path(override_path: Optional[str] = None) -> str:
    """Resolves standard socket path using priority hierarchy.

    Non-root clients are expected to talk to the root daemon's system socket,
    which is group-owned (wheel) and mode 0660. The per-user runtime path is
    only a fallback for user-mode/development daemons where no system socket
    is present.
    """
    if override_path:
        return os.path.abspath(override_path)
    if "AGENT_ROOT_RUNNER_SOCKET" in os.environ:
        return os.path.abspath(os.environ["AGENT_ROOT_RUNNER_SOCKET"])
    if os.geteuid() == 0:
        return SYSTEM_SOCKET_PATH
    if os.path.exists(SYSTEM_SOCKET_PATH):
        return SYSTEM_SOCKET_PATH
    xdg_runtime = os.environ.get("XDG_RUNTIME_DIR")
    if xdg_runtime:
        return os.path.join(xdg_runtime, "agent-root-runner", "runner.sock")
    return os.path.expanduser("~/.local/state/agent-root-runner/runner.sock")


class AgentRootRunnerDaemon:
    """Core daemon managing Unix domain socket IPC and JSON-RPC dispatching."""

    def __init__(
        self,
        socket_path: Optional[str] = None,
        audit_log_path: Optional[str] = None,
        allow_user_arm: bool = False,
        socket_mode: int = 0o660,
        socket_group: Optional[str] = "wheel",
        max_buffer_limit: int = 10 * 1024 * 1024,  # 10 MB
        guardrail_evaluator: Optional[Any] = None,
    ) -> None:
        self.socket_path = resolve_socket_path(socket_path)
        self.allow_user_arm = allow_user_arm
        self.socket_mode = socket_mode
        self.socket_group = socket_group
        self.max_buffer_limit = max_buffer_limit
        if guardrail_evaluator is not None:
            self.guardrail_evaluator = guardrail_evaluator
        elif CommandAnalyzer is not None:
            self.guardrail_evaluator = CommandAnalyzer()
        else:
            self.guardrail_evaluator = evaluate_command

        self.start_time = time.monotonic()
        self.audit_logger = AuditLogger(
            log_path=audit_log_path,
            force_user_mode=allow_user_arm or (os.geteuid() != 0),
        )
        self.state_machine = RunnerStateMachine(audit_logger=self.audit_logger)
        self.executor = SubprocessExecutor(
            max_output_bytes=self.max_buffer_limit,
            is_user_mode=allow_user_arm or (os.geteuid() != 0),
        )
        # Kill any in-flight privileged command the moment we disarm.
        self.state_machine.on_disarm = self.executor.terminate_current
        self._exec_semaphore = asyncio.Semaphore(1)

        self.server: Optional[asyncio.Server] = None
        self.active_tasks: Set[asyncio.Task[Any]] = set()
        self.is_stopping: bool = False

    def _prepare_socket_path(self) -> None:
        """Ensures parent directory exists and recovers stale socket files."""
        parent_dir = os.path.dirname(self.socket_path)
        if parent_dir:
            dir_mode = 0o750 if os.geteuid() == 0 else 0o700
            os.makedirs(parent_dir, mode=dir_mode, exist_ok=True)

        if os.path.exists(self.socket_path):
            mode = os.stat(self.socket_path).st_mode
            if not stat.S_ISSOCK(mode):
                raise RuntimeError(
                    f"Path {self.socket_path} exists and is not a socket file."
                )

            # Probe connect to check if a live server is already running
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(self.socket_path)
                probe.close()
                raise RuntimeError(
                    f"Active daemon already listening on {self.socket_path}"
                )
            except (ConnectionRefusedError, FileNotFoundError):
                # Stale socket: safe to remove.
                probe.close()
                try:
                    os.unlink(self.socket_path)
                except OSError:
                    pass
            except OSError as exc:
                # e.g. EACCES/EPERM: the socket may be live but unreachable.
                # Do not delete a socket we cannot prove is stale.
                probe.close()
                raise RuntimeError(
                    f"Cannot verify existing socket {self.socket_path}: {exc}"
                )

    def _apply_permissions(self) -> None:
        """Applies mode 0660 and attempts group ownership assignment."""
        try:
            os.chmod(self.socket_path, self.socket_mode)
        except OSError:
            pass

        if os.geteuid() == 0 and self.socket_group:
            try:
                import grp
                gid = grp.getgrnam(self.socket_group).gr_gid
                os.chown(self.socket_path, -1, gid)
            except (KeyError, PermissionError, OSError):
                pass

    async def start(self) -> None:
        """Binds socket server and commences client listening."""
        self._prepare_socket_path()
        self.server = await asyncio.start_unix_server(
            self._handle_client,
            path=self.socket_path,
            limit=self.max_buffer_limit,
        )
        self._apply_permissions()

        self.audit_logger.log("DAEMON_START", {
            "socket_path": self.socket_path,
            "pid": os.getpid(),
            "allow_user_arm": self.allow_user_arm,
        })

    async def stop(self) -> None:
        """Gracefully shuts down server, cancels tasks, and removes socket file."""
        if self.is_stopping:
            return
        self.is_stopping = True

        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass

        # Disarm state machine and reset timer tasks
        await self.state_machine.reset()

        # Cancel active client handlers
        curr = asyncio.current_task()
        for task in list(self.active_tasks):
            if task is not curr and not task.done():
                task.cancel()

        if self.active_tasks:
            await asyncio.gather(*self.active_tasks, return_exceptions=True)

        # Unlink socket
        if os.path.exists(self.socket_path):
            try:
                os.unlink(self.socket_path)
            except OSError:
                pass

        self.audit_logger.log("DAEMON_STOP", {
            "uptime_sec": round(time.monotonic() - self.start_time, 2),
            "pid": os.getpid(),
        })
        self.audit_logger.close()

    def _extract_credentials(self, writer: asyncio.StreamWriter) -> PeerCredentials:
        """Extracts peer credentials from socket; fails closed (uid = -1) on error."""
        sock = writer.get_extra_info("socket")
        if sock:
            try:
                return get_peer_credentials(sock)
            except Exception:
                return PeerCredentials(
                    pid=-1,
                    uid=-1,
                    gid=-1,
                    comm="[unresolved]",
                    cmdline="[unresolved]",
                )
        return PeerCredentials(
            pid=-1,
            uid=-1,
            gid=-1,
            comm="[unknown]",
            cmdline="[unknown]",
        )

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        """Handles single client connection over Unix domain socket."""
        task = asyncio.current_task()
        if task:
            self.active_tasks.add(task)
            task.add_done_callback(self.active_tasks.discard)

        try:
            creds = self._extract_credentials(writer)

            while not self.is_stopping:
                try:
                    line = await reader.readline()
                except ValueError:
                    err_resp = {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {
                            "code": -32600,
                            "message": f"Line length exceeded buffer limit ({self.max_buffer_limit} bytes)",
                        },
                    }
                    writer.write(json.dumps(err_resp).encode("utf-8") + b"\n")
                    await writer.drain()
                    break

                if not line:
                    break

                line_str = line.decode("utf-8", errors="replace").strip()
                if not line_str:
                    continue

                response = await self._dispatch_request_line(line_str, creds)
                writer.write(json.dumps(response).encode("utf-8") + b"\n")
                await writer.drain()

        except (ConnectionResetError, BrokenPipeError):
            pass
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def _dispatch_request_line(
        self, line_str: str, creds: PeerCredentials
    ) -> Dict[str, Any]:
        """Parses and dispatches a JSON-RPC 2.0 request."""
        try:
            req = json.loads(line_str)
        except json.JSONDecodeError:
            return {
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: Invalid JSON"},
            }

        if (
            not isinstance(req, dict)
            or req.get("jsonrpc") != "2.0"
            or "method" not in req
        ):
            return {
                "jsonrpc": "2.0",
                "id": req.get("id") if isinstance(req, dict) else None,
                "error": {
                    "code": -32600,
                    "message": "Invalid Request: Malformed JSON-RPC 2.0 payload",
                },
            }

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params") or {}
        if not isinstance(params, dict):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: Parameters must be an object",
                },
            }

        # Method Dispatching
        if method == "ping":
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "status": "ok",
                    "version": __version__,
                    "uptime_sec": round(time.monotonic() - self.start_time, 2),
                    "daemon_pid": os.getpid(),
                },
            }

        elif method == "status":
            status_data = await self.state_machine.get_status()
            status_data["socket_path"] = self.socket_path
            status_data["daemon_pid"] = os.getpid()
            return {"jsonrpc": "2.0", "id": req_id, "result": status_data}

        elif method == "arm":
            duration = params.get(
                "duration_seconds", params.get("timeout_seconds", 900)
            )
            quota = params.get("quota")
            forever = params.get("forever", False)
            if forever is True and (
                "duration_seconds" in params or "timeout_seconds" in params
            ):
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": "Invalid params: 'forever' and a duration are mutually exclusive",
                        "data": {"reason": "INVALID_PARAMS"},
                    },
                }
            try:
                arm_res = await self.state_machine.arm(
                    duration_seconds=duration,
                    quota=quota,
                    forever=forever,
                    requester_uid=creds.uid,
                    allow_user_arm=self.allow_user_arm,
                    requester_pid=creds.pid,
                )
                return {"jsonrpc": "2.0", "id": req_id, "result": arm_res}
            except PermissionError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32003,
                        "message": str(exc),
                        "data": {"reason": "PERMISSION_DENIED"},
                    },
                }
            except ValueError as exc:
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": str(exc),
                        "data": {"reason": "INVALID_PARAMS"},
                    },
                }

        elif method == "disarm":
            disarm_res = await self.state_machine.disarm(disarmed_by_uid=creds.uid)
            return {"jsonrpc": "2.0", "id": req_id, "result": disarm_res}

        elif method == "exec":
            return await self._handle_exec_request(req_id, params, creds)

        else:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32601,
                    "message": f"Method '{method}' not found",
                },
            }

    def _evaluate_guardrails(
        self, command: str
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str]]:
        """Evaluates command against configured guardrail evaluator.

        Returns:
            Tuple of (allowed: bool, rule: Optional[str], reason: Optional[str], category: Optional[str])
        """
        if self.guardrail_evaluator is None:
            return True, None, None, None

        try:
            if hasattr(self.guardrail_evaluator, "evaluate"):
                eval_res = self.guardrail_evaluator.evaluate(command)
            elif callable(self.guardrail_evaluator):
                eval_res = self.guardrail_evaluator(command)
            else:
                return True, None, None, None
        except Exception as exc:
            return False, "RULE_EVALUATOR_ERROR", f"Guardrail evaluation error: {exc}", "evasion"

        if isinstance(eval_res, tuple):
            allowed = bool(eval_res[0])
            rule = eval_res[1] if len(eval_res) > 1 else None
            reason = eval_res[2] if len(eval_res) > 2 else "Violation"
            category = eval_res[3] if len(eval_res) > 3 else None
            return allowed, rule, reason, category

        allowed = getattr(eval_res, "allowed", True)
        rule = getattr(eval_res, "matched_rule", None) or getattr(eval_res, "rule", None)
        reason = getattr(eval_res, "reason", "Violation")
        category = getattr(eval_res, "category", None)
        return allowed, rule, reason, category

    async def _handle_exec_request(
        self, req_id: Any, params: Dict[str, Any], creds: PeerCredentials
    ) -> Dict[str, Any]:
        """Handles execution request including queueing, state re-check, guardrails, and execution."""
        raw_command = params.get("command", params.get("cmd", ""))
        if not isinstance(raw_command, str):
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'command' must be a string",
                    "data": {"reason": "INVALID_PARAMS"},
                },
            }
        command = raw_command

        raw_timeout = params.get("timeout_seconds", params.get("timeout", 60))
        if raw_timeout is None:
            raw_timeout = 60
        if isinstance(raw_timeout, bool):
            raw_timeout = None
        try:
            timeout_seconds = float(raw_timeout)
        except (TypeError, ValueError):
            timeout_seconds = -1.0
        if not math.isfinite(timeout_seconds) or timeout_seconds <= 0:
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32602,
                    "message": "Invalid params: 'timeout_seconds' must be a positive number",
                    "data": {"reason": "INVALID_PARAMS"},
                },
            }
        timeout_seconds = min(timeout_seconds, MAX_TIMEOUT_SECONDS)

        workdir = params.get("workdir", "/")
        env = params.get("env")

        # 1. Pre-queue Fast Path: Reject immediately if already disarmed
        if not await self.state_machine.is_armed():
            allowed, reason = (
                await self.state_machine.check_permission_and_decrement_quota()
            )
            await self.audit_logger.log_event(
                "EXEC_REJECTED",
                peer_pid=creds.pid,
                peer_uid=creds.uid,
                peer_gid=creds.gid,
                peer_comm=creds.comm,
                command=command,
                decision="DENIED_DISARMED",
                reason=reason,
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32001,
                    "message": reason,
                    "data": {
                        "reason": "DISARMED" if "DISARMED" in reason else "QUOTA_EXHAUSTED"
                    },
                },
            }

        # 2. Command length validation (DoS defense)
        if len(command) > 65536:
            await self.audit_logger.log_event(
                "EXEC_BLOCKED",
                peer_pid=creds.pid,
                peer_uid=creds.uid,
                peer_gid=creds.gid,
                peer_comm=creds.comm,
                command=command[:256] + "... [truncated]",
                decision="GUARDRAIL_BLOCKED",
                rule="RULE_COMMAND_LENGTH_EXCEEDED",
                reason="Command length exceeds 64KB limit",
                exit_code=126,
                category="resource",
            )
            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32002,
                    "message": "Destabilization guardrail violation: Command length exceeds 64KB limit",
                    "data": {
                        "rule": "RULE_COMMAND_LENGTH_EXCEEDED",
                        "reason": "Command length exceeds 64KB limit",
                        "category": "resource",
                    },
                },
            }

        # 3. Queue on execution semaphore to serialize subprocess execution
        async with self._exec_semaphore:
            # Re-evaluate state under execution lock
            if not await self.state_machine.is_armed():
                allowed, reason = (
                    await self.state_machine.check_permission_and_decrement_quota()
                )
                await self.audit_logger.log_event(
                    "EXEC_REJECTED",
                    peer_pid=creds.pid,
                    peer_uid=creds.uid,
                    peer_gid=creds.gid,
                    peer_comm=creds.comm,
                    command=command,
                    decision="DENIED_DISARMED",
                    reason=reason,
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": reason,
                        "data": {
                            "reason": "DISARMED" if "DISARMED" in reason else "QUOTA_EXHAUSTED"
                        },
                    },
                }

            # Guardrails Evaluation BEFORE quota consumption (preserving quota)
            gr_allowed, gr_rule, gr_reason, gr_category = self._evaluate_guardrails(command)
            if not gr_allowed:
                await self.audit_logger.log_event(
                    "EXEC_BLOCKED",
                    peer_pid=creds.pid,
                    peer_uid=creds.uid,
                    peer_gid=creds.gid,
                    peer_comm=creds.comm,
                    command=command,
                    decision="GUARDRAIL_BLOCKED",
                    rule=gr_rule,
                    reason=gr_reason,
                    exit_code=126,
                    category=gr_category,
                )
                err_data: Dict[str, Any] = {"rule": gr_rule, "reason": gr_reason}
                if gr_category is not None:
                    err_data["category"] = gr_category
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32002,
                        "message": f"Destabilization guardrail violation: {gr_reason}",
                        "data": err_data,
                    },
                }

            # Capture the active ARM deadline before quota accounting: consuming
            # the final quota slot disarms the session, but that admitted
            # command must still be bounded by the authorization window.
            remaining = await self.state_machine.remaining_seconds()

            # Re-evaluate state & atomically consume quota under execution lock
            permitted, err = (
                await self.state_machine.check_permission_and_decrement_quota()
            )
            if not permitted:
                await self.audit_logger.log_event(
                    "EXEC_REJECTED",
                    peer_pid=creds.pid,
                    peer_uid=creds.uid,
                    peer_gid=creds.gid,
                    peer_comm=creds.comm,
                    command=command,
                    decision="DENIED_DISARMED",
                    reason=err,
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32001,
                        "message": err,
                        "data": {
                            "reason": "DISARMED" if "DISARMED" in err else "QUOTA_EXHAUSTED"
                        },
                    },
                }

            # 4. Subprocess Execution. Bound the command to the remaining arm
            # window so it cannot outlive its authorization.
            if remaining is not None and remaining > 0:
                timeout_seconds = min(timeout_seconds, remaining)
            try:
                exec_res = await self.executor.execute(
                    command=command,
                    timeout_seconds=timeout_seconds,
                    workdir=workdir,
                    env=env,
                )
            except (InvalidEnvironmentError, InvalidWorkdirError) as exc:
                await self.state_machine.refund_quota()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32602,
                        "message": str(exc),
                        "data": {"reason": "INVALID_PARAMS"},
                    },
                }
            except Exception as exc:
                await self.state_machine.refund_quota()
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": f"Internal execution error: {exc}",
                        "data": {},
                    },
                }

            # 5. Accounting & Audit Logging
            await self.state_machine.record_command_execution(
                command=command,
                exit_code=exec_res.exit_code,
                duration_ms=exec_res.duration_ms,
            )

            if exec_res.timed_out:
                await self.audit_logger.log_event(
                    "EXEC_TIMEOUT",
                    peer_pid=creds.pid,
                    peer_uid=creds.uid,
                    peer_gid=creds.gid,
                    peer_comm=creds.comm,
                    command=command,
                    exit_code=exec_res.exit_code,
                    duration_ms=exec_res.duration_ms,
                    timed_out=True,
                )
                return {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32004,
                        "message": f"Execution timed out after {timeout_seconds}s",
                        "data": exec_res.to_dict(),
                    },
                }

            await self.audit_logger.log_event(
                "EXEC_ALLOWED",
                peer_pid=creds.pid,
                peer_uid=creds.uid,
                peer_gid=creds.gid,
                peer_comm=creds.comm,
                command=command,
                exit_code=exec_res.exit_code,
                duration_ms=exec_res.duration_ms,
                timed_out=False,
                decision="ALLOWED",
            )

            return {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": exec_res.to_dict(),
            }

    _handle_exec = _handle_exec_request


# Alias matching blueprint
DaemonServer = AgentRootRunnerDaemon


def run_daemon_main():
    """Main CLI entrypoint to start the daemon process."""
    parser = argparse.ArgumentParser(description="Agent Root Runner Daemon")
    parser.add_argument(
        "--socket",
        default=None,
        help="Unix socket path",
    )
    parser.add_argument(
        "--audit-log",
        default=None,
        help="Audit log path",
    )
    parser.add_argument(
        "--allow-user-arm",
        action="store_true",
        default=False,
        help="Allow non-root arming in development/test mode",
    )
    args, _ = parser.parse_known_args()

    if args.allow_user_arm and os.geteuid() == 0:
        sys.exit(
            "Error: --allow-user-arm is a development/test flag and is refused "
            "for a root daemon (it would let any local user arm root execution). "
            "Run the daemon as your own unprivileged user instead."
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    daemon = AgentRootRunnerDaemon(
        socket_path=args.socket,
        audit_log_path=args.audit_log,
        allow_user_arm=args.allow_user_arm,
    )

    loop.run_until_complete(daemon.start())

    shutdown_event = asyncio.Event()

    def _sig_handler():
        shutdown_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _sig_handler)
        except NotImplementedError:
            pass

    async def _wait_and_stop():
        await shutdown_event.wait()
        await daemon.stop()

    try:
        loop.run_until_complete(_wait_and_stop())
    finally:
        loop.run_until_complete(daemon.stop())
        loop.close()


if __name__ == "__main__":
    run_daemon_main()
