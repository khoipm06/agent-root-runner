"""Comprehensive Unit Test Suite for Agent Root Runner Milestone 1.

Verifies:
1. SO_PEERCRED credential extraction and authorization policy (auth.py)
2. State machine lifecycle, dual-tier auto-lock, and quota accounting (state.py)
3. Process-group isolated execution, environment sanitization, stream capping, and timeouts (executor.py)
4. Append-only structured NDJSON audit logging with fdatasync (audit.py)
5. End-to-end Unix domain socket IPC client/server request/response loop (server.py)
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
    get_process_info,
    is_arm_authorized,
)
from src.daemon.executor import (
    ExecutionResult,
    InvalidEnvironmentError,
    InvalidWorkdirError,
    SubprocessExecutor,
)
from src.daemon.server import AgentRootRunnerDaemon
from src.daemon.state import (
    DisarmReason,
    RunnerState,
    RunnerStateMachine,
)


class TestAuth(unittest.TestCase):
    """Unit tests for src/daemon/auth.py."""

    def test_peer_credentials_extraction_socketpair(self):
        """Verify extraction of SO_PEERCRED from a Unix socketpair."""
        s1, s2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            creds = get_peer_credentials(s1)
            self.assertIsInstance(creds, PeerCredentials)
            self.assertEqual(creds.pid, os.getpid())
            self.assertEqual(creds.uid, os.geteuid())
            self.assertEqual(creds.gid, os.getegid())
            self.assertTrue(len(creds.comm) > 0)
        finally:
            s1.close()
            s2.close()

    def test_get_process_info_current_pid(self):
        """Verify reading /proc for current process."""
        comm, cmdline = get_process_info(os.getpid())
        self.assertNotEqual(comm, "[exited]")
        self.assertNotEqual(cmdline, "[exited]")
        self.assertTrue(len(comm) > 0)

    def test_get_process_info_nonexistent_pid(self):
        """Verify graceful fallback for non-existent PID."""
        comm, cmdline = get_process_info(99999999)
        self.assertIn(comm, ["[unknown]", "[exited]"])
        self.assertIn(cmdline, ["[unknown]", "[exited]"])

    def test_is_arm_authorized_production(self):
        """In production, only root (UID 0) is authorized to arm."""
        self.assertTrue(is_arm_authorized(0, allow_user_arm=False))
        self.assertFalse(is_arm_authorized(1000, allow_user_arm=False))
        self.assertFalse(is_arm_authorized(1001, allow_user_arm=False))

    def test_is_arm_authorized_dev_mode(self):
        """In dev/test mode (allow_user_arm=True), unprivileged UIDs are permitted."""
        self.assertTrue(is_arm_authorized(0, allow_user_arm=True))
        self.assertTrue(is_arm_authorized(1000, allow_user_arm=True))
        self.assertTrue(is_arm_authorized(os.geteuid(), allow_user_arm=True))

    def test_check_arm_permission(self):
        """Verify check_arm_permission messages and decisions."""
        root_creds = PeerCredentials(pid=123, uid=0, gid=0)
        user_creds = PeerCredentials(pid=124, uid=1000, gid=1000)

        allowed, msg = check_arm_permission(root_creds, allow_user_arm=False)
        self.assertTrue(allowed)

        allowed, msg = check_arm_permission(user_creds, allow_user_arm=False)
        self.assertFalse(allowed)
        self.assertIn("root privileges", msg)

        allowed, msg = check_arm_permission(user_creds, allow_user_arm=True)
        self.assertTrue(allowed)

    def test_check_disarm_permission(self):
        """Disarm is always permitted."""
        user_creds = PeerCredentials(pid=124, uid=1000, gid=1000)
        allowed, msg = check_disarm_permission(user_creds)
        self.assertTrue(allowed)


class TestStateMachine(unittest.IsolatedAsyncioTestCase):
    """Unit tests for src/daemon/state.py."""

    async def asyncSetUp(self):
        self.sm = RunnerStateMachine()

    async def asyncTearDown(self):
        await self.sm.reset()

    async def test_initial_state_fail_closed(self):
        """Initial state must be DISARMED and reject execution."""
        self.assertEqual(self.sm.state, RunnerState.DISARMED)
        self.assertFalse(await self.sm.is_armed())
        status = await self.sm.get_status()
        self.assertEqual(status["state"], "DISARMED")
        self.assertIsNone(status["session_id"])
        self.assertEqual(status["remaining_seconds"], 0.0)

        allowed, reason = await self.sm.check_permission_and_decrement_quota()
        self.assertFalse(allowed)
        self.assertIn("DISARMED", reason)

    async def test_arm_success(self):
        """Arming transitions to ARMED and records session."""
        status = await self.sm.arm(
            duration_seconds=300,
            quota=5,
            requester_uid=1000,
            allow_user_arm=True,
        )
        self.assertEqual(self.sm.state, RunnerState.ARMED)
        self.assertTrue(await self.sm.is_armed())
        self.assertEqual(status["state"], "ARMED")
        self.assertIsNotNone(status["session_id"])
        self.assertGreater(status["remaining_seconds"], 0.0)
        self.assertEqual(status["quota_remaining"], 5)

    async def test_arm_validation_errors(self):
        """Invalid duration or quota raises ValueError."""
        with self.assertRaises(ValueError):
            await self.sm.arm(duration_seconds=0, allow_user_arm=True)
        with self.assertRaises(ValueError):
            await self.sm.arm(duration_seconds=-10, allow_user_arm=True)
        with self.assertRaises(ValueError):
            await self.sm.arm(duration_seconds=90000, allow_user_arm=True)
        with self.assertRaises(ValueError):
            await self.sm.arm(duration_seconds=300, quota=0, allow_user_arm=True)

    async def test_arm_permission_denied(self):
        """Arming by non-root without allow_user_arm raises PermissionError."""
        with self.assertRaises(PermissionError):
            await self.sm.arm(
                duration_seconds=300,
                requester_uid=1000,
                allow_user_arm=False,
            )
        self.assertEqual(self.sm.state, RunnerState.DISARMED)

    async def test_manual_disarm(self):
        """Calling disarm terminates active session immediately."""
        await self.sm.arm(duration_seconds=300, allow_user_arm=True)
        self.assertEqual(self.sm.state, RunnerState.ARMED)

        disarm_res = await self.sm.disarm(reason="MANUAL_DISARM")
        self.assertEqual(self.sm.state, RunnerState.DISARMED)
        self.assertEqual(disarm_res["state"], "DISARMED")
        self.assertFalse(disarm_res["already_disarmed"])

        # Second disarm is idempotent
        disarm_again = await self.sm.disarm()
        self.assertTrue(disarm_again["already_disarmed"])

    async def test_rearm_cancels_previous(self):
        """Re-arming replaces old session with new session ID and duration."""
        res1 = await self.sm.arm(duration_seconds=100, allow_user_arm=True)
        id1 = res1["session_id"]
        res2 = await self.sm.arm(duration_seconds=200, allow_user_arm=True)
        id2 = res2["session_id"]
        self.assertNotEqual(id1, id2)
        self.assertEqual(res2["duration_seconds"], 200)

    async def test_active_autolock_timeout(self):
        """Active timer countdown automatically locks state to DISARMED."""
        await self.sm.arm(duration_seconds=1, allow_user_arm=True)
        self.assertEqual(self.sm.state, RunnerState.ARMED)
        await asyncio.sleep(1.1)
        self.assertEqual(self.sm.state, RunnerState.DISARMED)
        self.assertFalse(await self.sm.is_armed())

    async def test_passive_autolock_guard(self):
        """Passive guard detects expired monotonic deadline even if timer task lags."""
        await self.sm.arm(duration_seconds=100, allow_user_arm=True)
        self.assertEqual(self.sm.state, RunnerState.ARMED)
        # Simulate clock advancing past monotonic expiry
        self.sm._session.expires_at_monotonic = time.monotonic() - 1.0

        # Trigger passive evaluation
        status = await self.sm.get_status()
        self.assertEqual(status["state"], "DISARMED")
        self.assertFalse(await self.sm.is_armed())

    async def test_quota_exhaustion_lock(self):
        """Exhausting quota admits final command but locks state for subsequent requests."""
        await self.sm.arm(duration_seconds=300, quota=2, allow_user_arm=True)

        # 1st execution
        allowed1, _ = await self.sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed1)
        self.assertEqual(self.sm.state, RunnerState.ARMED)

        # 2nd execution (exhausts quota -> transitions to DISARMED)
        allowed2, _ = await self.sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed2)
        self.assertEqual(self.sm.state, RunnerState.DISARMED)

        # 3rd execution rejected
        allowed3, reason3 = await self.sm.check_permission_and_decrement_quota()
        self.assertFalse(allowed3)
        self.assertIn("quota", reason3.lower())

    async def test_quota_refund_on_guardrail(self):
        """Refunding quota restores slot and ARMED state if quota had reached 0."""
        await self.sm.arm(duration_seconds=300, quota=1, allow_user_arm=True)
        allowed, _ = await self.sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed)
        self.assertEqual(self.sm.state, RunnerState.DISARMED)

        # Refund
        await self.sm.refund_quota()
        self.assertEqual(self.sm.state, RunnerState.ARMED)
        status = await self.sm.get_status()
        self.assertEqual(status["quota_remaining"], 1)

    async def test_quota_refund_does_not_override_manual_disarm(self):
        """Verify refund_quota() never re-arms daemon after manual disarm."""
        await self.sm.arm(duration_seconds=300, quota=5, allow_user_arm=True)
        allowed, _ = await self.sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed)
        await self.sm.disarm(reason=DisarmReason.MANUAL_DISARM.value)
        self.assertEqual(self.sm.state, RunnerState.DISARMED)

        await self.sm.refund_quota()
        self.assertEqual(self.sm.state, RunnerState.DISARMED)
        self.assertEqual(self.sm._last_disarm_reason, DisarmReason.MANUAL_DISARM.value)
        self.assertTrue(self.sm._timer_task is None or self.sm._timer_task.done())

    async def test_quota_refund_restarts_active_timer_on_legitimate_exhaustion(self):
        """Verify refund_quota() restarts active timer when re-arming from quota exhaustion."""
        await self.sm.arm(duration_seconds=300, quota=1, allow_user_arm=True)
        allowed, _ = await self.sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed)
        self.assertEqual(self.sm.state, RunnerState.DISARMED)
        self.assertEqual(self.sm._last_disarm_reason, DisarmReason.QUOTA_EXHAUSTED.value)

        await self.sm.refund_quota()
        self.assertEqual(self.sm.state, RunnerState.ARMED)
        self.assertIsNotNone(self.sm._timer_task)
        self.assertFalse(self.sm._timer_task.done())


class TestExecutor(unittest.IsolatedAsyncioTestCase):
    """Unit tests for src/daemon/executor.py."""

    async def asyncSetUp(self):
        self.executor = SubprocessExecutor(is_user_mode=True)
        self.tmpdir = tempfile.mkdtemp(prefix="test_executor_")

    async def asyncTearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_simple_command_execution(self):
        """Verifies simple echo execution returns 0 and correct stdout."""
        res = await self.executor.execute("echo 'hello executor'")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("hello executor", res.stdout)
        self.assertEqual(res.stderr, "")
        self.assertFalse(res.timed_out)

    async def test_command_nonzero_exit(self):
        """Non-zero command returns correct exit code and stderr."""
        res = await self.executor.execute("ls /nonexistent_dir_0987654321")
        self.assertNotEqual(res.exit_code, 0)
        self.assertTrue(len(res.stderr) > 0)

    async def test_custom_workdir(self):
        """Command executes inside specified working directory."""
        res = await self.executor.execute("pwd", workdir=self.tmpdir)
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout.strip(), self.tmpdir)

    async def test_environment_sanitization_safe_variable(self):
        """Safe caller environment variables are propagated."""
        res = await self.executor.execute(
            "echo $MY_CUSTOM_VAR",
            env={"MY_CUSTOM_VAR": "secret123"},
        )
        self.assertEqual(res.exit_code, 0)
        self.assertEqual(res.stdout.strip(), "secret123")

    async def test_environment_sanitization_blocked_variable(self):
        """Dangerous environment variables like LD_PRELOAD raise InvalidEnvironmentError."""
        with self.assertRaises(InvalidEnvironmentError):
            await self.executor.execute(
                "echo test",
                env={"LD_PRELOAD": "/tmp/evil.so"},
            )
        with self.assertRaises(InvalidEnvironmentError):
            await self.executor.execute(
                "echo test",
                env={"PYTHONPATH": "/tmp/evil"},
            )

    async def test_environment_sanitization_glibc_and_gconv_blocked(self):
        """Verify GLIBC_TUNABLES, GCONV_PATH, and LOCALDOMAIN raise InvalidEnvironmentError."""
        for var_name in ("GLIBC_TUNABLES", "GCONV_PATH", "LOCALDOMAIN"):
            with self.assertRaises(InvalidEnvironmentError):
                self.executor.sanitize_environment({var_name: "malicious_value"})

    async def test_timeout_and_process_group_kill(self):
        """Timeout kills process group and returns exit code 124."""
        start_t = time.monotonic()
        res = await self.executor.execute(
            "sleep 10 & sleep 10 & wait",
            timeout_seconds=0.2,
        )
        duration = time.monotonic() - start_t
        self.assertTrue(res.timed_out)
        self.assertEqual(res.exit_code, 124)
        self.assertIn("timed out", res.stderr)
        self.assertLess(duration, 2.0)

    async def test_stream_separation(self):
        """Stdout and stderr streams are captured separately without mixing."""
        res = await self.executor.execute("echo 'standard_out'; echo 'standard_err' >&2")
        self.assertEqual(res.exit_code, 0)
        self.assertIn("standard_out", res.stdout)
        self.assertNotIn("standard_err", res.stdout)
        self.assertIn("standard_err", res.stderr)
        self.assertNotIn("standard_out", res.stderr)

    async def test_output_capping(self):
        """Capped output avoids memory bloat and does not hang the stream."""
        limited_executor = SubprocessExecutor(
            max_output_bytes=4096,
            is_user_mode=True,
        )
        # Generate 100 KB of data
        res = await limited_executor.execute("head -c 100000 /dev/zero | tr '\\0' 'A'")
        self.assertEqual(res.exit_code, 0)
        self.assertTrue(res.truncated)
        self.assertLessEqual(len(res.stdout.encode("utf-8")), 50000)
        self.assertIn("truncated", res.stdout)

    async def test_empty_and_null_commands(self):
        """Empty command or command with null bytes returns error."""
        res1 = await self.executor.execute("")
        self.assertEqual(res1.exit_code, 2)
        res2 = await self.executor.execute("echo \x00 test")
        self.assertEqual(res2.exit_code, 2)


class TestAuditLogger(unittest.IsolatedAsyncioTestCase):
    """Unit tests for src/daemon/audit.py."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_audit_")
        self.log_path = os.path.join(self.tmpdir, "audit.log")
        self.logger = AuditLogger(log_path=self.log_path, force_user_mode=True)

    async def asyncTearDown(self):
        self.logger.close()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_audit_file_creation_and_permissions(self):
        """Audit log is created with mode 0600."""
        self.assertTrue(os.path.exists(self.log_path))
        mode = os.stat(self.log_path).st_mode
        self.assertEqual(stat.S_IMODE(mode), 0o600)

    async def test_log_event_ndjson_format(self):
        """Written events are valid single-line NDJSON with required fields."""
        await self.logger.log_event(
            event_type="EXEC_ALLOWED",
            peer_pid=1234,
            peer_uid=1000,
            peer_gid=1000,
            peer_comm="bash",
            command="uptime",
            decision="ALLOWED",
            exit_code=0,
            duration_ms=45.2,
        )

        with open(self.log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]

        self.assertEqual(len(lines), 1)
        entry = json.loads(lines[0])
        self.assertEqual(entry["event_type"], "EXEC_ALLOWED")
        self.assertEqual(entry["pid"], 1234)
        self.assertEqual(entry["uid"], 1000)
        self.assertEqual(entry["command"], "uptime")
        self.assertEqual(entry["decision"], "ALLOWED")
        self.assertEqual(entry["exit_code"], 0)
        self.assertIn("timestamp", entry)
        self.assertIn("event_id", entry)


class TestDaemonServerE2E(unittest.IsolatedAsyncioTestCase):
    """Unit tests for end-to-end Unix socket IPC via AgentRootRunnerDaemon."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_daemon_ipc_")
        self.sock_path = os.path.join(self.tmpdir, "runner.sock")
        self.audit_path = os.path.join(self.tmpdir, "audit.log")

        self.daemon = AgentRootRunnerDaemon(
            socket_path=self.sock_path,
            audit_log_path=self.audit_path,
            allow_user_arm=True,
        )
        await self.daemon.start()

    async def asyncTearDown(self):
        await self.daemon.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def _send_request(self, method: str, params: Optional[dict] = None) -> dict:
        reader, writer = await asyncio.open_unix_connection(self.sock_path)
        req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        writer.write(json.dumps(req).encode("utf-8") + b"\n")
        await writer.drain()

        line = await reader.readline()
        writer.close()
        await writer.wait_closed()
        return json.loads(line.decode("utf-8"))

    async def test_ping(self):
        """Ping returns ok and the current package version."""
        from src import __version__

        resp = await self._send_request("ping")
        self.assertEqual(resp.get("jsonrpc"), "2.0")
        self.assertEqual(resp.get("result", {}).get("status"), "ok")
        self.assertEqual(resp.get("result", {}).get("version"), __version__)

    async def test_status_disarmed_by_default(self):
        """Status initially reflects DISARMED."""
        resp = await self._send_request("status")
        res = resp.get("result", {})
        self.assertEqual(res.get("state"), "DISARMED")
        self.assertFalse(res.get("is_armed"))

    async def test_exec_disarmed_rejected(self):
        """Executing command while disarmed returns error -32001."""
        resp = await self._send_request("exec", {"command": "echo 'should_fail'"})
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)
        self.assertIn("DISARMED", resp["error"]["message"])

    async def test_arm_and_exec_lifecycle(self):
        """Arming enables command execution; disarming locks service again."""
        # 1. Arm
        arm_resp = await self._send_request("arm", {"duration_seconds": 300})
        self.assertEqual(arm_resp.get("result", {}).get("state"), "ARMED")

        # 2. Exec
        exec_resp = await self._send_request("exec", {"command": "echo 'ipc_success'"})
        self.assertIn("result", exec_resp)
        self.assertEqual(exec_resp["result"]["exit_code"], 0)
        self.assertIn("ipc_success", exec_resp["result"]["stdout"])

        # 3. Disarm
        disarm_resp = await self._send_request("disarm")
        self.assertEqual(disarm_resp.get("result", {}).get("state"), "DISARMED")

        # 4. Exec again -> Rejected
        exec_again = await self._send_request("exec", {"command": "echo 'locked_out'"})
        self.assertEqual(exec_again.get("error", {}).get("code"), -32001)

    async def test_stale_socket_recovery(self):
        """Starting daemon over a stale dead socket file unlinks and recovers cleanly."""
        dead_sock = os.path.join(self.tmpdir, "dead.sock")
        # Create a dummy dead socket file
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(dead_sock)
        s.close()
        self.assertTrue(os.path.exists(dead_sock))

        # Start new daemon on same path
        new_daemon = AgentRootRunnerDaemon(
            socket_path=dead_sock,
            audit_log_path=os.path.join(self.tmpdir, "audit_dead.log"),
            allow_user_arm=True,
        )
        await new_daemon.start()
        try:
            # Verify new daemon responds
            reader, writer = await asyncio.open_unix_connection(dead_sock)
            writer.write(b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n')
            await writer.drain()
            res_line = await reader.readline()
            writer.close()
            await writer.wait_closed()
            self.assertIn(b'"ok"', res_line)
        finally:
            await new_daemon.stop()

    def test_extract_credentials_fail_closed(self):
        """Verify _extract_credentials fails closed with uid=-1 when extraction fails."""
        from unittest.mock import MagicMock
        mock_writer = MagicMock()
        mock_writer.get_extra_info.return_value = None
        creds = self.daemon._extract_credentials(mock_writer)
        self.assertEqual(creds.uid, -1)
        self.assertEqual(creds.gid, -1)
        self.assertEqual(creds.pid, -1)


if __name__ == "__main__":
    unittest.main()
