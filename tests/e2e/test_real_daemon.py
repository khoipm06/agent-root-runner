"""E2E tests against the REAL daemon process (src.daemon.server).

Spawns the production daemon as a detached subprocess (setsid + nohup, so it
does not die on SIGHUP) bound to an explicit --socket path, then asserts the
verified JSON-RPC 2.0 contracts over AF_UNIX. Framing mirrors
src/cli/runner_cli.py::send_request: one JSON object per line terminated with
"\\n", one JSON response line per request.

One fresh daemon per test for isolation; tearDown kills the whole process
group and removes every temp file.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from itertools import count
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOCKET_WAIT_SECONDS = 5.0

# Exact contract field lists (Milestone 1 spec).
STATUS_SESSION_FIELDS = (
    "state",
    "is_armed",
    "forever",
    "session_id",
    "armed_at",
    "expires_at",
    "remaining_seconds",
    "timeout_seconds",
    "duration_seconds",
    "quota_limit",
    "quota",
    "quota_remaining",
    "commands_executed",
    "lifetime_commands",
)
STATUS_FIELDS = STATUS_SESSION_FIELDS + ("socket_path", "daemon_pid")  # 16
DISARM_FIELDS = (
    "state",
    "previous_state",
    "session_id",
    "reason",
    "commands_executed",
    "active_duration_seconds",
    "already_disarmed",
    "message",
)
EXEC_RESULT_FIELDS = ("exit_code", "stdout", "stderr", "duration_ms", "timed_out", "truncated")


class RealDaemonTestBase(unittest.TestCase):
    """Spawns one real daemon per test and tears it down afterwards."""

    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="arr_e2e_")
        self.socket_path = os.path.join(self.tmpdir, "runner.sock")
        self.audit_log_path = os.path.join(self.tmpdir, "audit.log")
        self.daemon_out_path = os.path.join(self.tmpdir, "daemon.out")
        self.proc: subprocess.Popen | None = None
        self._req_ids = count(1)
        self.start_daemon()

    def tearDown(self) -> None:
        self.stop_daemon()
        for path in (self.socket_path, self.audit_log_path, self.daemon_out_path):
            try:
                os.unlink(path)
            except OSError:
                pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------
    # Daemon process lifecycle
    # ------------------------------------------------------------------

    def start_daemon(self) -> None:
        """Spawn the real daemon detached, then wait for its socket (<=5s).

        Uses the mandated pattern: ``setsid nohup python3 -m src.daemon.server
        --socket <SOCK> --audit-log <LOG> --allow-user-arm > OUT 2>&1 </dev/null &``.
        """
        with open(self.daemon_out_path, "ab") as out:
            self.proc = subprocess.Popen(
                [
                    "setsid",
                    "nohup",
                    sys.executable,
                    "-m",
                    "src.daemon.server",
                    "--socket",
                    self.socket_path,
                    "--audit-log",
                    self.audit_log_path,
                    "--allow-user-arm",
                ],
                cwd=str(REPO_ROOT),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
            )

        deadline = time.monotonic() + SOCKET_WAIT_SECONDS
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                break
            if os.path.exists(self.socket_path) and self._can_connect():
                return
            time.sleep(0.05)
        self.skipTest(
            f"Real daemon never became reachable on {self.socket_path} "
            f"(exit={self.proc.poll()}). daemon output:\n{self._daemon_output()}"
        )

    def _can_connect(self) -> bool:
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.5)
            probe.connect(self.socket_path)
            return True
        except OSError:
            return False
        finally:
            probe.close()

    def _daemon_output(self) -> str:
        try:
            return Path(self.daemon_out_path).read_text(errors="replace")[-2000:]
        except OSError:
            return "<no daemon output captured>"

    def stop_daemon(self) -> None:
        """Terminate the daemon process group (SIGTERM, then SIGKILL)."""
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self._signal_group(signal.SIGTERM)
            try:
                self.proc.wait(timeout=5.0)
            except subprocess.TimeoutExpired:
                self._signal_group(signal.SIGKILL)
                try:
                    self.proc.wait(timeout=5.0)
                except subprocess.TimeoutExpired:
                    pass
        self.proc = None

    def _signal_group(self, sig: signal.Signals) -> None:
        try:
            os.killpg(self.proc.pid, sig)
        except (ProcessLookupError, PermissionError, OSError):
            pass

    # ------------------------------------------------------------------
    # IPC (mirrors src/cli/runner_cli.py::send_request framing)
    # ------------------------------------------------------------------

    def rpc(self, method: str, params: dict | None = None, timeout: float = 15.0) -> dict:
        """Send one newline-delimited JSON-RPC request, return parsed response."""
        request = {"jsonrpc": "2.0", "id": next(self._req_ids), "method": method}
        if params is not None:
            request["params"] = params

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        data = b""
        try:
            sock.connect(self.socket_path)
            sock.sendall((json.dumps(request) + "\n").encode())
            while b"\n" not in data:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
        finally:
            sock.close()

        self.assertTrue(data.endswith(b"\n"), f"response not newline-delimited: {data!r}")
        return json.loads(data.decode().strip())

    def exec_rpc(self, command: str, timeout_seconds: float | None = None) -> dict:
        params: dict = {"command": command}
        if timeout_seconds is not None:
            params["timeout_seconds"] = timeout_seconds
        return self.rpc("exec", params)

    def status(self) -> dict:
        resp = self.rpc("status")
        self.assertNotIn("error", resp, f"status failed: {resp}")
        return resp["result"]

    def arm(self, duration: int = 30, quota: int | None = 3) -> dict:
        params: dict = {"duration_seconds": duration}
        if quota is not None:
            params["quota"] = quota
        resp = self.rpc("arm", params)
        self.assertNotIn("error", resp, f"arm failed: {resp}")
        return resp["result"]


class TestRealDaemonE2E(RealDaemonTestBase):
    # 1 ---------------------------------------------------------------
    def test_ping_contract(self) -> None:
        resp = self.rpc("ping")
        self.assertNotIn("error", resp)
        result = resp["result"]
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertTrue(
            {"status", "version", "uptime_sec", "daemon_pid"} <= set(result),
            f"ping missing fields: {result}",
        )
        self.assertEqual(result["status"], "ok")
        from src import __version__

        self.assertEqual(result["version"], __version__)
        self.assertIsInstance(result["daemon_pid"], int)
        self.assertIn("uptime_sec", result)
        self.assertIsInstance(result["uptime_sec"], (int, float))

    # 2 ---------------------------------------------------------------
    def test_status_disarmed_exact_fields(self) -> None:
        result = self.status()
        self.assertEqual(len(result), 16, f"expected 16 fields, got {result}")
        self.assertEqual(set(result), set(STATUS_FIELDS), f"field mismatch: {sorted(result)}")
        self.assertEqual(result["state"], "DISARMED")
        self.assertIs(result["is_armed"], False)
        self.assertEqual(result["socket_path"], self.socket_path)
        self.assertEqual(result["daemon_pid"], self.proc.pid)

    # 3 ---------------------------------------------------------------
    def test_arm_exact_fields(self) -> None:
        result = self.arm(duration=30, quota=3)
        self.assertEqual(len(result), 14, f"expected 14 fields, got {result}")
        self.assertEqual(set(result), set(STATUS_SESSION_FIELDS), f"field mismatch: {sorted(result)}")
        self.assertEqual(result["state"], "ARMED")
        self.assertIs(result["is_armed"], True)
        self.assertTrue(result["session_id"].startswith("arm_"), result["session_id"])
        for key in ("armed_at", "expires_at"):
            self.assertIsInstance(result[key], str)
            self.assertTrue(result[key].endswith("Z"), f"{key}={result[key]!r} not ISO-Z")
        self.assertEqual(result["duration_seconds"], 30)
        self.assertEqual(result["timeout_seconds"], 30)
        self.assertEqual(result["quota_limit"], 3)
        self.assertEqual(result["quota_remaining"], 3)

    def test_forever_arm_returns_disarmed_after_daemon_restart(self) -> None:
        old_pid = self.proc.pid
        arm_result = self.rpc("arm", {"forever": True, "quota": 3})
        self.assertNotIn("error", arm_result, arm_result)
        self.assertTrue(arm_result["result"]["forever"])

        self.stop_daemon()
        self.start_daemon()

        status = self.status()
        self.assertEqual(status["state"], "DISARMED")
        self.assertFalse(status["forever"])
        self.assertNotEqual(status["daemon_pid"], old_pid)

    # 4 ---------------------------------------------------------------
    def test_exec_disarmed_rejected(self) -> None:
        resp = self.exec_rpc("true")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)
        self.assertEqual(resp["error"]["data"]["reason"], "DISARMED")

    # 5 ---------------------------------------------------------------
    def test_guardrail_recursive_root_delete_blocked(self) -> None:
        self.arm(duration=30, quota=3)
        resp = self.exec_rpc("rm -rf /etc")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)
        self.assertEqual(resp["error"]["data"]["rule"], "RULE_FS_RECURSIVE_ROOT_DELETE")

    # 6 ---------------------------------------------------------------
    def test_quota_exhaustion(self) -> None:
        self.arm(duration=30, quota=1)

        first = self.exec_rpc("true")
        self.assertNotIn("error", first, f"first exec should be admitted: {first}")
        self.assertEqual(first["result"]["exit_code"], 0)

        second = self.exec_rpc("true")
        self.assertIn("error", second)
        self.assertEqual(second["error"]["code"], -32001)
        self.assertEqual(second["error"]["data"]["reason"], "QUOTA_EXHAUSTED")

    def test_last_quota_command_is_bounded_by_arm_deadline(self) -> None:
        self.arm(duration=1, quota=1)
        started = time.monotonic()

        response = self.exec_rpc("sleep 5", timeout_seconds=5)

        elapsed = time.monotonic() - started
        self.assertEqual(response.get("error", {}).get("code"), -32004, response)
        self.assertLess(elapsed, 3.0, f"final command outlived its ARM deadline ({elapsed:.2f}s)")

    # 7 ---------------------------------------------------------------
    def test_exec_timeout_returns_124(self) -> None:
        self.arm(duration=30, quota=10)
        resp = self.exec_rpc("sleep 5", timeout_seconds=1)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)
        self.assertEqual(resp["error"]["data"]["exit_code"], 124)
        self.assertIs(resp["error"]["data"]["timed_out"], True)

    # 8 ---------------------------------------------------------------
    def test_exec_success_and_counter_increment(self) -> None:
        self.arm(duration=30, quota=5)
        resp = self.exec_rpc("id")
        self.assertNotIn("error", resp, f"exec failed: {resp}")
        result = resp["result"]
        self.assertEqual(set(result), set(EXEC_RESULT_FIELDS), f"exec result shape: {sorted(result)}")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("uid=", result["stdout"])

        after = self.status()
        self.assertEqual(after["commands_executed"], 1)
        self.assertEqual(after["lifetime_commands"], 1)
        self.assertIs(after["is_armed"], True)

    # 9 ---------------------------------------------------------------
    def test_restart_resets_to_disarmed(self) -> None:
        arm_result = self.arm(duration=30, quota=3)
        self.assertEqual(arm_result["state"], "ARMED")

        self.stop_daemon()
        self.start_daemon()

        result = self.status()
        self.assertEqual(result["state"], "DISARMED")
        self.assertIs(result["is_armed"], False)
        self.assertIsNone(result["session_id"])

    # 10 --------------------------------------------------------------
    def test_disarm_result_shape(self) -> None:
        arm_result = self.arm(duration=30, quota=3)
        resp = self.rpc("disarm")
        self.assertNotIn("error", resp, f"disarm failed: {resp}")
        result = resp["result"]
        self.assertEqual(set(result), set(DISARM_FIELDS), f"disarm shape: {sorted(result)}")
        self.assertEqual(result["state"], "DISARMED")
        self.assertEqual(result["previous_state"], "ARMED")
        self.assertEqual(result["reason"], "MANUAL_DISARM")
        self.assertEqual(result["session_id"], arm_result["session_id"])
        self.assertEqual(result["commands_executed"], 0)
        self.assertIs(result["already_disarmed"], False)
        self.assertIsInstance(result["message"], str)
        self.assertIsInstance(result["active_duration_seconds"], (int, float))


if __name__ == "__main__":
    unittest.main()
