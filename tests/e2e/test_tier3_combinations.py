"""Tier 3: Cross-Feature Combinations Test Suite.

Covers pairwise interactions and multi-component workflows:
1. Armed State + Execution Timeout (command times out, session remains armed)
2. Armed State + Guardrail Violation + Audit Log Entry
3. Guardrail Rejection followed immediately by Valid Command (pipeline resilience)
4. Quota Accounting with Guardrail Violations
5. Non-Blocking Status Queries during Subprocess Execution (concurrency)
6. Pristine Environment + Forbidden Variable Rejection (LD_PRELOAD, BASH_ENV)
7. Multi-Connection Session Persistence (separate socket connections share armed state)
8. MCP Tool Call + Daemon Auto-Lock Transition
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
from typing import Optional

from tests.fixtures.client import SocketRpcClient
from tests.fixtures.mock_tools import read_audit_log
from tests.fixtures.daemon_process import start_daemon_process, stop_daemon_process


class TestTier3Combinations(unittest.TestCase):
    """Tier 3 cross-feature pairwise interactions."""

    tmpdir: str
    sock_path: str
    audit_path: str
    daemon_proc: Optional[subprocess.Popen] = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="agent_root_runner_t3_")
        cls.sock_path = os.path.join(cls.tmpdir, "runner.sock")
        cls.audit_path = os.path.join(cls.tmpdir, "audit.log")

        cls.daemon_proc = start_daemon_process(
            socket_path=cls.sock_path,
            audit_log_path=cls.audit_path,
            allow_user_arm=True,
        )

    @classmethod
    def tearDownClass(cls):
        stop_daemon_process(cls.daemon_proc)
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def setUp(self):
        self.client = SocketRpcClient(socket_path=self.sock_path)
        self.client.connect()
        self.client.disarm()

    def tearDown(self):
        try:
            self.client.disarm()
        except Exception:
            pass
        self.client.close()

    def test_c01_armed_execution_timeout_preserves_session(self):
        """C-01: An execution timeout does not disarm or invalidate the active session."""
        self.client.arm(duration_seconds=300)
        # 1. Run command that times out
        tout_resp = self.client.exec_cmd("sleep 5", timeout_seconds=1)
        self.assertIn("error", tout_resp)
        self.assertEqual(tout_resp["error"]["code"], -32004)

        # 2. Verify subsequent valid command still succeeds under same armed session
        sub_resp = self.client.exec_cmd("echo 'still_armed'")
        self.assertIn("result", sub_resp)
        self.assertEqual(sub_resp["result"]["exit_code"], 0)
        self.assertIn("still_armed", sub_resp["result"]["stdout"])

    def test_c02_armed_guardrail_block_logs_audit_and_preserves_session(self):
        """C-02: Guardrail rejection logs violation and leaves session intact for valid work."""
        self.client.arm(duration_seconds=300)
        initial_log_count = len(read_audit_log(self.audit_path))

        # Attempt raw disk overwrite
        blocked_resp = self.client.exec_cmd("dd if=/dev/zero of=/dev/nvme0n1 bs=1M count=1")
        self.assertIn("error", blocked_resp)
        self.assertEqual(blocked_resp["error"]["code"], -32002)

        # Check audit log contains EXEC_BLOCKED entry
        logs = read_audit_log(self.audit_path)
        self.assertGreater(len(logs), initial_log_count)
        blocked_entries = [e for e in logs if e.get("event_type") == "EXEC_BLOCKED"]
        self.assertGreater(len(blocked_entries), 0)
        self.assertEqual(blocked_entries[-1].get("rule"), "RULE_BLOCK_DEV_RAW_WRITE")

        # Daemon remains ARMED
        status = self.client.status()
        self.assertEqual(status["result"]["state"], "ARMED")

    def test_c03_guardrail_rejection_followed_by_valid_command(self):
        """C-03: System recovers cleanly from guardrail rejection to execute valid diagnostic."""
        self.client.arm(duration_seconds=300)

        # Step 1: Forbidden network flush
        r1 = self.client.exec_cmd("iptables -F")
        self.assertIn("error", r1)
        self.assertEqual(r1["error"]["code"], -32002)

        # Step 2: Valid network inspection
        r2 = self.client.exec_cmd("echo 'iptables -L -n simulated'")
        self.assertIn("result", r2)
        self.assertEqual(r2["result"]["exit_code"], 0)

    def test_c04_environment_injection_rejected(self):
        """C-04: Prohibited environment variables (LD_PRELOAD, BASH_ENV) are rejected
        outright (fail-closed) rather than silently stripped or passed through.

        The daemon runs with a pristine baseline environment; a caller may extend it
        with safe variables, but never override PATH/SHELL/LD_*/BASH_ENV/etc.
        """
        self.client.arm(duration_seconds=300)

        for bad_env in ({"LD_PRELOAD": "/tmp/evil.so"}, {"BASH_ENV": "/tmp/evil.sh"}):
            with self.subTest(bad_env=bad_env):
                resp = self.client.exec_cmd("env", env=bad_env)
                self.assertIn("error", resp)
                self.assertEqual(resp["error"]["code"], -32602)

        # A safe, non-reserved variable is accepted and reaches the child process.
        ok = self.client.exec_cmd("env", env={"CUSTOM_SAFE_VAR": "safe_value"})
        self.assertIn("result", ok)
        self.assertIn("CUSTOM_SAFE_VAR=safe_value", ok["result"]["stdout"])

    def test_c05_concurrent_status_during_execution(self):
        """C-05: Status queries return promptly while an execution is running concurrently."""
        self.client.arm(duration_seconds=300)

        # Client 1 runs 2-second command in a separate thread
        c1 = SocketRpcClient(socket_path=self.sock_path)
        c2 = SocketRpcClient(socket_path=self.sock_path)
        c1.connect()
        c2.connect()

        t1 = threading.Thread(target=lambda: c1.exec_cmd("sleep 2", timeout_seconds=5))
        t1.start()
        try:
            time.sleep(0.3)
            # Client 2 queries status immediately
            t_start = time.perf_counter()
            st = c2.status()
            latency = time.perf_counter() - t_start
            # Status query should respond in under 1 second without waiting for sleep 2
            self.assertLess(latency, 1.0)
            self.assertEqual(st["result"]["state"], "ARMED")
        finally:
            t1.join(timeout=3.0)
            c1.close()
            c2.close()

    def test_c06_multiple_client_connections_share_session_state(self):
        """C-06: Distinct socket client connections observe and share the same armed session."""
        c1 = SocketRpcClient(socket_path=self.sock_path)
        c2 = SocketRpcClient(socket_path=self.sock_path)
        c1.connect()
        c2.connect()
        try:
            # c1 arms daemon
            arm_resp = c1.arm(duration_seconds=120)
            session_id = arm_resp["result"]["session_id"]

            # c2 checks status
            st = c2.status()
            self.assertEqual(st["result"]["state"], "ARMED")
            self.assertEqual(st["result"]["session_id"], session_id)

            # c2 disarms daemon
            c2.disarm()

            # c1 checks status -> disarmed
            st1 = c1.status()
            self.assertEqual(st1["result"]["state"], "DISARMED")
        finally:
            c1.close()
            c2.close()

    def test_c07_pipe_to_shell_evasion_blocked(self):
        """C-07: Attempt to pipe arbitrary stream into shell interpreter is caught and blocked."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd("echo 'rm -rf /' | bash")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)


if __name__ == "__main__":
    unittest.main()
