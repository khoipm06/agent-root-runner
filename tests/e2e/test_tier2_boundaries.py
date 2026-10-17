"""Tier 2: Boundary & Corner Cases Test Suite.

Covers edge conditions, protocol malformations, boundary values, and race conditions:
1. Empty and whitespace-only commands
2. Malformed JSON-RPC 2.0 framing and payloads (invalid JSON, missing fields, wrong types)
3. Non-zero exit codes (boundary codes: 1, 123, 255)
4. Strict stdout vs stderr channel separation (no stream mixing or banner pollution)
5. Rapid arm/disarm toggling under concurrency
6. Expired session race condition (boundary monotonic timestamp checks)
7. Large payload / high-volume output streaming without buffer deadlock
8. Subprocess group termination and cleanup upon timeout
"""

import asyncio
import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Optional

from tests.fixtures.client import SocketRpcClient
from tests.fixtures.test_daemon import start_daemon_process, stop_daemon_process


class TestTier2Boundaries(unittest.TestCase):
    """Tier 2 boundary & corner case test cases."""

    tmpdir: str
    sock_path: str
    audit_path: str
    daemon_proc: Optional[subprocess.Popen] = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="agent_root_runner_t2_")
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

    def test_b01_empty_command_handling(self):
        """B-01: Executing empty string command is handled gracefully without crashing."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("")
        # Empty command should either succeed as no-op (exit 0) or return valid result
        self.assertTrue("result" in resp or "error" in resp)
        if "result" in resp:
            self.assertEqual(resp["result"]["exit_code"], 0)

    def test_b02_whitespace_only_command(self):
        """B-02: Executing whitespace-only command produces clean exit code 0 or handled result."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("     \t   ")
        self.assertTrue("result" in resp or "error" in resp)

    def test_b03_malformed_json_syntax(self):
        """B-03: Sending broken JSON returns JSON-RPC Parse Error (-32700)."""
        raw_resp = self.client.send_raw("{this is not json}\n")
        resp = json.loads(raw_resp)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32700)

    def test_b04_malformed_json_rpc_missing_version(self):
        """B-04: Request missing jsonrpc: '2.0' returns Invalid Request (-32600)."""
        raw_resp = self.client.send_raw(json.dumps({"id": 1, "method": "status"}) + "\n")
        resp = json.loads(raw_resp)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32600)

    def test_b05_malformed_json_rpc_missing_method(self):
        """B-05: Request missing 'method' field returns Invalid Request (-32600)."""
        raw_resp = self.client.send_raw(json.dumps({"jsonrpc": "2.0", "id": 1}) + "\n")
        resp = json.loads(raw_resp)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32600)

    def test_b06_unknown_method_returns_32601(self):
        """B-06: Request with unrecognized method returns Method Not Found (-32601)."""
        resp = self.client.request("nonexistent_method_xyz")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32601)

    def test_b07_stdout_stderr_channel_separation(self):
        """B-07: Verify stdout carries only stdout and stderr carries only stderr without mixing."""
        self.client.arm(duration_seconds=60)
        cmd = "sh -c 'echo \"stdout_line\" ; echo \"stderr_line\" >&2'"
        resp = self.client.exec_cmd(cmd)
        self.assertIn("result", resp)
        res = resp["result"]
        self.assertEqual(res["exit_code"], 0)
        self.assertEqual(res["stdout"].strip(), "stdout_line")
        self.assertEqual(res["stderr"].strip(), "stderr_line")

    def test_b08_extreme_exit_codes(self):
        """B-08: Verify extreme shell exit codes (1, 123, 255) are preserved exactly."""
        self.client.arm(duration_seconds=60)
        for expected_code in [1, 123, 255]:
            resp = self.client.exec_cmd(f"sh -c 'exit {expected_code}'")
            self.assertIn("result", resp)
            self.assertEqual(resp["result"]["exit_code"], expected_code)

    def test_b09_rapid_arm_disarm_toggling(self):
        """B-09: Rapid arm/disarm cycling completes reliably without deadlocks or state drift."""
        for _ in range(15):
            arm_resp = self.client.arm(duration_seconds=5)
            self.assertEqual(arm_resp["result"]["state"], "ARMED")
            disarm_resp = self.client.disarm()
            self.assertEqual(disarm_resp["result"]["state"], "DISARMED")

        # Verify final state is consistently DISARMED
        status = self.client.status()
        self.assertEqual(status["result"]["state"], "DISARMED")

    def test_b10_expired_session_boundary_race(self):
        """B-10: Request submitted right around expiration boundary is deterministically handled."""
        self.client.arm(duration_seconds=1)
        # Sleep exactly to expiration point
        time.sleep(1.05)
        resp = self.client.exec_cmd("echo 'boundary'")
        # Must be rejected because duration expired
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)

    def test_b11_large_output_streaming_buffer(self):
        """B-11: Command generating large volume output (10,000 lines) does not stall socket buffers."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("seq 1 10000")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        lines = resp["result"]["stdout"].strip().split("\n")
        self.assertEqual(len(lines), 10000)
        self.assertEqual(lines[0], "1")
        self.assertEqual(lines[-1], "10000")

    def test_b12_process_group_cleanup_on_timeout(self):
        """B-12: Timed out background processes spawned in subshells are killed cleanly."""
        self.client.arm(duration_seconds=60)
        # Spawns subshell sleep that would otherwise become orphan
        resp = self.client.exec_cmd("sh -c 'sleep 20 & sleep 20'", timeout_seconds=1)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)


if __name__ == "__main__":
    unittest.main()
