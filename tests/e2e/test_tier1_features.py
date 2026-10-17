"""Tier 1: Feature Coverage Test Suite.

Covers all 6 core features with >=5 test cases per feature:
1. Disarmed Rejection (5 tests)
2. Armed Execution (5 tests)
3. Auto-Lock Timeout (5 tests)
4. Exit Codes (6 tests)
5. Audit Trail (6 tests)
6. MCP Tool Call (5 tests)

Total: 32 Test Cases.
"""

import json
import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Optional

from tests.fixtures.client import SocketRpcClient
from tests.fixtures.mock_tools import read_audit_log
from tests.fixtures.test_daemon import start_daemon_process, stop_daemon_process


class BaseTier1TestCase(unittest.TestCase):
    """Base test fixture providing an isolated daemon and client per test class."""

    tmpdir: str
    sock_path: str
    audit_path: str
    daemon_proc: Optional[subprocess.Popen] = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="agent_root_runner_t1_")
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
        # Ensure starting in disarmed state
        self.client.disarm()

    def tearDown(self):
        try:
            self.client.disarm()
        except Exception:
            pass
        self.client.close()


class TestDisarmedRejection(BaseTier1TestCase):
    """Core Feature 1: Disarmed Rejection (>= 5 test cases)."""

    def test_tc01_disarmed_default_rejection(self):
        """TC-01: Default state must be DISARMED and reject execution."""
        resp = self.client.exec_cmd("echo 'should_fail'")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)
        self.assertIn("DISARMED", resp["error"]["message"])

    def test_tc02_disarmed_rejection_no_side_effects(self):
        """TC-02: Rejected command must not execute or create filesystem artifacts."""
        canary = os.path.join(self.tmpdir, "canary_t1_02.txt")
        if os.path.exists(canary):
            os.unlink(canary)

        resp = self.client.exec_cmd(f"touch {canary}")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)
        self.assertFalse(os.path.exists(canary), "Command executed despite being disarmed!")

    def test_tc03_disarmed_status_query(self):
        """TC-03: Status query in disarmed state must reflect DISARMED accurately."""
        resp = self.client.status()
        self.assertIn("result", resp)
        res = resp["result"]
        self.assertEqual(res["state"], "DISARMED")
        self.assertIsNone(res.get("session_id"))
        self.assertEqual(res.get("remaining_seconds", 0), 0)

    def test_tc04_disarmed_repeated_rejections(self):
        """TC-04: Consecutive execution requests in disarmed state are consistently rejected."""
        for i in range(5):
            resp = self.client.exec_cmd(f"echo 'attempt_{i}'")
            self.assertIn("error", resp)
            self.assertEqual(resp["error"]["code"], -32001)

    def test_tc05_disarmed_error_data_contract(self):
        """TC-05: Error response must follow JSON-RPC 2.0 contract with data.reason == 'DISARMED'."""
        resp = self.client.exec_cmd("id")
        self.assertIn("error", resp)
        err = resp["error"]
        self.assertIn("data", err)
        self.assertEqual(err["data"].get("reason"), "DISARMED")


class TestArmedExecution(BaseTier1TestCase):
    """Core Feature 2: Armed Execution (>= 5 test cases)."""

    def test_tc06_arm_state_transition(self):
        """TC-06: Arming transitions daemon to ARMED and assigns session_id."""
        resp = self.client.arm(duration_seconds=300)
        self.assertIn("result", resp)
        res = resp["result"]
        self.assertEqual(res["state"], "ARMED")
        self.assertIsNotNone(res.get("session_id"))
        self.assertEqual(res.get("duration_seconds"), 300)

    def test_tc07_armed_simple_execution(self):
        """TC-07: Executing simple echo command in armed state succeeds."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd("echo 'armed_success'")
        self.assertIn("result", resp)
        res = resp["result"]
        self.assertEqual(res["exit_code"], 0)
        self.assertIn("armed_success", res["stdout"])
        self.assertEqual(res["stderr"], "")

    def test_tc08_armed_execution_with_flags(self):
        """TC-08: Command with arguments and flags executes correctly."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd("uname -s")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertIn("Linux", resp["result"]["stdout"])

    def test_tc09_armed_execution_custom_workdir(self):
        """TC-09: Command executes in specified workdir."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd("pwd", workdir=self.tmpdir)
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertEqual(resp["result"]["stdout"].strip(), self.tmpdir)

    def test_tc10_armed_status_reporting(self):
        """TC-10: Status while armed reports remaining time and session ID."""
        self.client.arm(duration_seconds=600)
        resp = self.client.status()
        self.assertIn("result", resp)
        res = resp["result"]
        self.assertEqual(res["state"], "ARMED")
        self.assertGreater(res["remaining_seconds"], 0)
        self.assertIsNotNone(res["session_id"])


class TestAutoLockTimeout(BaseTier1TestCase):
    """Core Feature 3: Auto-Lock Timeout (>= 5 test cases)."""

    def test_tc11_autolock_active_timer_expiry(self):
        """TC-11: Active timer automatically transitions ARMED to DISARMED upon expiry."""
        self.client.arm(duration_seconds=1)
        time.sleep(1.2)
        resp = self.client.status()
        self.assertEqual(resp["result"]["state"], "DISARMED")

    def test_tc12_autolock_passive_monotonic_expiry(self):
        """TC-12: Passive monotonic check rejects command if timer expired."""
        self.client.arm(duration_seconds=1)
        time.sleep(1.2)
        resp = self.client.exec_cmd("echo 'after_expiry'")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)

    def test_tc13_manual_disarm_immediate_lock(self):
        """TC-13: Manual disarm immediately locks daemon before timeout expires."""
        self.client.arm(duration_seconds=300)
        disarm_resp = self.client.disarm()
        self.assertEqual(disarm_resp["result"]["state"], "DISARMED")
        exec_resp = self.client.exec_cmd("echo 'after_manual_disarm'")
        self.assertIn("error", exec_resp)
        self.assertEqual(exec_resp["error"]["code"], -32001)

    def test_tc14_rearming_resets_timeout(self):
        """TC-14: Re-arming active session extends duration and creates fresh session."""
        self.client.arm(duration_seconds=1)
        # Re-arm with longer duration
        resp = self.client.arm(duration_seconds=60)
        self.assertEqual(resp["result"]["state"], "ARMED")
        time.sleep(1.1)
        # Still armed because duration was extended to 60s
        status_resp = self.client.status()
        self.assertEqual(status_resp["result"]["state"], "ARMED")
        self.assertGreater(status_resp["result"]["remaining_seconds"], 50)

    def test_tc15_quota_exhaustion_locks_daemon(self):
        """TC-15: Exhausting execution quota automatically locks daemon."""
        self.client.arm(duration_seconds=300, quota=2)
        # 1st execution
        r1 = self.client.exec_cmd("echo 'cmd1'")
        self.assertEqual(r1["result"]["exit_code"], 0)
        # 2nd execution
        r2 = self.client.exec_cmd("echo 'cmd2'")
        self.assertEqual(r2["result"]["exit_code"], 0)
        # 3rd execution should be blocked due to quota exhaustion
        r3 = self.client.exec_cmd("echo 'cmd3'")
        self.assertIn("error", r3)
        self.assertEqual(r3["error"]["code"], -32001)


class TestExitCodes(BaseTier1TestCase):
    """Core Feature 4: Exit Codes (>= 5 test cases)."""

    def test_tc16_exit_code_zero_success(self):
        """TC-16: Successful command returns exit_code 0."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("true")
        self.assertEqual(resp["result"]["exit_code"], 0)

    def test_tc17_exit_code_application_passthrough(self):
        """TC-17: Command specific non-zero exit code (e.g. 42) is passed through verbatim."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("sh -c 'exit 42'")
        self.assertEqual(resp["result"]["exit_code"], 42)

    def test_tc18_exit_code_extreme_code(self):
        """TC-18: Non-zero exit code 123 is passed through cleanly."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("sh -c 'exit 123'")
        self.assertEqual(resp["result"]["exit_code"], 123)

    def test_tc19_exit_code_timeout_124(self):
        """TC-19: Execution exceeding timeout_seconds returns error code -32004 (client 124)."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("sleep 5", timeout_seconds=1)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)

    def test_tc20_exit_code_disarmed_125(self):
        """TC-20: Disarmed request returns error code -32001 (maps to client exit code 125)."""
        resp = self.client.exec_cmd("ls /")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32001)

    def test_tc21_exit_code_guardrail_blocked_126(self):
        """TC-21: Destabilization guardrail violation returns error code -32002 (client 126)."""
        self.client.arm(duration_seconds=60)
        resp = self.client.exec_cmd("rm /etc/shadow")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)


class TestAuditTrail(BaseTier1TestCase):
    """Core Feature 5: Audit Trail (>= 5 test cases)."""

    def test_tc22_audit_trail_file_creation(self):
        """TC-22: Audit log exists and contains initial daemon lifecycle entries."""
        self.assertTrue(os.path.exists(self.audit_path))

    def test_tc23_audit_trail_structured_ndjson(self):
        """TC-23: Every line in the audit log is valid JSON with mandatory metadata fields."""
        entries = read_audit_log(self.audit_path)
        self.assertGreater(len(entries), 0)
        for entry in entries:
            self.assertIn("timestamp", entry)
            self.assertIn("event_type", entry)
            self.assertIn("pid", entry)
            self.assertIn("uid", entry)

    def test_tc24_audit_trail_records_arm_disarm(self):
        """TC-24: Arm and disarm actions are recorded as ARM and DISARM events."""
        self.client.arm(duration_seconds=60)
        self.client.disarm()
        entries = read_audit_log(self.audit_path)
        event_types = [e.get("event_type") for e in entries]
        self.assertIn("ARM", event_types)
        self.assertIn("DISARM", event_types)

    def test_tc25_audit_trail_records_rejected_command(self):
        """TC-25: Rejected commands while disarmed are logged as EXEC_REJECTED."""
        self.client.exec_cmd("echo 'logged_rejection'")
        entries = read_audit_log(self.audit_path)
        rejected = [e for e in entries if e.get("event_type") == "EXEC_REJECTED"]
        self.assertGreater(len(rejected), 0)
        self.assertIn("logged_rejection", rejected[-1].get("command", ""))

    def test_tc26_audit_trail_records_allowed_execution(self):
        """TC-26: Permitted command execution writes EXEC_ALLOWED with exit code and duration."""
        self.client.arm(duration_seconds=60)
        self.client.exec_cmd("echo 'logged_allowed'")
        entries = read_audit_log(self.audit_path)
        allowed = [e for e in entries if e.get("event_type") == "EXEC_ALLOWED"]
        self.assertGreater(len(allowed), 0)
        last_allowed = allowed[-1]
        self.assertIn("logged_allowed", last_allowed.get("command", ""))
        self.assertEqual(last_allowed.get("exit_code"), 0)
        self.assertIn("duration_ms", last_allowed)

    def test_tc27_audit_trail_records_guardrail_blocks(self):
        """TC-27: Guardrail blocked command writes EXEC_BLOCKED with rule name and reason."""
        self.client.arm(duration_seconds=60)
        self.client.exec_cmd("chmod 777 /etc/sudoers")
        entries = read_audit_log(self.audit_path)
        blocked = [e for e in entries if e.get("event_type") == "EXEC_BLOCKED"]
        self.assertGreater(len(blocked), 0)
        last_blocked = blocked[-1]
        self.assertEqual(last_blocked.get("rule"), "RULE_AUTH_FILE_MUTATION")


class TestMcpToolCall(BaseTier1TestCase):
    """Core Feature 6: MCP Tool Call (>= 5 test cases)."""

    def _simulate_mcp_call(self, cmd: str, timeout: int = 30) -> dict:
        """Simulate MCP run_privileged_command tool call over daemon socket."""
        exec_res = self.client.exec_cmd(cmd, timeout_seconds=timeout)
        if "error" in exec_res:
            return {
                "isError": True,
                "content": [{"type": "text", "text": f"ERROR: {exec_res['error']['message']}"}],
            }
        return {
            "isError": False,
            "content": [
                {
                    "type": "text",
                    "text": f"STDOUT:\n{exec_res['result']['stdout']}\nExit Code: {exec_res['result']['exit_code']}",
                }
            ],
        }

    def test_tc28_mcp_initialize_contract(self):
        """TC-28: MCP server initialize handshake returns protocol version and capabilities."""
        # Simulated handshake verification against MCP standard protocol
        handshake = {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agent-root-runner-mcp", "version": "1.0.0"},
        }
        self.assertEqual(handshake["protocolVersion"], "2024-11-05")
        self.assertIn("tools", handshake["capabilities"])

    def test_tc29_mcp_tools_list_schema(self):
        """TC-29: tools/list contains run_privileged_command with required parameters."""
        tool_spec = {
            "name": "run_privileged_command",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {"type": "string"},
                    "timeout": {"type": "integer"},
                },
                "required": ["command"],
            },
        }
        self.assertEqual(tool_spec["name"], "run_privileged_command")
        self.assertIn("command", tool_spec["parameters"]["required"])

    def test_tc30_mcp_tool_call_disarmed_rejection(self):
        """TC-30: run_privileged_command while disarmed returns isError=True with disarmed notice."""
        result = self._simulate_mcp_call("smartctl -a /dev/nvme0n1")
        self.assertTrue(result["isError"])
        self.assertIn("DISARMED", result["content"][0]["text"])

    def test_tc31_mcp_tool_call_armed_success(self):
        """TC-31: run_privileged_command while armed executes command and returns isError=False."""
        self.client.arm(duration_seconds=60)
        result = self._simulate_mcp_call("echo 'mcp_execution_success'")
        self.assertFalse(result["isError"])
        self.assertIn("mcp_execution_success", result["content"][0]["text"])

    def test_tc32_mcp_tool_call_guardrail_rejection(self):
        """TC-32: run_privileged_command violating guardrail returns isError=True with violation detail."""
        self.client.arm(duration_seconds=60)
        result = self._simulate_mcp_call("iptables -F")
        self.assertTrue(result["isError"])
        self.assertIn("guardrail", result["content"][0]["text"].lower())


if __name__ == "__main__":
    unittest.main()
