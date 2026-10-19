"""Tier 4: Real-World Application Scenarios Test Suite.

Simulates realistic AI agent workloads and production scenarios:
1. Storage diagnostic scenario: smartctl inspection allowed, raw dd write blocked
2. Firewall administration scenario: iptables -L allowed, iptables -F blocked
3. Storage identity scenario: hdparm -I drive inspection
4. System service supervision scenario: systemctl status allowed, systemctl stop blocked
5. End-to-end agent remediation lifecycle workflow with audit provenance
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Optional

from tests.fixtures.client import SocketRpcClient
from tests.fixtures.mock_tools import create_mock_binaries, read_audit_log
from tests.fixtures.daemon_process import start_daemon_process, stop_daemon_process


class TestTier4Scenarios(unittest.TestCase):
    """Tier 4 Real-World Application Scenarios."""

    tmpdir: str
    bin_dir: str
    sock_path: str
    audit_path: str
    daemon_proc: Optional[subprocess.Popen] = None

    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="agent_root_runner_t4_")
        cls.bin_dir = os.path.join(cls.tmpdir, "bin")
        cls.sock_path = os.path.join(cls.tmpdir, "runner.sock")
        cls.audit_path = os.path.join(cls.tmpdir, "audit.log")

        # Create mock binaries for diagnostic commands
        cls.bins = create_mock_binaries(cls.bin_dir)

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
        # The daemon refuses caller-supplied PATH (fail-closed environment), so the
        # mock diagnostic tools are invoked by absolute path instead.
        self.bins = type(self).bins

    def tearDown(self):
        try:
            self.client.disarm()
        except Exception:
            pass
        self.client.close()

    def test_s01_smartctl_storage_inspection_allowed(self):
        """S-01: Agent executes smartctl health query on NVMe drive without guardrail interference."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['smartctl']} -a /dev/nvme0n1")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertIn("PASSED", resp["result"]["stdout"])
        self.assertIn("SAMSUNG", resp["result"]["stdout"])

    def test_s02_smartctl_storage_destruction_blocked(self):
        """S-02: Destructive raw overwrite on the same NVMe drive is firmly rejected."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd("dd if=/dev/zero of=/dev/nvme0n1 bs=1M count=100")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)
        self.assertIn("guardrail", resp["error"]["message"].lower())

    def test_s03_firewall_rule_inspection_allowed(self):
        """S-03: Agent queries firewall state with iptables -L without modification."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['iptables']} -L -n")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertIn("Chain INPUT", resp["result"]["stdout"])

    def test_s04_firewall_rule_flush_blocked(self):
        """S-04: Agent attempting indiscriminate firewall flush (iptables -F) is blocked."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['iptables']} -F")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)

    def test_s05_hdparm_identity_probe_allowed(self):
        """S-05: Agent inspects drive geometry via hdparm -I read-only mode."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['hdparm']} -I /dev/nvme0n1")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertIn("Model Number", resp["result"]["stdout"])

    def test_s06_systemctl_service_query_allowed(self):
        """S-06: Agent checks service status with systemctl status."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['systemctl']} status NetworkManager")
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["exit_code"], 0)
        self.assertIn("active (running)", resp["result"]["stdout"])

    def test_s07_systemctl_network_service_kill_blocked(self):
        """S-07: Agent attempting to stop critical network service is blocked."""
        self.client.arm(duration_seconds=300)
        resp = self.client.exec_cmd(f"{self.bins['systemctl']} stop NetworkManager")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32002)

    def test_s08_full_agent_workflow_with_audit_trail(self):
        """S-08: Complete realistic 6-step agent workflow:
        1. Agent probes status -> DISARMED
        2. Attempt unprivileged action -> Rejected
        3. Operator arms daemon
        4. Agent runs diagnostics -> Allowed
        5. Agent attempts forbidden modification -> Blocked
        6. Agent finishes and operator disarms -> Locked
        """
        # Step 1: Probe status
        st1 = self.client.status()
        self.assertEqual(st1["result"]["state"], "DISARMED")

        # Step 2: Unprivileged command fails
        rej = self.client.exec_cmd(f"{self.bins['smartctl']} -a /dev/nvme0n1")
        self.assertEqual(rej["error"]["code"], -32001)

        # Step 3: Operator arms
        arm_res = self.client.arm(duration_seconds=120)
        self.assertEqual(arm_res["result"]["state"], "ARMED")
        session_id = arm_res["result"]["session_id"]

        # Step 4: Diagnostic succeeds
        diag = self.client.exec_cmd(f"{self.bins['smartctl']} -a /dev/nvme0n1")
        self.assertEqual(diag["result"]["exit_code"], 0)

        # Step 5: Dangerous command blocked
        danger = self.client.exec_cmd("chmod 777 /etc/sudoers")
        self.assertEqual(danger["error"]["code"], -32002)

        # Step 6: Disarm and verify locked
        self.client.disarm()
        st2 = self.client.status()
        self.assertEqual(st2["result"]["state"], "DISARMED")

        # Step 7: Verify audit log records all lifecycle stages
        logs = read_audit_log(self.audit_path)
        events = [e.get("event_type") for e in logs]
        self.assertIn("EXEC_REJECTED", events)
        self.assertIn("ARM", events)
        self.assertIn("EXEC_ALLOWED", events)
        self.assertIn("EXEC_BLOCKED", events)
        self.assertIn("DISARM", events)


if __name__ == "__main__":
    unittest.main()
