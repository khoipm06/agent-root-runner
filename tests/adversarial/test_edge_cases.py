"""Edge cases and failure mode stress testing for Milestone 1.

Investigates:
1. Glibc & dynamic linker unscrubbed variables (GLIBC_TUNABLES, GCONV_PATH).
2. Fail-open vulnerability in peer credential fallback (server.py:200).
3. Active daemon collision and non-socket file collision.
4. Line buffer overflow handling (DDoS defense).
5. Unix domain socket filesystem permission enforcement (0660).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import socket
import stat
import tempfile
import unittest
from unittest.mock import patch

from src.daemon.audit import AuditLogger
from src.daemon.auth import AuthenticationError, PeerCredentials
from src.daemon.executor import InvalidEnvironmentError, SubprocessExecutor
from src.daemon.server import AgentRootRunnerDaemon


class TestDeepAdversarialEdgeCases(unittest.IsolatedAsyncioTestCase):
    """Stress tests and boundary condition investigations."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_adv_edge_")

    async def asyncTearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_unscrubbed_glibc_variables_investigation(self):
        """Investigate whether GLIBC_TUNABLES or GCONV_PATH bypass environment scrubbing."""
        executor = SubprocessExecutor(is_user_mode=True)

        # Check GLIBC_TUNABLES
        glibc_allowed = False
        try:
            cleaned = executor.sanitize_environment({"GLIBC_TUNABLES": "glibc.mem.tagging=3"})
            glibc_allowed = "GLIBC_TUNABLES" in cleaned
        except InvalidEnvironmentError:
            glibc_allowed = False

        # Check GCONV_PATH
        gconv_allowed = False
        try:
            cleaned = executor.sanitize_environment({"GCONV_PATH": "/tmp/gconv"})
            gconv_allowed = "GCONV_PATH" in cleaned
        except InvalidEnvironmentError:
            gconv_allowed = False

        # Document finding: Both GLIBC_TUNABLES and GCONV_PATH are currently NOT blocked by executor
        # We record whether the vulnerability exists
        print(f"\n[EMPIRICAL FINDING] GLIBC_TUNABLES allowed through filter: {glibc_allowed}")
        print(f"[EMPIRICAL FINDING] GCONV_PATH allowed through filter: {gconv_allowed}")

    async def test_peer_credential_fallback_fail_open_vulnerability(self):
        """Investigate server.py:200 fallback behavior if get_peer_credentials raises an exception."""
        sock_path = os.path.join(self.tmpdir, "runner.sock")
        audit_path = os.path.join(self.tmpdir, "audit.log")

        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=False,  # Production mode
        )
        await daemon.start()

        try:
            # Simulate a scenario where SO_PEERCRED extraction fails on the socket
            with patch("src.daemon.server.get_peer_credentials", side_effect=AuthenticationError("SO_PEERCRED failed")):
                reader, writer = await asyncio.open_unix_connection(sock_path)

                req = {
                    "jsonrpc": "2.0",
                    "id": "arm-exploit",
                    "method": "arm",
                    "params": {"duration_seconds": 60},
                }
                writer.write(json.dumps(req).encode("utf-8") + b"\n")
                await writer.drain()

                resp_line = await reader.readline()
                resp = json.loads(resp_line.decode("utf-8"))

                # In server.py lines 200-206:
                # except Exception:
                #     creds = PeerCredentials(pid=os.getpid(), uid=os.geteuid(), gid=os.getegid(), comm="[unresolved]")
                # If daemon runs as root (euid=0), creds.uid will be 0, granting root access!
                # If daemon runs as current user (uid=1000), creds.uid will be 1000.
                print(f"\n[EMPIRICAL FINDING] Server response on SO_PEERCRED failure: {resp}")

                writer.close()
                await writer.wait_closed()

        finally:
            await daemon.stop()

    async def test_socket_mode_0660_enforcement(self):
        """Verify Unix socket file is created with 0660 mode permissions."""
        sock_path = os.path.join(self.tmpdir, "runner.sock")
        audit_path = os.path.join(self.tmpdir, "audit.log")

        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=True,
            socket_mode=0o660,
        )
        await daemon.start()

        try:
            self.assertTrue(os.path.exists(sock_path))
            mode = stat.S_IMODE(os.stat(sock_path).st_mode)
            self.assertEqual(mode, 0o660, f"Expected socket mode 0660, got {oct(mode)}")
        finally:
            await daemon.stop()

    async def test_active_daemon_collision_rejection(self):
        """Verify attempting to start a second daemon on an active socket raises RuntimeError."""
        sock_path = os.path.join(self.tmpdir, "runner.sock")
        daemon1 = AgentRootRunnerDaemon(socket_path=sock_path, allow_user_arm=True)
        await daemon1.start()

        try:
            daemon2 = AgentRootRunnerDaemon(socket_path=sock_path, allow_user_arm=True)
            with self.assertRaises(RuntimeError) as ctx:
                await daemon2.start()
            self.assertIn("Active daemon already listening", str(ctx.exception))
        finally:
            await daemon1.stop()

    async def test_non_socket_path_collision_rejection(self):
        """Verify attempting to start daemon over a regular file raises RuntimeError."""
        file_path = os.path.join(self.tmpdir, "not_a_socket")
        with open(file_path, "w") as f:
            f.write("regular file")

        daemon = AgentRootRunnerDaemon(socket_path=file_path, allow_user_arm=True)
        with self.assertRaises(RuntimeError) as ctx:
            await daemon.start()
        self.assertIn("exists and is not a socket file", str(ctx.exception))

    async def test_line_length_buffer_overflow_defense(self):
        """Verify client sending >10MB line is rejected with -32600 without crashing daemon."""
        sock_path = os.path.join(self.tmpdir, "runner.sock")
        audit_path = os.path.join(self.tmpdir, "audit.log")

        # Set limit to 64KB for faster test execution
        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=True,
            max_buffer_limit=65536,
        )
        await daemon.start()

        try:
            reader, writer = await asyncio.open_unix_connection(sock_path)
            # Send line larger than max_buffer_limit
            oversized_payload = b'{"jsonrpc":"2.0","id":1,"method":"ping","data":"' + (b"A" * 70000) + b'"}\n'
            writer.write(oversized_payload)
            await writer.drain()

            resp_line = await reader.readline()
            resp = json.loads(resp_line.decode("utf-8"))

            self.assertIn("error", resp)
            self.assertEqual(resp["error"]["code"], -32600)
            self.assertIn("buffer limit", resp["error"]["message"])

            writer.close()
            await writer.wait_closed()

            # Verify daemon is still alive and responsive to subsequent clients
            reader2, writer2 = await asyncio.open_unix_connection(sock_path)
            writer2.write(b'{"jsonrpc":"2.0","id":2,"method":"ping"}\n')
            await writer2.drain()
            resp_line2 = await reader2.readline()
            resp2 = json.loads(resp_line2.decode("utf-8"))
            self.assertEqual(resp2["result"]["status"], "ok")
            writer2.close()
            await writer2.wait_closed()

        finally:
            await daemon.stop()


if __name__ == "__main__":
    unittest.main()
