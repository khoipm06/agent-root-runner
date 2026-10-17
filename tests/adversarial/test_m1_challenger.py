"""Milestone 1 Challenger Empirical Stress Tests & Vulnerability Harness.

Adversarial Verification Suite for:
1. Socket Framing Stress:
   - Broken JSON lines & syntax errors
   - Pipelined requests in a single TCP/socket buffer
   - Rapid connect/disconnect stress
   - Huge payloads & buffer limit boundaries
   - Null bytes and binary corruption
2. Timeout & Process Tree Killing Stress:
   - Nested sleep tree cleanup via os.killpg
   - Background detached child orphan leak & stream truncation bug
   - Process group detachment escape via setsid
3. State Machine Race Conditions & Security Boundaries:
   - Silent re-arming vulnerability: refund_quota overriding manual disarm
   - Semaphore queuing execution after daemon disarm/expiry
   - Concurrent requests near expiry boundary
   - SO_PEERCRED fallback fail-open privilege escalation
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from src.daemon.audit import AuditLogger
from src.daemon.auth import AuthenticationError, PeerCredentials
from src.daemon.executor import SubprocessExecutor
from src.daemon.server import AgentRootRunnerDaemon
from src.daemon.state import DisarmReason, RunnerState, RunnerStateMachine


def _find_pids_matching(cmd_pattern: str) -> list[int]:
    """Find system PIDs matching pattern via pgrep/ps for leak detection."""
    try:
        out = subprocess.check_output(["pgrep", "-f", cmd_pattern], text=True)
        my_pid = os.getpid()
        return [int(p) for p in out.strip().split("\n") if p and int(p) != my_pid]
    except (subprocess.CalledProcessError, ValueError):
        return []


def _cleanup_pids(pids: list[int]) -> None:
    """Force kill lingering test processes."""
    for pid in pids:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


class TestSocketFramingStress(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress testing of Unix domain socket line-delimited JSON-RPC framing."""

    async def asyncSetUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="test_chal_framing_")
        self.sock_path = os.path.join(self.tmpdir, "runner.sock")
        self.audit_path = os.path.join(self.tmpdir, "audit.log")
        self.daemon = AgentRootRunnerDaemon(
            socket_path=self.sock_path,
            audit_log_path=self.audit_path,
            allow_user_arm=True,
            max_buffer_limit=1024 * 1024,  # 1MB for testing
        )
        await self.daemon.start()

    async def asyncTearDown(self):
        await self.daemon.stop()
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    async def test_broken_json_lines_fuzzing(self):
        """Verify broken, malformed, and truncated JSON lines return valid JSON-RPC error codes without killing daemon."""
        reader, writer = await asyncio.open_unix_connection(self.sock_path)
        try:
            fuzz_inputs = [
                b'{"jsonrpc": "2.0", "method": "ping" INVALID\n',
                b'{"jsonrpc": "2.0", "unclosed_brace": true\n',
                b'{not_even_json}\n',
                b'null\n',
                b'12345\n',
                b'"just a string"\n',
                b'{"jsonrpc": "1.0", "method": "ping"}\n',
                b'{"jsonrpc": "2.0"}\n',  # missing method
                b'{"jsonrpc": "2.0", "method": 999}\n',  # method not string
                b'{"jsonrpc": "2.0", "method": "ping", "params": "string_not_dict"}\n',
                b'\n\n\n',  # empty lines
                b'   \t   \n',  # whitespace only
            ]

            for payload in fuzz_inputs:
                writer.write(payload)
                await writer.drain()
                # Empty lines produce no response, valid malformed produce error JSON
                if payload.strip():
                    line = await reader.readline()
                    self.assertTrue(len(line) > 0, f"No response for payload: {payload}")
                    data = json.loads(line.decode("utf-8"))
                    self.assertIn("error", data, f"Expected error for payload: {payload}")
                    self.assertIn(data["error"]["code"], [-32700, -32600, -32601, -32602])

            # Verify daemon survives fuzzing and responds to valid ping
            writer.write(b'{"jsonrpc": "2.0", "id": 999, "method": "ping"}\n')
            await writer.drain()
            resp_line = await reader.readline()
            resp = json.loads(resp_line.decode("utf-8"))
            self.assertEqual(resp.get("result", {}).get("status"), "ok")

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_pipelined_requests_in_single_buffer(self):
        """Verify sending 50 pipelined requests in one buffer executes and replies to all 50 in order."""
        reader, writer = await asyncio.open_unix_connection(self.sock_path)
        try:
            n_requests = 50
            payloads = []
            for i in range(n_requests):
                payloads.append(f'{{"jsonrpc": "2.0", "id": {i}, "method": "ping"}}')
            batch_bytes = ("\n".join(payloads) + "\n").encode("utf-8")

            # Write all in a single write call
            writer.write(batch_bytes)
            await writer.drain()

            # Read all 50 responses
            received_ids = []
            for _ in range(n_requests):
                line = await reader.readline()
                self.assertTrue(len(line) > 0)
                data = json.loads(line.decode("utf-8"))
                self.assertEqual(data.get("result", {}).get("status"), "ok")
                received_ids.append(data.get("id"))

            self.assertEqual(received_ids, list(range(n_requests)))

        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    async def test_rapid_connect_disconnect_stress(self):
        """Stress daemon with 60 rapid connect/disconnect cycles under varying partial states."""
        for _ in range(20):
            # 1. Connect and close immediately
            r, w = await asyncio.open_unix_connection(self.sock_path)
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass

            # 2. Connect, send partial payload without newline, close
            r, w = await asyncio.open_unix_connection(self.sock_path)
            w.write(b'{"jsonrpc": "2.0", "method": "pin')
            await w.drain()
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass

            # 3. Connect, send full request, close before reading
            r, w = await asyncio.open_unix_connection(self.sock_path)
            w.write(b'{"jsonrpc": "2.0", "id": 1, "method": "ping"}\n')
            await w.drain()
            w.close()
            try:
                await w.wait_closed()
            except Exception:
                pass

        # Verify daemon is healthy after rapid connect/disconnect storm
        r, w = await asyncio.open_unix_connection(self.sock_path)
        w.write(b'{"jsonrpc": "2.0", "id": 100, "method": "ping"}\n')
        await w.drain()
        line = await r.readline()
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        resp = json.loads(line.decode("utf-8"))
        self.assertEqual(resp.get("result", {}).get("status"), "ok")

    async def test_huge_payload_buffer_limit_handling(self):
        """Verify oversized line exceeding max_buffer_limit returns -32600 and disconnects gracefully."""
        # Use daemon with 65536 byte limit
        limit_sock = os.path.join(self.tmpdir, "limit.sock")
        limit_daemon = AgentRootRunnerDaemon(
            socket_path=limit_sock,
            audit_log_path=os.path.join(self.tmpdir, "limit_audit.log"),
            allow_user_arm=True,
            max_buffer_limit=65536,
        )
        await limit_daemon.start()
        try:
            reader, writer = await asyncio.open_unix_connection(limit_sock)
            # Send line larger than 65536
            huge_line = b'{"jsonrpc": "2.0", "id": 1, "method": "ping", "data": "' + (b"X" * 70000) + b'"}\n'
            writer.write(huge_line)
            await writer.drain()

            resp_line = await reader.readline()
            self.assertTrue(len(resp_line) > 0)
            data = json.loads(resp_line.decode("utf-8"))
            self.assertIn("error", data)
            self.assertEqual(data["error"]["code"], -32600)
            self.assertIn("buffer limit", data["error"]["message"])

            # Verify connection was terminated by server
            next_line = await reader.readline()
            self.assertEqual(next_line, b"")

            writer.close()
            await writer.wait_closed()
        finally:
            await limit_daemon.stop()



class TestProcessKillingAndOrphansStress(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress testing of process tree termination and child orphan leaks."""

    async def asyncSetUp(self):
        self.executor = SubprocessExecutor(is_user_mode=True)

    async def test_nested_sleep_tree_terminated_cleanly_on_timeout(self):
        """Verify os.killpg terminates a synchronous nested sleep tree on timeout."""
        # Tree that stays attached to process group:
        # parent bash -> subshell -> sleep
        cmd = 'bash -c "sleep 40 & (sleep 40 & wait) & wait"'
        res = await self.executor.execute(cmd, timeout_seconds=0.5)

        self.assertTrue(res.timed_out)
        self.assertEqual(res.exit_code, 124)

        # Allow kernel a moment to process SIGKILL
        await asyncio.sleep(0.3)
        pids_after = _find_pids_matching("sleep 40")
        _cleanup_pids(pids_after)
        self.assertEqual(
            len(pids_after),
            0,
            f"Expected all processes in PG to be killed, but found lingering PIDs: {pids_after}",
        )

    async def test_detached_background_child_orphan_and_stdout_wipe_flaw(self):
        """EMPIRICAL BUG CONFIRMATION: Background child process causes stream drain timeout,

        wipes collected stdout, and leaves orphaned background process running.
        """
        # Clean any prior sleeps
        _cleanup_pids(_find_pids_matching("sleep 42"))

        # Command spawns background child without redirecting stdout, then prints 'output_captured' and exits
        cmd = 'python3 -c "import subprocess; subprocess.Popen([\'sleep\', \'42\']); print(\'output_captured\')"'
        start_t = time.monotonic()
        res = await self.executor.execute(cmd, timeout_seconds=5)
        duration = time.monotonic() - start_t

        await asyncio.sleep(0.2)
        pids_after = _find_pids_matching("sleep 42")

        try:
            print(f"\n[EMPIRICAL FINDING] Subprocess stdout after background spawn: {repr(res.stdout)}")
            print(f"[EMPIRICAL FINDING] Execution duration: {duration:.2f}s (expected <0.2s without pipe hang)")
            print(f"[EMPIRICAL FINDING] Lingering orphan PIDs: {pids_after}")

            # Verified Fix 1: stdout is preserved despite stream drain timeout
            self.assertIn("output_captured", res.stdout)
            self.assertNotIn("truncated", res.stdout.lower())

            # Verified Fix 2: Pipe drain timeout duration
            self.assertGreaterEqual(duration, 1.9)

            # Verified Fix 3: Background child process killed; zero lingering orphan processes
            self.assertEqual(
                len(pids_after),
                0,
                "Expected all background child processes in PG to be terminated cleanly",
            )
        finally:
            _cleanup_pids(pids_after)

    async def test_setsid_child_escapes_process_group(self):
        """EMPIRICAL FINDING: Child process calling setsid creates a new PGID and escapes killpg."""
        _cleanup_pids(_find_pids_matching("sleep 43"))
        cmd = "setsid sleep 43"

        res = await self.executor.execute(cmd, timeout_seconds=0.5)

        await asyncio.sleep(0.2)
        pids_after = _find_pids_matching("sleep 43")
        try:
            print(f"\n[EMPIRICAL FINDING] setsid process survived execution: {pids_after}")
            self.assertGreater(len(pids_after), 0)
        finally:
            _cleanup_pids(pids_after)


class TestStateMachineRaceConditionsAndVulnerabilities(unittest.IsolatedAsyncioTestCase):
    """Adversarial stress testing of state machine transitions, concurrency races, and auth bugs."""

    async def test_silent_rearming_vulnerability_via_quota_refund(self):
        """CRITICAL VULNERABILITY: refund_quota() overrides manual disarm and silently re-arms daemon

        without restarting the active auto-lock timer task.
        """
        sm = RunnerStateMachine()
        # 1. Arm daemon with quota=5 and duration=300
        await sm.arm(duration_seconds=300, quota=5, allow_user_arm=True)
        self.assertEqual(sm.state, RunnerState.ARMED)

        # 2. Command 1 admitted
        allowed, _ = await sm.check_permission_and_decrement_quota()
        self.assertTrue(allowed)

        # 3. User realizes an emergency and executes MANUAL DISARM
        disarm_res = await sm.disarm(reason="MANUAL_DISARM")
        self.assertEqual(sm.state, RunnerState.DISARMED)
        self.assertEqual(disarm_res["reason"], "MANUAL_DISARM")

        # 4. Command 1 fails pre-execution (guardrail blocked or invalid workdir) -> refund_quota() called
        await sm.refund_quota()

        # EMPIRICAL VULNERABILITY CONFIRMATION:
        # refund_quota() sets state back to ARMED! Manual disarm was completely bypassed!
        is_silently_rearmed = sm.state == RunnerState.ARMED
        has_active_timer = sm._timer_task is not None and not sm._timer_task.done()

        print(f"\n[EMPIRICAL FINDING] Daemon silently re-armed after manual disarm: {is_silently_rearmed}")
        print(f"[EMPIRICAL FINDING] Active countdown timer task running: {has_active_timer}")

        self.assertFalse(
            is_silently_rearmed,
            "Security verification: refund_quota() must NOT re-arm the service after manual disarm!",
        )
        self.assertEqual(sm.state, RunnerState.DISARMED)
        self.assertEqual(sm._last_disarm_reason, DisarmReason.MANUAL_DISARM.value)
        self.assertFalse(
            has_active_timer,
            "Daemon must remain disarmed with no active timer task running",
        )

        await sm.reset()

    async def test_queued_command_executes_after_manual_disarm(self):
        """CONCURRENCY RACE: Command queued on SubprocessExecutor semaphore executes

        after the user has manually disarmed the daemon.
        """
        tmpdir = tempfile.mkdtemp(prefix="test_chal_race_")
        sock_path = os.path.join(tmpdir, "runner.sock")
        audit_path = os.path.join(tmpdir, "audit.log")

        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=True,
        )
        await daemon.start()

        try:
            await daemon.state_machine.arm(duration_seconds=30, allow_user_arm=True)

            # Request 1: Long-running command (2.0s) holding the semaphore
            async def req_long():
                r, w = await asyncio.open_unix_connection(sock_path)
                req = {"jsonrpc": "2.0", "id": 1, "method": "exec", "params": {"command": "sleep 2.0"}}
                w.write(json.dumps(req).encode() + b"\n")
                await w.drain()
                resp = await r.readline()
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return json.loads(resp.decode())

            # Request 2: Admitted while armed, but queued behind Request 1
            async def req_queued():
                await asyncio.sleep(0.3)
                r, w = await asyncio.open_unix_connection(sock_path)
                req = {"jsonrpc": "2.0", "id": 2, "method": "exec", "params": {"command": "echo 'unauthorized_post_disarm'"}}
                w.write(json.dumps(req).encode() + b"\n")
                await w.drain()
                resp = await r.readline()
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return json.loads(resp.decode())

            # User disarms at t = 0.8s
            async def user_disarm():
                await asyncio.sleep(0.8)
                r, w = await asyncio.open_unix_connection(sock_path)
                req = {"jsonrpc": "2.0", "id": 3, "method": "disarm"}
                w.write(json.dumps(req).encode() + b"\n")
                await w.drain()
                resp = await r.readline()
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return json.loads(resp.decode())

            res_long, res_queued, res_disarm = await asyncio.gather(
                req_long(), req_queued(), user_disarm()
            )

            # Disarm succeeded at t=0.8s
            self.assertEqual(res_disarm.get("result", {}).get("state"), "DISARMED")

            # Verified Fix: Queued request rejected with -32001 because service was disarmed while queued
            print(f"\n[VERIFIED RESULT] Queued execution after disarm result: {res_queued}")
            self.assertIn("error", res_queued)
            self.assertEqual(res_queued["error"]["code"], -32001)
            self.assertIn("DISARMED", res_queued["error"]["message"])
            self.assertNotIn("result", res_queued)

        finally:
            await daemon.stop()
            shutil.rmtree(tmpdir, ignore_errors=True)

    async def test_concurrent_requests_at_expiry_boundary(self):
        """Verify 20 concurrent requests near expiry boundary fail closed without race errors."""
        tmpdir = tempfile.mkdtemp(prefix="test_chal_expiry_")
        sock_path = os.path.join(tmpdir, "runner.sock")
        audit_path = os.path.join(tmpdir, "audit.log")

        daemon = AgentRootRunnerDaemon(
            socket_path=sock_path,
            audit_log_path=audit_path,
            allow_user_arm=True,
        )
        await daemon.start()

        try:
            # Arm for 1 second, but artificially adjust expiry to test boundary
            await daemon.state_machine.arm(duration_seconds=1, allow_user_arm=True)
            daemon.state_machine._session.expires_at_monotonic = time.monotonic() + 0.3

            async def send_status():
                r, w = await asyncio.open_unix_connection(sock_path)
                req = {"jsonrpc": "2.0", "id": 1, "method": "status"}
                w.write(json.dumps(req).encode() + b"\n")
                await w.drain()
                line = await r.readline()
                w.close()
                try:
                    await w.wait_closed()
                except Exception:
                    pass
                return json.loads(line.decode())

            # Send requests across the 0.3s boundary (from t=0.0s to t=0.7s)
            tasks = []
            for i in range(15):
                delay = 0.05 * i
                async def delayed(d):
                    await asyncio.sleep(d)
                    return await send_status()
                tasks.append(delayed(delay))

            results = await asyncio.gather(*tasks)

            # Verify all responses are valid JSON-RPC and transition from ARMED to DISARMED
            states = [r.get("result", {}).get("state") for r in results]
            self.assertTrue(all(s in ["ARMED", "DISARMED"] for s in states))
            # The final state must be DISARMED
            self.assertEqual(states[-1], "DISARMED")

        finally:
            await daemon.stop()
            shutil.rmtree(tmpdir, ignore_errors=True)

    async def test_peer_credential_fallback_root_privilege_escalation(self):
        """EMPIRICAL FINDING: server.py:200 fallback to os.geteuid() grants root access

        when running as root if peer credential extraction raises an exception.
        """
        # When running as root daemon (geteuid == 0):
        # If get_peer_credentials raises an exception, creds is instantiated with:
        # creds = PeerCredentials(pid=os.getpid(), uid=os.geteuid(), gid=os.getegid(), comm="[unresolved]")
        # Since euid == 0, creds.uid is 0, granting root privilege to an unauthenticated connection!
        with patch("os.geteuid", return_value=0):
            with patch("src.daemon.server.get_peer_credentials", side_effect=AuthenticationError("kernel SO_PEERCRED failed")):
                tmpdir = tempfile.mkdtemp(prefix="test_chal_auth_")
                sock_path = os.path.join(tmpdir, "runner.sock")
                daemon = AgentRootRunnerDaemon(
                    socket_path=sock_path,
                    audit_log_path=os.path.join(tmpdir, "audit.log"),
                    allow_user_arm=False,  # Production mode: only root allowed!
                )
                await daemon.start()
                try:
                    r, w = await asyncio.open_unix_connection(sock_path)
                    req = {"jsonrpc": "2.0", "id": "exploit", "method": "arm", "params": {"duration_seconds": 60}}
                    w.write(json.dumps(req).encode() + b"\n")
                    await w.drain()
                    line = await r.readline()
                    w.close()
                    try:
                        await w.wait_closed()
                    except Exception:
                        pass
                    resp = json.loads(line.decode())
                    print(f"\n[VERIFIED RESULT] Fail-closed response with mocked root daemon: {resp}")
                    # Verified Fix: Unauthenticated peer credential extraction fails closed with -32003
                    self.assertIn("error", resp)
                    self.assertEqual(resp["error"]["code"], -32003)
                    self.assertIn("Permission denied", resp["error"]["message"])
                finally:
                    await daemon.stop()
                    shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
