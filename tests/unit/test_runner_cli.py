"""Unit tests for the management CLI (install/uninstall helpers)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO

from src.cli import runner_cli


class TestSanitizedChildEnv(unittest.TestCase):
    """The CLI must not leak a PyInstaller bundle dir into child processes."""

    def test_passthrough_when_not_frozen(self):
        with mock.patch.object(sys, "_MEIPASS", None, create=True):
            env = runner_cli._sanitized_child_env()
        self.assertEqual(
            env.get("LD_LIBRARY_PATH"), os.environ.get("LD_LIBRARY_PATH")
        )

    def test_strips_bundle_dir_but_keeps_other_entries(self):
        bundle = tempfile.mkdtemp(prefix="meipass_")
        self.addCleanup(lambda: os.rmdir(bundle))
        with mock.patch.dict(
            os.environ,
            {"LD_LIBRARY_PATH": f"{bundle}:/opt/lib", "LD_PRELOAD": "/evil.so"},
        ):
            with mock.patch.object(sys, "_MEIPASS", bundle, create=True):
                env = runner_cli._sanitized_child_env()
        self.assertEqual(env.get("LD_LIBRARY_PATH"), "/opt/lib")
        self.assertNotIn("LD_PRELOAD", env)

    def test_drops_ld_library_path_when_only_bundle_entry(self):
        bundle = tempfile.mkdtemp(prefix="meipass_")
        self.addCleanup(lambda: os.rmdir(bundle))
        with mock.patch.dict(os.environ, {"LD_LIBRARY_PATH": bundle}):
            with mock.patch.object(sys, "_MEIPASS", bundle, create=True):
                env = runner_cli._sanitized_child_env()
        self.assertNotIn("LD_LIBRARY_PATH", env)

    def test_run_systemctl_spawns_child_without_bundle_on_library_path(self):
        """End-to-end: a fake systemctl observes a clean LD_LIBRARY_PATH."""
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "out.txt"
            fake = Path(d) / "systemctl"
            fake.write_text(
                "#!/bin/sh\n"
                f'printf "%s" "${{LD_LIBRARY_PATH:-<unset>}}" > "{out}"\n'
            )
            fake.chmod(0o755)

            bundle = tempfile.mkdtemp(prefix="meipass_")
            self.addCleanup(lambda: os.rmdir(bundle))
            with mock.patch.dict(os.environ, {"PATH": d, "LD_LIBRARY_PATH": bundle}):
                with mock.patch.object(sys, "_MEIPASS", bundle, create=True):
                    rc = runner_cli._run_systemctl("--version")

            self.assertEqual(rc, 0)
            self.assertEqual(out.read_text(), "<unset>")


class TestArmCli(unittest.TestCase):
    def test_forever_arm_sends_forever_and_quota_without_duration(self):
        sock = mock.Mock()
        output = StringIO()
        response = {
            "result": {
                "is_armed": True,
                "forever": True,
                "expires_at": None,
                "quota": 3,
            }
        }
        with mock.patch.object(sys, "argv", ["agent-root-runner", "arm", "--forever", "--quota", "3"]):
            with mock.patch.object(runner_cli, "resolve_socket_path", return_value="/run/test.sock"):
                with mock.patch.object(runner_cli, "connect_socket", return_value=sock):
                    with mock.patch.object(runner_cli, "send_request", return_value=response) as send:
                        with redirect_stdout(output):
                            runner_cli.main()

        send.assert_called_once_with(sock, "arm", {"forever": True, "quota": 3})
        sock.close.assert_called_once_with()
        self.assertIn("Expires: Never", output.getvalue())

    def test_forever_and_duration_are_mutually_exclusive(self):
        with mock.patch.object(sys, "argv", ["agent-root-runner", "arm", "--forever", "--duration", "60"]):
            with redirect_stderr(StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    runner_cli.main()
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
