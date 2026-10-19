"""Unit tests for the management CLI (install/uninstall helpers)."""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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


if __name__ == "__main__":
    unittest.main()
