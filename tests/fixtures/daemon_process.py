"""Launch the REAL agent-root-runner daemon for end-to-end tests.

The E2E suites exercise ``src.daemon.server`` (the production daemon) instead of
a mock, so they cover the actual state machine, guardrail analyzer, subprocess
executor, and audit logger.

When the test process is unprivileged the daemon is started with
``--allow-user-arm`` so the suite can arm it without sudo. (The daemon refuses
that flag when it runs as root; when the test process *is* root it can simply
arm directly, so the flag is omitted.)
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from typing import Optional

from tests.fixtures.client import SocketRpcClient


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def start_daemon_process(
    socket_path: str,
    audit_log_path: str,
    allow_user_arm: bool = True,
    timeout: float = 10.0,
) -> subprocess.Popen:
    """Start the real daemon in a background subprocess and wait for readiness."""
    cmd = [
        sys.executable,
        "-m",
        "src.daemon.server",
        "--socket",
        socket_path,
        "--audit-log",
        audit_log_path,
    ]
    if allow_user_arm and os.geteuid() != 0:
        cmd.append("--allow-user-arm")

    stderr_path = audit_log_path + ".daemon.stderr"
    with open(stderr_path, "wb") as err_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=err_fh,
            cwd=_project_root(),
        )

    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            break
        if os.path.exists(socket_path):
            try:
                with SocketRpcClient(socket_path=socket_path, timeout=0.5) as client:
                    resp = client.ping()
                    if resp.get("result", {}).get("status") == "ok":
                        return proc
            except Exception:
                pass
        time.sleep(0.05)

    proc.terminate()
    try:
        proc.wait(timeout=1.0)
    except Exception:
        proc.kill()

    detail = ""
    try:
        with open(stderr_path, "r", errors="replace") as fh:
            detail = fh.read()
    except OSError:
        pass
    raise RuntimeError(
        f"Real daemon failed to bind and respond on {socket_path} within {timeout}s "
        f"(exit={proc.poll()}). stderr:\n{detail}"
    )


def stop_daemon_process(proc: Optional[subprocess.Popen]) -> None:
    """Cleanly terminate the daemon subprocess."""
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
            try:
                proc.wait(timeout=1.0)
            except Exception:
                pass
