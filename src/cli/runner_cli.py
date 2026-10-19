#!/usr/bin/env python3
"""
agent-root-runner — Management CLI for the agent-root-runner daemon.

Provides: arm, disarm, status, install (systemd), uninstall.
"""

import argparse
import json
import os
import shutil
import socket
import sys
import time
from pathlib import Path

# Import daemon modules
sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from src.daemon.server import resolve_socket_path
except ImportError:
    from daemon.server import resolve_socket_path


def connect_socket(sock_path: str) -> socket.socket:
    """Connect to the daemon Unix domain socket."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(sock_path)
        return sock
    except (ConnectionRefusedError, FileNotFoundError) as e:
        sys.exit(f"Error: Cannot connect to daemon at {sock_path}. Is it running? ({e})")
    except PermissionError:
        sys.exit(f"Error: Permission denied connecting to {sock_path}. Check socket group/permissions.")


def send_request(sock: socket.socket, method: str, params: dict = None, req_id: int = 1) -> dict:
    """Send JSON-RPC 2.0 request and read single-line response."""
    request = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params:
        request["params"] = params
    sock.sendall((json.dumps(request) + "\n").encode())
    # Read line
    data = b""
    while b"\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    if not data:
        sys.exit("Error: Daemon closed connection unexpectedly.")
    return json.loads(data.decode().strip())


def handle_rpc_response(response: dict) -> int:
    """Map a JSON-RPC response to a CLI exit code; print message to stderr.

    Exit-code contract (shared with agent-root-exec):
      0 = success, 1 = permission denied (-32003), 124 = timeout (-32004),
      125 = disarmed (-32001), 126 = guardrail blocked (-32002), 128 = other.
    """
    if "error" not in response:
        return 0
    err = response.get("error") or {}
    code = err.get("code", -32603)
    reason = (err.get("data") or {}).get("reason", "")
    message = err.get("message", "Unknown daemon error")
    hint = " (run with sudo)" if (code == -32003 or reason == "PERMISSION_DENIED") else ""
    print(f"Error: {message}{hint}", file=sys.stderr)
    return {-32001: 125, -32002: 126, -32003: 1, -32004: 124}.get(code, 128)


def cmd_status(args):
    sock_path = resolve_socket_path(args.socket)
    sock = connect_socket(sock_path)
    try:
        resp = send_request(sock, "status")
    finally:
        sock.close()
    if "error" in resp:
        sys.exit(handle_rpc_response(resp))
    result = resp.get("result", {})
    print(f"State: {result.get('state', 'UNKNOWN')}")
    print(f"Armed: {result.get('is_armed', False)}")
    for label, key in (
        ("Session", "session_id"),
        ("Armed at", "armed_at"),
        ("Expires at", "expires_at"),
        ("Remaining", "remaining_seconds"),
        ("Timeout", "timeout_seconds"),
        ("Duration", "duration_seconds"),
        ("Forever", "forever"),
        ("Quota limit", "quota_limit"),
        ("Quota remaining", "quota_remaining"),
        ("Commands executed", "commands_executed"),
        ("Lifetime commands", "lifetime_commands"),
        ("Socket", "socket_path"),
        ("Daemon PID", "daemon_pid"),
    ):
        if result.get(key) is not None:
            print(f"{label}: {result[key]}")
    if result.get("state") == "DISARMED":
        print("Daemon is disarmed. Run 'agent-root-runner arm' to enable.")
    elif result.get("forever"):
        print("ARM has no time limit; disarm manually, exhaust quota, or restart the daemon.")


def cmd_arm(args):
    sock_path = resolve_socket_path(args.socket)
    sock = connect_socket(sock_path)
    try:
        params = {"forever": args.forever}
        if not args.forever:
            params["duration_seconds"] = args.duration if args.duration is not None else 900
        if args.quota is not None:
            params["quota"] = args.quota
        resp = send_request(sock, "arm", params)
    finally:
        sock.close()
    if "error" in resp:
        sys.exit(handle_rpc_response(resp))
    result = resp.get("result", {})
    print(f"Armed: {result.get('is_armed', False)}")
    if result.get("expires_at"):
        print(f"Expires at: {result['expires_at']}")
    elif result.get("forever"):
        print("Expires: Never (manual disarm, quota exhaustion, or daemon restart)")
    if result.get("quota"):
        print(f"Quota: {result['quota']} commands")


def cmd_disarm(args):
    sock_path = resolve_socket_path(args.socket)
    sock = connect_socket(sock_path)
    try:
        resp = send_request(sock, "disarm")
    finally:
        sock.close()
    if "error" in resp:
        sys.exit(handle_rpc_response(resp))
    print("Disarmed.")


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INSTALL_PREFIX = Path("/usr/local/lib/agent-root-runner")
BIN_DIR = Path("/usr/local/bin")
SERVICE_NAME = "agent-root-runner.service"
UNIT_DEST_PATH = Path("/etc/systemd/system") / SERVICE_NAME
ENTRY_POINTS = (
    "agent-root-runner",
    "agent-root-runner-daemon",
    "agent-root-exec",
    "agent-root-mcp",
)
MANIFEST_DIR = Path("/etc/agent-root-runner")
MANIFEST_PATH = MANIFEST_DIR / "installed-files"
LAUNCHER_MARKER = "# Launcher installed by agent-root-runner"


def _resolve_unit_source() -> Path:
    """Locate the systemd unit for both source checkouts and frozen builds."""
    candidates = [PROJECT_ROOT / "systemd" / SERVICE_NAME]
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(Path(meipass) / "systemd" / SERVICE_NAME)
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[0]


def _sanitized_child_env() -> dict:
    """Environment for host tools (systemctl, …) spawned by the CLI.

    A PyInstaller one-file build prepends its extraction directory
    (``sys._MEIPASS``) to ``LD_LIBRARY_PATH``. Child processes inherit that and
    would then load the *bundled* shared libraries (for example an older
    ``libcrypto.so.3``) instead of the host's, which breaks dynamically linked
    system tools such as ``systemctl``. Strip the bundle directory (and
    ``LD_PRELOAD``) from the environment handed to our children.
    """
    env = dict(os.environ)
    meipass = getattr(sys, "_MEIPASS", None)
    if not meipass:
        return env

    bundle = os.path.realpath(meipass)
    lib_path = env.get("LD_LIBRARY_PATH", "")
    kept = [
        entry
        for entry in lib_path.split(":")
        if entry and os.path.realpath(entry) != bundle
    ]
    if kept:
        env["LD_LIBRARY_PATH"] = ":".join(kept)
    else:
        env.pop("LD_LIBRARY_PATH", None)
    env.pop("LD_PRELOAD", None)
    return env


def _run_systemctl(*args: str) -> int:
    """Run systemctl, streaming output; return exit code."""
    import subprocess

    return subprocess.call(["systemctl", *args], env=_sanitized_child_env())


def _force_unlink(path: Path) -> None:
    """Remove a file, symlink, or directory occupying ``path`` (if any)."""
    try:
        if path.is_symlink() or path.exists():
            if path.is_dir() and not path.is_symlink():
                shutil.rmtree(path)
            else:
                path.unlink()
    except OSError as exc:
        sys.exit(f"Error: could not replace {path}: {exc}")


def _write_manifest(paths) -> None:
    """Record the paths we installed so uninstall removes only our own files."""
    try:
        MANIFEST_DIR.mkdir(parents=True, exist_ok=True)
        MANIFEST_PATH.write_text("\n".join(str(p) for p in paths) + "\n")
    except OSError as exc:
        print(f"Warning: could not write install manifest: {exc}", file=sys.stderr)


def _read_manifest() -> list:
    if not MANIFEST_PATH.is_file():
        return []
    try:
        return [
            Path(line.strip())
            for line in MANIFEST_PATH.read_text().splitlines()
            if line.strip()
        ]
    except OSError:
        return []


def _looks_like_our_install(path: Path) -> bool:
    """Best-effort check that a PATH entry came from us (no-manifest fallback)."""
    try:
        if path.is_symlink():
            target = path.resolve()
            return INSTALL_PREFIX in target.parents or target == INSTALL_PREFIX
        if path.is_file():
            if path.stat().st_size < 8192:
                return LAUNCHER_MARKER in path.read_text(errors="ignore")
            with open(path, "rb") as fh:
                return fh.read(4) == b"\x7fELF"
    except OSError:
        return False
    return False


def _install_entry_points() -> list:
    """Expose the four entry points on PATH; return the installed paths."""
    if getattr(sys, "frozen", False):
        return _install_frozen_entry_points()
    return _install_source_entry_points()


def _install_source_entry_points() -> list:
    """Deploy the source tree and install small launcher scripts on PATH.

    The deployed tree is only read at runtime. The launchers in
    ``/usr/local/bin`` are tiny shell scripts that exec the running Python
    interpreter against the deployed entry point. Launchers are used instead of
    symlinks into the tree so execution does not depend on how the deployment
    directory is labeled (SELinux) or mounted (``noexec``), and the entry
    points keep ``sys.path`` relative to the deployed tree, so ``src`` remains
    importable.
    """
    root = PROJECT_ROOT.resolve()
    prefix = INSTALL_PREFIX.resolve()
    if root != prefix:
        if root in prefix.parents:
            sys.exit(
                f"Error: refusing to install into {prefix} because it is nested "
                f"inside the source tree {root}."
            )
        INSTALL_PREFIX.parent.mkdir(parents=True, exist_ok=True)
        staging = INSTALL_PREFIX.parent / (INSTALL_PREFIX.name + ".new")
        if staging.exists():
            shutil.rmtree(staging)
        # Copy to a staging dir first so a failure cannot leave a half-written
        # deployment behind the launchers.
        shutil.copytree(
            root,
            staging,
            symlinks=True,
            ignore=shutil.ignore_patterns(".git", "__pycache__", "*.pyc"),
        )
        if INSTALL_PREFIX.exists():
            shutil.rmtree(INSTALL_PREFIX)
        os.replace(staging, INSTALL_PREFIX)

    interpreter = sys.executable or "/usr/bin/python3"
    installed = []
    for name in ENTRY_POINTS:
        target = INSTALL_PREFIX / "bin" / name
        if not target.is_file():
            print(f"Warning: entry point not found, skipping: {target}")
            continue
        launcher = BIN_DIR / name
        _force_unlink(launcher)
        launcher.write_text(
            "#!/bin/sh\n"
            f"{LAUNCHER_MARKER}; see `agent-root-runner install`.\n"
            f'exec "{interpreter}" "{target}" "$@"\n'
        )
        launcher.chmod(0o755)
        installed.append(launcher)
        print(f"Installed: {launcher} -> {target}")
    return installed


def _install_frozen_entry_points() -> list:
    """Copy the sibling standalone release binaries to /usr/local/bin."""
    exe_dir = Path(sys.executable).resolve().parent
    missing = [name for name in ENTRY_POINTS if not (exe_dir / name).is_file()]
    if missing:
        sys.exit(
            "Error: no source tree found and these release binaries are missing "
            f"next to {sys.executable}: {', '.join(missing)}"
        )
    installed = []
    for name in ENTRY_POINTS:
        src = (exe_dir / name).resolve()
        dest = BIN_DIR / name
        if dest.exists() and os.path.samefile(src, dest):
            # Re-running install from the install location: nothing to copy.
            installed.append(dest)
            print(f"Already installed: {dest}")
            continue
        _force_unlink(dest)
        # copyfile/copymode (not copy2) so no source SELinux/xattr labels ride along.
        shutil.copyfile(src, dest)
        shutil.copymode(src, dest)
        dest.chmod(0o755)
        installed.append(dest)
        print(f"Installed: {dest}")
    return installed


def cmd_install(args):
    """Install entry points and the systemd unit, then start and verify."""
    if os.geteuid() != 0:
        sys.exit("Error: install requires root. Run with sudo.")

    unit_source = _resolve_unit_source()
    if not unit_source.is_file():
        sys.exit(f"Error: systemd unit not found (looked at {unit_source}).")

    BIN_DIR.mkdir(parents=True, exist_ok=True)
    print("Installing entry points...")
    installed = _install_entry_points()
    _write_manifest(installed)

    try:
        UNIT_DEST_PATH.write_bytes(unit_source.read_bytes())
    except OSError as exc:
        sys.exit(f"Error: could not install systemd unit: {exc}")
    print(f"Installed systemd unit: {UNIT_DEST_PATH}")

    if _run_systemctl("daemon-reload") != 0:
        sys.exit("Error: systemctl daemon-reload failed.")
    if _run_systemctl("enable", SERVICE_NAME) != 0:
        print(f"Warning: systemctl enable {SERVICE_NAME} failed.", file=sys.stderr)
    if _run_systemctl("restart", SERVICE_NAME) != 0:
        _run_systemctl("status", SERVICE_NAME, "--no-pager")
        sys.exit(f"Error: failed to start {SERVICE_NAME}.")

    time.sleep(0.5)
    if _run_systemctl("is-active", "--quiet", SERVICE_NAME) != 0:
        _run_systemctl("status", SERVICE_NAME, "--no-pager")
        sys.exit(f"Error: {SERVICE_NAME} is not active after start.")
    print(f"{SERVICE_NAME} is active.")


def cmd_uninstall(args):
    """Stop and disable the service, then remove the unit and entry points."""
    if os.geteuid() != 0:
        sys.exit("Error: uninstall requires root. Run with sudo.")
    # Tolerate 'not loaded' / already-stopped failures.
    _run_systemctl("stop", SERVICE_NAME)
    _run_systemctl("disable", SERVICE_NAME)
    if UNIT_DEST_PATH.exists():
        try:
            UNIT_DEST_PATH.unlink()
            print(f"Removed: {UNIT_DEST_PATH}")
        except PermissionError:
            sys.exit("Error: Permission denied. Run with sudo.")
    else:
        print(f"Not found: {UNIT_DEST_PATH}")
    _run_systemctl("daemon-reload")
    _run_systemctl("reset-failed", SERVICE_NAME)

    # Remove only entry points we installed (manifest), plus a safe fallback
    # heuristic for installs made by older versions that lacked a manifest.
    known = set(_read_manifest())
    candidates = list(known)
    for name in ENTRY_POINTS:
        candidate = BIN_DIR / name
        if candidate not in candidates:
            candidates.append(candidate)

    for path in candidates:
        if not (path.is_symlink() or path.exists()):
            continue
        if path not in known and not _looks_like_our_install(path):
            print(f"Skipping (not installed by agent-root-runner): {path}")
            continue
        try:
            path.unlink()
            print(f"Removed: {path}")
        except OSError as exc:
            print(f"Warning: could not remove {path}: {exc}")

    if MANIFEST_PATH.exists():
        try:
            MANIFEST_PATH.unlink()
        except OSError:
            pass
    if MANIFEST_DIR.exists():
        try:
            MANIFEST_DIR.rmdir()
        except OSError:
            pass

    if INSTALL_PREFIX.is_dir() and not INSTALL_PREFIX.is_symlink():
        shutil.rmtree(INSTALL_PREFIX, ignore_errors=True)
        print(f"Removed: {INSTALL_PREFIX}")

    socket_dir = Path("/run/agent-root-runner")
    if socket_dir.exists():
        try:
            socket_dir.rmdir()
            print(f"Removed: {socket_dir}")
        except OSError as exc:
            print(f"Warning: could not remove {socket_dir}: {exc}")

    print("Note: audit logs under /var/log/agent-root-runner are preserved.")


def main():
    parser = argparse.ArgumentParser(
        prog="agent-root-runner",
        description="Management CLI for agent-root-runner daemon",
    )
    parser.add_argument(
        "--socket",
        default=None,
        help="Override socket path (default: auto-resolve via XDG_RUNTIME_DIR)",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Query daemon state")
    subparsers.add_parser("disarm", help="Disarm the daemon (block exec)")

    arm_p = subparsers.add_parser("arm", help="Arm the daemon (allow exec)")
    arm_mode = arm_p.add_mutually_exclusive_group()
    arm_mode.add_argument("--duration", type=int, default=None, help="Arming duration in seconds (default: 900; max: 86400)")
    arm_mode.add_argument("--forever", action="store_true", help="Arm without a time limit; manual disarm, quota exhaustion, or daemon restart ends the session")
    arm_p.add_argument("--quota", type=int, default=None, help="Max commands before auto-disarm")

    subparsers.add_parser("install", help="Install systemd service unit")
    subparsers.add_parser("uninstall", help="Remove systemd service unit")

    args = parser.parse_args()

    if args.command == "status":
        cmd_status(args)
    elif args.command == "arm":
        cmd_arm(args)
    elif args.command == "disarm":
        cmd_disarm(args)
    elif args.command == "install":
        cmd_install(args)
    elif args.command == "uninstall":
        cmd_uninstall(args)


if __name__ == "__main__":
    main()
