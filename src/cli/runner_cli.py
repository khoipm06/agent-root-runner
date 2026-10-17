#!/usr/bin/env python3
"""
agent-root-runner — Management CLI for the agent-root-runner daemon.

Provides: arm, disarm, status, install (systemd), uninstall.
"""

import argparse
import json
import os
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


def cmd_arm(args):
    sock_path = resolve_socket_path(args.socket)
    sock = connect_socket(sock_path)
    try:
        params = {"duration_seconds": args.duration}
        if args.quota:
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
UNIT_SOURCE_PATH = PROJECT_ROOT / "systemd" / "agent-root-runner.service"
UNIT_DEST_PATH = Path("/etc/systemd/system/agent-root-runner.service")


def _run_systemctl(*args: str) -> int:
    """Run systemctl, streaming output; return exit code."""
    import subprocess

    return subprocess.call(["systemctl", *args])


def cmd_install(args):
    """Install systemd service unit by copying the repo unit file, then enable it."""
    if os.geteuid() != 0:
        sys.exit("Error: install requires root. Run with sudo.")
    if not UNIT_SOURCE_PATH.is_file():
        sys.exit(f"Error: unit file not found: {UNIT_SOURCE_PATH}")
    try:
        UNIT_DEST_PATH.write_bytes(UNIT_SOURCE_PATH.read_bytes())
    except PermissionError:
        sys.exit("Error: Permission denied. Run with sudo.")
    print(f"Installed systemd unit: {UNIT_DEST_PATH}")
    _run_systemctl("daemon-reload")
    if _run_systemctl("enable", "--now", "agent-root-runner.service") != 0:
        sys.exit("Error: systemctl enable --now agent-root-runner.service failed.")


def cmd_uninstall(args):
    """Stop, disable and remove the systemd service unit."""
    if os.geteuid() != 0:
        sys.exit("Error: uninstall requires root. Run with sudo.")
    # Tolerate 'not loaded' / already-stopped failures.
    _run_systemctl("stop", "agent-root-runner.service")
    _run_systemctl("disable", "agent-root-runner.service")
    if UNIT_DEST_PATH.exists():
        try:
            UNIT_DEST_PATH.unlink()
            print(f"Removed: {UNIT_DEST_PATH}")
        except PermissionError:
            sys.exit("Error: Permission denied. Run with sudo.")
    else:
        print(f"Not found: {UNIT_DEST_PATH}")
    _run_systemctl("daemon-reload")
    socket_dir = Path("/run/agent-root-runner")
    if socket_dir.exists():
        try:
            socket_dir.rmdir()
            print(f"Removed: {socket_dir}")
        except OSError as e:
            print(f"Warning: could not remove {socket_dir}: {e}")


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
    arm_p.add_argument("--duration", type=int, default=900, help="Arming duration in seconds (default: 900)")
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
