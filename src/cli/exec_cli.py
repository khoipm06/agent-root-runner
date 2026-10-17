#!/usr/bin/env python3
"""
agent-root-exec — Transparent execution wrapper for privileged commands.

Sends exec requests to the agent-root-runner daemon via Unix domain socket.
Exit codes:
  0-123  : command exit code (pass-through)
  124    : execution timeout
  125    : daemon disarmed
  126    : guardrail blocked
  128    : daemon error / connection failure
"""

import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from src.daemon.server import resolve_socket_path
except ImportError:
    from daemon.server import resolve_socket_path


def send_exec(sock_path: str, command: str, timeout: int, workdir: str, env: dict) -> dict:
    """Connect and send exec request; return JSON-RPC response."""
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout + 10)  # allow daemon overhead
        sock.connect(sock_path)
    except (ConnectionRefusedError, FileNotFoundError) as e:
        sys.exit(f"agent-root-exec: Cannot connect to daemon at {sock_path}: {e}")

    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "exec",
        "params": {
            "command": command,
            "timeout_seconds": timeout,
            "workdir": workdir,
            "env": env,
        },
    }
    sock.sendall((json.dumps(request) + "\n").encode())

    data = b""
    try:
        while b"\n" not in data:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        sock.close()

    if not data:
        sys.exit("agent-root-exec: Daemon closed connection unexpectedly.")
    return json.loads(data.decode().strip())


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="agent-root-exec",
        description="Execute a command via the privileged runner daemon",
    )
    parser.add_argument("command", nargs="+", help="Command to execute (joined with spaces)")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds (default: 60)")
    parser.add_argument("--workdir", default="/", help="Working directory (default: /)")
    parser.add_argument("--socket", default=None, help="Override socket path")
    parser.add_argument("--env", action="append", default=[], help="Extra env vars KEY=VALUE")

    args = parser.parse_args()

    command_str = " ".join(args.command)
    env = {}
    for e in args.env:
        if "=" in e:
            k, v = e.split("=", 1)
            env[k] = v

    sock_path = resolve_socket_path(args.socket)
    resp = send_exec(sock_path, command_str, args.timeout, args.workdir, env)

    if "error" in resp:
        err = resp["error"]
        code = err.get("code", -32603)
        reason = err.get("data", {}).get("reason", "")
        print(f"agent-root-exec: {err['message']}", file=sys.stderr)

        # Map error codes to exit codes
        if code == -32001:  # disarmed
            sys.exit(125)
        elif code == -32002:  # guardrail blocked
            sys.exit(126)
        elif code == -32003:  # permission denied
            sys.exit(1)
        elif code == -32004:  # timeout
            sys.exit(124)
        else:
            sys.exit(128)

    result = resp.get("result", {})
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    exit_code = result.get("exit_code", 0)

    if stdout:
        sys.stdout.write(stdout)
        if not stdout.endswith("\n"):
            sys.stdout.write("\n")
    if stderr:
        sys.stderr.write(stderr)
        if not stderr.endswith("\n"):
            sys.stderr.write("\n")

    sys.exit(exit_code if 0 <= exit_code <= 123 else 128)


if __name__ == "__main__":
    main()
