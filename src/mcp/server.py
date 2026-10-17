#!/usr/bin/env python3
"""
agent-root-mcp — Zero-dependency stdio JSON-RPC 2.0 MCP Server.

Exposes `run_privileged_command` tool compatible with Antigravity, OpenCode, and Pi.
"""

import json
import os
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
try:
    from src.daemon.server import resolve_socket_path
except ImportError:
    from daemon.server import resolve_socket_path


class MCPServer:
    """Minimal stdio JSON-RPC 2.0 MCP server."""

    def __init__(self, sock_path: str):
        self.sock_path = sock_path
        self.request_id = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        with self._lock:
            self.request_id += 1
            return self.request_id

    def _send_response(self, resp: dict):
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

    def _send_error(self, req_id, code: int, message: str, data: dict = None):
        err = {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}
        if data:
            err["error"]["data"] = data
        self._send_response(err)

    def _send_result(self, req_id, result: dict):
        self._send_response({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _call_daemon(self, method: str, params: dict, timeout: int = 70) -> dict:
        """Forward request to daemon and return response."""
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(self.sock_path)
        except (ConnectionRefusedError, FileNotFoundError) as e:
            raise RuntimeError(f"Daemon connection failed: {e}")

        req = {"jsonrpc": "2.0", "id": self._next_id(), "method": method, "params": params}
        sock.sendall((json.dumps(req) + "\n").encode())

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
            raise RuntimeError("Daemon closed connection unexpectedly")
        return json.loads(data.decode().strip())

    def handle_initialize(self, req_id, params: dict):
        """Handle MCP initialize request."""
        self._send_result(req_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agent-root-mcp", "version": "1.0.0"},
        })

    def handle_tools_list(self, req_id, params: dict):
        """Return available tools."""
        self._send_result(req_id, {
            "tools": [{
                "name": "run_privileged_command",
                "description": "Execute a shell command with root privileges via the agent-root-runner daemon. Requires the daemon to be armed (sudo agent-root-runner arm).",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {
                            "type": "string",
                            "description": "Shell command to execute (e.g., 'smartctl -a /dev/nvme0n1', 'systemctl restart nginx')"
                        },
                        "timeout": {
                            "type": "integer",
                            "description": "Command timeout in seconds (default: 60)",
                            "default": 60,
                            "minimum": 1,
                            "maximum": 3600
                        },
                        "workdir": {
                            "type": "string",
                            "description": "Working directory (default: /)",
                            "default": "/"
                        },
                        "env": {
                            "type": "object",
                            "description": "Additional environment variables",
                            "additionalProperties": {"type": "string"}
                        }
                    },
                    "required": ["command"]
                }
            }]
        })

    def handle_tools_call(self, req_id, params: dict):
        """Execute run_privileged_command tool."""
        name = params.get("name")
        if name != "run_privileged_command":
            self._send_error(req_id, -32601, f"Unknown tool: {name}")
            return

        args = params.get("arguments", {})
        command = args.get("command")
        timeout = args.get("timeout", 60)
        workdir = args.get("workdir", "/")
        env = args.get("env", {})

        if not command:
            self._send_error(req_id, -32602, "Missing required argument: command")
            return

        try:
            resp = self._call_daemon("exec", {
                "command": command,
                "timeout_seconds": timeout,
                "workdir": workdir,
                "env": env,
            }, timeout=timeout + 10)
        except RuntimeError as e:
            self._send_error(req_id, -32000, str(e), {"reason": "DAEMON_ERROR"})
            return

        if "error" in resp:
            err = resp["error"]
            code = err.get("code", -32603)
            reason = err.get("data", {}).get("reason", "")
            # Daemon exec failures (-32001..-32004) surfaced as tool results, not
            # top-level JSON-RPC errors; kept top-level only for protocol failures.
            if -32004 <= code <= -32001:
                text = err.get("message", "") or reason
                self._send_result(req_id, {
                    "content": [{"type": "text", "text": text}],
                    "isError": True,
                    "meta": {"daemon_code": code, "reason": reason,
                             "stderr": err.get("data", {}).get("stderr", "")},
                })
                return
            self._send_error(req_id, code, err["message"], {"reason": reason})
            return

        result = resp.get("result", {})
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_code = result.get("exit_code", 0)

        text = stdout
        if exit_code != 0:
            text = (stdout + "\n" + stderr).strip() if stdout else stderr
        self._send_result(req_id, {
            "content": [{"type": "text", "text": text or ""}],
            "isError": exit_code != 0,
            "meta": {
                "exit_code": exit_code,
                "stderr": stderr,
                "duration_ms": result.get("duration_ms"),
            }
        })

    def handle_request(self, line: str):
        """Dispatch a single JSON-RPC request."""
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            self._send_error(None, -32700, "Parse error")
            return

        req_id = req.get("id")
        method = req.get("method")
        params = req.get("params", {})

        if method == "initialize":
            self.handle_initialize(req_id, params)
        elif method == "tools/list":
            self.handle_tools_list(req_id, params)
        elif method == "tools/call":
            self.handle_tools_call(req_id, params)
        elif method == "ping":
            self._send_result(req_id, {"pong": True})
        else:
            self._send_error(req_id, -32601, f"Method not found: {method}")

    def run(self):
        """Main loop: read lines from stdin, dispatch requests. EOF exits cleanly."""
        try:
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                self.handle_request(line)
        except (KeyboardInterrupt, BrokenPipeError):
            pass


def main():
    import argparse

    parser = argparse.ArgumentParser(
        prog="agent-root-mcp",
        description="MCP server exposing run_privileged_command tool",
    )
    parser.add_argument("--socket", default=None, help="Override socket path")
    args = parser.parse_args()

    sock_path = resolve_socket_path(args.socket)
    server = MCPServer(sock_path)
    server.run()


if __name__ == "__main__":
    main()
