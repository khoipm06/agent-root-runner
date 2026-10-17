"""IPC Client and Subprocess Wrappers for Agent Root Runner Tests.

Provides:
- SocketRpcClient: Communicates over Unix domain socket using line-delimited JSON-RPC 2.0.
- CliRunner: Executes agent-root-runner and agent-root-exec CLI tools and captures outputs.
- McpTestClient: Stdio JSON-RPC 2.0 client to test MCP server tool integration.
"""

import json
import os
import socket
import subprocess
import time
from typing import Any, Dict, Optional, Tuple


class SocketRpcClient:
    """Unix Domain Socket JSON-RPC 2.0 client."""

    def __init__(self, socket_path: Optional[str] = None, timeout: float = 10.0):
        self.socket_path = socket_path or os.environ.get(
            "AGENT_ROOT_RUNNER_SOCKET", "/run/agent-root-runner/runner.sock"
        )
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    def connect(self) -> "SocketRpcClient":
        """Connect to the Unix domain socket with retries."""
        deadline = time.time() + self.timeout
        last_err = None
        while time.time() < deadline:
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(self.timeout)
                s.connect(self.socket_path)
                self.sock = s
                return self
            except (FileNotFoundError, ConnectionRefusedError, PermissionError) as exc:
                last_err = exc
                time.sleep(0.1)
        raise ConnectionError(
            f"Failed to connect to socket {self.socket_path} within {self.timeout}s: {last_err}"
        )

    def close(self) -> None:
        """Close socket connection."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    def __enter__(self) -> "SocketRpcClient":
        return self.connect()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def send_raw(self, payload: str, expect_response: bool = True) -> str:
        """Send raw string terminated by newline and read single-line response."""
        if not self.sock:
            self.connect()
        if not payload.endswith("\n"):
            payload += "\n"
        self.sock.sendall(payload.encode("utf-8"))

        if not expect_response:
            return ""

        buffer = bytearray()
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            buffer.extend(chunk)
            if b"\n" in chunk:
                break
        return buffer.decode("utf-8").strip()

    def request(
        self,
        method: str,
        params: Optional[Dict[str, Any]] = None,
        req_id: Any = 1,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        """Send JSON-RPC 2.0 request and return parsed response dictionary."""
        if timeout:
            self.sock.settimeout(timeout)

        req_obj: Dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if req_id is not None:
            req_obj["id"] = req_id
        if params is not None:
            req_obj["params"] = params

        raw_req = json.dumps(req_obj) + "\n"
        raw_resp = self.send_raw(raw_req)
        if not raw_resp:
            raise RuntimeError("Empty response received from daemon")
        return json.loads(raw_resp)

    def ping(self, req_id: int = 1) -> Dict[str, Any]:
        return self.request("ping", params={}, req_id=req_id)

    def status(self, req_id: int = 1) -> Dict[str, Any]:
        return self.request("status", params={}, req_id=req_id)

    def arm(
        self,
        duration_seconds: int = 900,
        quota: Optional[int] = None,
        req_id: int = 1,
    ) -> Dict[str, Any]:
        params = {"duration_seconds": duration_seconds, "quota": quota}
        return self.request("arm", params=params, req_id=req_id)

    def disarm(self, req_id: int = 1) -> Dict[str, Any]:
        return self.request("disarm", params={}, req_id=req_id)

    def exec_cmd(
        self,
        command: str,
        timeout_seconds: int = 60,
        workdir: str = "/",
        env: Optional[Dict[str, str]] = None,
        req_id: int = 1,
    ) -> Dict[str, Any]:
        params = {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "workdir": workdir,
            "env": env or {},
        }
        return self.request("exec", params=params, req_id=req_id)


class CliRunner:
    """Wrapper to run agent-root-runner and agent-root-exec CLI commands."""

    def __init__(self, project_root: Optional[str] = None, socket_path: Optional[str] = None):
        self.project_root = project_root or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        self.socket_path = socket_path or os.environ.get("AGENT_ROOT_RUNNER_SOCKET")

    def _get_env(self, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        env = os.environ.copy()
        if self.socket_path:
            env["AGENT_ROOT_RUNNER_SOCKET"] = self.socket_path
        if custom_env:
            env.update(custom_env)
        return env

    def run_exec(
        self,
        cmd_args: list[str],
        timeout: float = 30.0,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Invoke agent-root-exec <cmd_args>."""
        binary = os.path.join(self.project_root, "bin", "agent-root-exec")
        if not os.path.exists(binary) or not os.access(binary, os.X_OK):
            # Fallback to python runner if bin is not yet created or compiled
            binary_cmd = [
                "python3",
                "-m",
                "src.cli.exec_cli",
                *cmd_args,
            ]
        else:
            binary_cmd = [binary, *cmd_args]

        proc = subprocess.run(
            binary_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=self._get_env(custom_env),
            cwd=self.project_root,
        )
        return proc.returncode, proc.stdout, proc.stderr

    def run_runner(
        self,
        args: list[str],
        timeout: float = 30.0,
        custom_env: Optional[Dict[str, str]] = None,
    ) -> Tuple[int, str, str]:
        """Invoke agent-root-runner <args>."""
        binary = os.path.join(self.project_root, "bin", "agent-root-runner")
        if not os.path.exists(binary) or not os.access(binary, os.X_OK):
            binary_cmd = [
                "python3",
                "-m",
                "src.cli.runner_cli",
                *args,
            ]
        else:
            binary_cmd = [binary, *args]

        proc = subprocess.run(
            binary_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=self._get_env(custom_env),
            cwd=self.project_root,
        )
        return proc.returncode, proc.stdout, proc.stderr


class McpTestClient:
    """Stdio JSON-RPC 2.0 client for Agent Root Runner MCP server."""

    def __init__(self, project_root: Optional[str] = None, socket_path: Optional[str] = None):
        self.project_root = project_root or os.path.abspath(
            os.path.join(os.path.dirname(__file__), "..", "..")
        )
        self.socket_path = socket_path or os.environ.get("AGENT_ROOT_RUNNER_SOCKET")
        self.proc: Optional[subprocess.Popen] = None

    def start(self) -> "McpTestClient":
        binary = os.path.join(self.project_root, "bin", "agent-root-mcp")
        if not os.path.exists(binary) or not os.access(binary, os.X_OK):
            cmd = ["python3", "-m", "src.mcp.server"]
        else:
            cmd = [binary]

        env = os.environ.copy()
        if self.socket_path:
            env["AGENT_ROOT_RUNNER_SOCKET"] = self.socket_path

        self.proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
            cwd=self.project_root,
        )
        return self

    def stop(self) -> None:
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None

    def __enter__(self) -> "McpTestClient":
        return self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def send_request(self, method: str, params: Optional[Dict[str, Any]] = None, req_id: int = 1) -> Dict[str, Any]:
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("MCP process is not running")

        payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params

        self.proc.stdin.write(json.dumps(payload) + "\n")
        self.proc.stdin.flush()

        resp_line = self.proc.stdout.readline()
        if not resp_line:
            stderr_out = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError(f"MCP server closed stdout unexpectedly. Stderr: {stderr_out}")
        return json.loads(resp_line.strip())

    def initialize(self) -> Dict[str, Any]:
        return self.send_request(
            "initialize",
            params={
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "test-client", "version": "1.0.0"},
            },
            req_id=1,
        )

    def list_tools(self, req_id: int = 2) -> Dict[str, Any]:
        return self.send_request("tools/list", params={}, req_id=req_id)

    def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        req_id: int = 3,
    ) -> Dict[str, Any]:
        return self.send_request(
            "tools/call",
            params={"name": name, "arguments": arguments},
            req_id=req_id,
        )
