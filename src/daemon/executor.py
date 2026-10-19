"""Asynchronous Subprocess Execution Engine.

Part of Milestone 1 (M1) of Agent Root Runner.
Provides session isolation, process-group termination, stream buffer capping,
anti-deadlock drainage, and environment sanitization.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import os
import re
import resource
import signal
import subprocess
import time
from typing import Any, Dict, Optional, Tuple

# Configuration Constants
DEFAULT_TIMEOUT_SECONDS: int = 60
DEFAULT_MAX_OUTPUT_BYTES: int = 10 * 1024 * 1024  # 10 MB per stream
CHUNK_READ_SIZE: int = 65536  # 64 KB (matches kernel pipe buffer)
DEFAULT_DRAIN_TIMEOUT_SECONDS: float = 2.0

# Immutable Baseline Environment
CLEAN_ENV_BASE: Dict[str, str] = {
    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "USER": "root",
    "HOME": "/root",
    "SHELL": "/bin/bash",
    "TERM": "xterm-256color",
}

# Blocked Environment Variable Prefixes
BLOCKED_ENV_PREFIXES: Tuple[str, ...] = (
    "LD_",
    "PYTHON",
    "PERL",
    "RUBY",
    "NODE_",
    "LUA_",
    "BASH_FUNC_",
)

# Blocked Environment Variable Exact Names
BLOCKED_ENV_EXACT: frozenset[str] = frozenset({
    "PATH",
    "SHELL",
    "BASH_ENV",
    "ENV",
    "SHELLOPTS",
    "BASHOPTS",
    "IFS",
    "PROMPT_COMMAND",
    "GLOBIGNORE",
    "SUDO_COMMAND",
    "SUDO_USER",
    "SUDO_UID",
    "SUDO_GID",
    "KRB5_CONFIG",
    "KRB5CCNAME",
    "RESOLV_CONF",
    "HOME",
    "USER",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCALDOMAIN",
})

VAR_NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


class ExecutorError(Exception):
    """Base exception for executor errors."""
    pass


class InvalidEnvironmentError(ExecutorError):
    """Raised when environment variables violate security constraints."""
    pass


class InvalidWorkdirError(ExecutorError):
    """Raised when working directory is invalid or inaccessible."""
    pass


@dataclass(frozen=True)
class ExecutionResult:
    """Immutable result of a subprocess execution with dict compatibility."""
    exit_code: int
    stdout: str
    stderr: str
    duration_ms: float
    timed_out: bool = False
    truncated: bool = False

    def __getitem__(self, item: str) -> Any:
        return getattr(self, item)

    def get(self, item: str, default: Any = None) -> Any:
        return getattr(self, item, default)

    def to_dict(self) -> dict[str, Any]:
        return {
            "exit_code": self.exit_code,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration_ms": self.duration_ms,
            "timed_out": self.timed_out,
            "truncated": self.truncated,
        }


def _child_preexec_fn() -> None:
    """Pre-exec hook executed in child process after fork.
    
    Applies defense-in-depth resource limits against fork bombs, DoS,
    CPU hogging, file size exhaustion, and fd leaks.
    """
    # 1. RLIMIT_CORE: 0 (prevent core dump file leaks and disk fill)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ValueError, OSError):
        pass

    # 2. RLIMIT_NOFILE: 1024
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (1024, 1024))
    except (ValueError, OSError):
        pass

    # 3. RLIMIT_NPROC: 256. NOTE: the kernel does not enforce RLIMIT_NPROC for
    #    processes holding CAP_SYS_RESOURCE (root has it), so for the root daemon
    #    this is not an effective fork-bomb defense; it is kept as best-effort
    #    hardening for unprivileged (dev/user-mode) execution.
    try:
        if os.geteuid() == 0:
            resource.setrlimit(resource.RLIMIT_NPROC, (256, 256))
    except (ValueError, OSError):
        pass

    # 4. RLIMIT_CPU: soft 60s, hard 120s
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (60, 120))
    except (ValueError, OSError):
        pass

    # 5. RLIMIT_FSIZE: 500 MB max single file write
    try:
        max_fsize = 500 * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (max_fsize, max_fsize))
    except (ValueError, OSError):
        pass



class SubprocessExecutor:
    """Asynchronous subprocess executor with process-group isolation and stream capping."""

    def __init__(
        self,
        default_timeout: int = DEFAULT_TIMEOUT_SECONDS,
        max_output_bytes: int = DEFAULT_MAX_OUTPUT_BYTES,
        max_concurrency: int = 1,
        is_user_mode: bool = False,
        drain_timeout: float = DEFAULT_DRAIN_TIMEOUT_SECONDS,
    ) -> None:
        self.default_timeout = default_timeout
        self.max_output_bytes = max_output_bytes
        self.is_user_mode = is_user_mode
        self.drain_timeout = drain_timeout
        self._semaphore = asyncio.Semaphore(max_concurrency)
        self._current_pgid: Optional[int] = None

    def terminate_current(self) -> None:
        """SIGKILL the process group of the in-flight command, if any.

        Wired to the state machine's disarm hook so a privileged command cannot
        outlive its authorization window.
        """
        pgid = self._current_pgid
        if pgid is None:
            return
        try:
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, OSError):
            pass

    def sanitize_environment(
        self,
        caller_env: Optional[Dict[str, str]] = None,
    ) -> Dict[str, str]:
        """Produces a pristine execution environment merged with validated caller variables."""
        env = dict(CLEAN_ENV_BASE)

        if self.is_user_mode or os.geteuid() != 0:
            env["USER"] = os.environ.get("USER", "runner")
            env["HOME"] = os.environ.get("HOME", "/tmp")

        if not caller_env:
            return env

        for key, val in caller_env.items():
            if not isinstance(key, str) or not isinstance(val, str):
                raise InvalidEnvironmentError(f"Environment key and value must be strings: {key!r}")

            if not VAR_NAME_PATTERN.match(key):
                raise InvalidEnvironmentError(f"Malformed environment variable name: {key!r}")

            if "\x00" in key or "\x00" in val:
                raise InvalidEnvironmentError(f"Null bytes forbidden in environment: {key!r}")

            if key in BLOCKED_ENV_EXACT or any(key.startswith(p) for p in BLOCKED_ENV_PREFIXES):
                raise InvalidEnvironmentError(
                    f"Prohibited environment variable injection detected: {key}"
                )

            env[key] = val

        return env

    def validate_workdir(self, workdir: Optional[str]) -> str:
        """Validates and resolves the target working directory."""
        if not workdir:
            return "/tmp" if (self.is_user_mode or os.geteuid() != 0) else "/root"

        if "\x00" in workdir:
            raise InvalidWorkdirError("Null bytes forbidden in workdir path.")

        resolved = os.path.realpath(workdir)
        if not os.path.exists(resolved):
            raise InvalidWorkdirError(f"Working directory does not exist: {workdir}")
        if not os.path.isdir(resolved):
            raise InvalidWorkdirError(f"Working directory is not a directory: {workdir}")

        return resolved

    async def _read_stream_capped(
        self,
        stream: Optional[asyncio.StreamReader],
        max_bytes: int,
    ) -> Tuple[bytes, bool]:
        """Reads stream in chunks up to max_bytes.
        
        Continues reading and discarding beyond max_bytes to prevent
        the child process from blocking on full OS pipe buffers.
        """
        if stream is None:
            return b"", False

        chunks: list[bytes] = []
        captured_bytes: int = 0
        truncated: bool = False

        try:
            while True:
                chunk = await stream.read(CHUNK_READ_SIZE)
                if not chunk:
                    break

                if captured_bytes < max_bytes:
                    allow = min(len(chunk), max_bytes - captured_bytes)
                    chunks.append(chunk[:allow])
                    captured_bytes += allow
                    if len(chunk) > allow:
                        truncated = True
                else:
                    truncated = True
        except (asyncio.CancelledError, ConnectionResetError, BrokenPipeError, OSError):
            # NOTE: swallowing CancelledError is intentional here: on drain
            # timeout the reader tasks are cancelled and their partial capture is
            # collected by the caller.
            pass

        return b"".join(chunks), truncated

    async def execute(
        self,
        command: str,
        timeout_seconds: Optional[int] = None,
        workdir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
    ) -> ExecutionResult:
        """Executes a shell command asynchronously inside a dedicated session and process group.

        Returns:
            ExecutionResult containing exit code, stdout, stderr, and execution duration.
        """
        if not command or not command.strip():
            return ExecutionResult(
                exit_code=2,
                stdout="",
                stderr="Error: Empty command string provided.",
                duration_ms=0.0,
            )

        if "\x00" in command:
            return ExecutionResult(
                exit_code=2,
                stdout="",
                stderr="Error: Command contains embedded null bytes.",
                duration_ms=0.0,
            )

        clean_env = self.sanitize_environment(env)
        target_dir = self.validate_workdir(workdir)
        timeout = float(timeout_seconds if timeout_seconds is not None else self.default_timeout)

        async with self._semaphore:
            start_time = time.monotonic()

            proc = await asyncio.create_subprocess_exec(
                "/bin/bash",
                "-c",
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=target_dir,
                env=clean_env,
                start_new_session=True,  # setsid() -> New PGID
                preexec_fn=_child_preexec_fn,
            )
            self._current_pgid = proc.pid

            # Concurrent readers to prevent pipe buffer deadlocks
            stdout_task = asyncio.create_task(
                self._read_stream_capped(proc.stdout, self.max_output_bytes)
            )
            stderr_task = asyncio.create_task(
                self._read_stream_capped(proc.stderr, self.max_output_bytes)
            )

            timed_out = False

            try:
                try:
                    await asyncio.wait_for(proc.wait(), timeout=timeout)
                except asyncio.TimeoutError:
                    timed_out = True
                    # Atomic process group termination
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass

                    # Reap child zombie
                    try:
                        await proc.wait()
                    except Exception:
                        pass

                # Await drain of remaining data from streams
                try:
                    (stdout_raw, out_trunc), (stderr_raw, err_trunc) = await asyncio.wait_for(
                        asyncio.gather(stdout_task, stderr_task), timeout=self.drain_timeout
                    )
                except asyncio.TimeoutError:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except (ProcessLookupError, OSError):
                        pass

                    stdout_task.cancel()
                    stderr_task.cancel()
                    stream_res = await asyncio.gather(
                        stdout_task, stderr_task, return_exceptions=True
                    )
                    stdout_res = stream_res[0]
                    stderr_res = stream_res[1]
                    stdout_raw, out_trunc = (
                        stdout_res if isinstance(stdout_res, tuple) else (b"", False)
                    )
                    stderr_raw, err_trunc = (
                        stderr_res if isinstance(stderr_res, tuple) else (b"", False)
                    )
            finally:
                # Ensure post-execution cleanup terminates all remaining processes in the
                # process group via os.killpg(proc.pid, signal.SIGKILL) to prevent detached
                # children (e.g. sleep 42 &) from leaking into the system.
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, OSError):
                    pass
                try:
                    if proc.returncode is None:
                        await proc.wait()
                except Exception:
                    pass
                self._current_pgid = None

            duration_ms = round((time.monotonic() - start_time) * 1000, 2)

            stdout_str = stdout_raw.decode("utf-8", errors="replace")
            stderr_str = stderr_raw.decode("utf-8", errors="replace")

            if out_trunc:
                stdout_str += f"\n[... stdout truncated at {self.max_output_bytes // (1024 * 1024)}MB limit ...]\n"
            if err_trunc:
                stderr_str += f"\n[... stderr truncated at {self.max_output_bytes // (1024 * 1024)}MB limit ...]\n"

            if timed_out:
                exit_code = 124
                timeout_msg = f"Command execution timed out after {timeout} seconds.\n"
                stderr_str = timeout_msg + stderr_str
            elif proc.returncode is not None:
                if proc.returncode < 0:
                    sig_num = abs(proc.returncode)
                    exit_code = 128 + sig_num
                    if sig_num == signal.SIGXFSZ:
                        stderr_str = "Error: File size limit exceeded (RLIMIT_FSIZE violated).\n" + stderr_str
                    elif sig_num == signal.SIGXCPU:
                        stderr_str = "Error: CPU time limit exceeded (RLIMIT_CPU violated).\n" + stderr_str
                else:
                    exit_code = proc.returncode
            else:
                exit_code = 1

            return ExecutionResult(
                exit_code=exit_code,
                stdout=stdout_str,
                stderr=stderr_str,
                duration_ms=duration_ms,
                timed_out=timed_out,
                truncated=out_trunc or err_trunc,
            )
