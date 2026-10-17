"""High-Integrity Append-Only Structured NDJSON Audit Logger.

Part of Milestone 1 (M1) of Agent Root Runner.
Provides secure audit logging with file permissions 0600, append-only mode,
synchronous os.fdatasync durability, and non-blocking event loop dispatch.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
from typing import Any, Dict, Optional
import uuid

PROD_AUDIT_LOG_PATH = "/var/log/agent-root-runner/audit.log"
ENV_AUDIT_LOG_OVERRIDE = "AGENT_ROOT_RUNNER_AUDIT_LOG"


class AuditLogger:
    """Thread-safe, event-loop non-blocking NDJSON audit logger."""

    def __init__(
        self,
        log_path: Optional[str] = None,
        force_user_mode: bool = False,
    ) -> None:
        self.log_path = self._resolve_log_path(log_path, force_user_mode)
        self._fd: Optional[int] = None
        self._lock = asyncio.Lock()
        self._ensure_file_open()

    def _resolve_log_path(self, custom_path: Optional[str], force_user_mode: bool) -> str:
        # 1. Environment variable override
        env_path = os.environ.get(ENV_AUDIT_LOG_OVERRIDE)
        if env_path:
            return os.path.realpath(env_path)

        # 2. Explicit constructor parameter
        if custom_path:
            return os.path.realpath(custom_path)

        # 3. Production mode if root
        if not force_user_mode and os.geteuid() == 0:
            return PROD_AUDIT_LOG_PATH

        # 4. User mode fallback
        state_home = os.environ.get("XDG_STATE_HOME")
        if state_home:
            fallback_dir = Path(state_home) / "agent-root-runner"
        else:
            fallback_dir = Path.home() / ".local" / "state" / "agent-root-runner"

        try:
            fallback_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            return str(fallback_dir / "audit.log")
        except OSError:
            tmp_dir = Path("/tmp/agent-root-runner")
            tmp_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            return str(tmp_dir / "audit.log")

    def _ensure_file_open(self) -> None:
        if self._fd is not None:
            return

        parent_dir = os.path.dirname(self.log_path)
        if parent_dir:
            try:
                os.makedirs(parent_dir, mode=0o700, exist_ok=True)
            except PermissionError:
                # If cannot create /var/log/..., fall back to /tmp
                tmp_dir = "/tmp/agent-root-runner"
                os.makedirs(tmp_dir, mode=0o700, exist_ok=True)
                self.log_path = os.path.join(tmp_dir, "audit.log")

        flags = os.O_CREAT | os.O_APPEND | os.O_WRONLY
        self._fd = os.open(self.log_path, flags, 0o600)

        # Guarantee mode 0600
        try:
            st = os.fstat(self._fd)
            if stat.S_IMODE(st.st_mode) != 0o600:
                os.fchmod(self._fd, 0o600)
        except OSError:
            pass

    def _sync_write_entry(self, entry_bytes: bytes) -> None:
        """Synchronously writes entry and calls os.fdatasync in worker thread."""
        if self._fd is None:
            self._ensure_file_open()
        assert self._fd is not None

        os.write(self._fd, entry_bytes)
        os.fdatasync(self._fd)

    async def log_event(
        self,
        event_type: str,
        peer_pid: Optional[int] = None,
        peer_uid: Optional[int] = None,
        peer_gid: Optional[int] = None,
        peer_comm: Optional[str] = None,
        command: Optional[str] = None,
        decision: Optional[str] = None,
        exit_code: Optional[int] = None,
        duration_ms: Optional[float] = None,
        reason: Optional[str] = None,
        rule: Optional[str] = None,
        **extra: Any,
    ) -> None:
        """Writes a structured audit event to the log file with physical sync."""
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        pid_val = peer_pid if peer_pid is not None else os.getpid()
        uid_val = peer_uid if peer_uid is not None else os.geteuid()
        gid_val = peer_gid if peer_gid is not None else os.getegid()

        record: Dict[str, Any] = {
            "timestamp": now_utc,
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "event_type": event_type,
            # Top-level attribution fields
            "pid": pid_val,
            "peer_pid": pid_val,
            "uid": uid_val,
            "peer_uid": uid_val,
            "gid": gid_val,
            "peer_gid": gid_val,
            "comm": peer_comm or "[unknown]",
            "peer_comm": peer_comm or "[unknown]",
        }

        if command is not None:
            record["command"] = command
        if decision is not None:
            record["decision"] = decision
        if reason is not None:
            record["reason"] = reason
        if rule is not None:
            record["rule"] = rule
        if exit_code is not None:
            record["exit_code"] = exit_code
        if duration_ms is not None:
            record["duration_ms"] = duration_ms

        # Merge any extra fields
        for k, v in extra.items():
            if k not in record and v is not None:
                record[k] = v

        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")

        async with self._lock:
            await asyncio.to_thread(self._sync_write_entry, line)

    def log(self, event_type: str, data: Optional[Dict[str, Any]] = None) -> None:
        """Synchronous logging helper compatible with simpler callers and protocols."""
        data = data or {}
        now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        pid_val = data.get("pid", data.get("peer_pid", data.get("caller_pid", os.getpid())))
        uid_val = data.get("uid", data.get("peer_uid", data.get("caller_uid", os.geteuid())))
        gid_val = data.get("gid", data.get("peer_gid", data.get("caller_gid", os.getegid())))
        comm_val = data.get("comm", data.get("peer_comm", "[unknown]"))

        record: Dict[str, Any] = {
            "timestamp": now_utc,
            "event_id": f"evt_{uuid.uuid4().hex[:12]}",
            "event_type": event_type,
            "pid": pid_val,
            "peer_pid": pid_val,
            "uid": uid_val,
            "peer_uid": uid_val,
            "gid": gid_val,
            "peer_gid": gid_val,
            "comm": comm_val,
            "peer_comm": comm_val,
        }

        for k, v in data.items():
            if k not in record:
                record[k] = v

        line = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        self._sync_write_entry(line)

    def close(self) -> None:
        """Closes open log file descriptor."""
        if self._fd is not None:
            try:
                os.close(self._fd)
            except OSError:
                pass
            self._fd = None
