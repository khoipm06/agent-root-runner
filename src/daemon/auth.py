"""Kernel Peer Credential Extraction and Authentication Policies.

Part of Milestone 1 (M1) of Agent Root Runner.
Extracts SO_PEERCRED (struct ucred) from Unix domain socket connections,
inspects /proc for process attribution, and evaluates arming authorization.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
import socket
import struct
from typing import Optional, Tuple

SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)
UCRED_FORMAT = "iII"
UCRED_SIZE = struct.calcsize(UCRED_FORMAT)  # 12 bytes


@dataclass(frozen=True)
class PeerCredentials:
    """Immutable peer credentials verified by the Linux kernel."""
    pid: int
    uid: int
    gid: int
    comm: str = "[unknown]"
    cmdline: str = "[unknown]"


class AuthenticationError(Exception):
    """Raised when peer credential extraction fails."""
    pass


class AuthorizationError(Exception):
    """Raised when peer credentials violate policy rules."""
    def __init__(self, message: str, code: int = -32003, reason: str = "PERMISSION_DENIED"):
        super().__init__(message)
        self.code = code
        self.reason = reason


def get_process_info(pid: int) -> Tuple[str, str]:
    """Safely reads /proc/{pid}/comm and /proc/{pid}/cmdline.

    Returns:
        Tuple of (comm, cmdline). Falls back gracefully if the process has exited
        or procfs is restricted.
    """
    comm = "[unknown]"
    cmdline = "[unknown]"

    try:
        comm_path = f"/proc/{pid}/comm"
        if os.path.exists(comm_path):
            with open(comm_path, "r", encoding="utf-8", errors="replace") as f:
                comm = f.read().strip()
    except (OSError, ProcessLookupError, PermissionError):
        comm = "[exited]"

    try:
        cmdline_path = f"/proc/{pid}/cmdline"
        if os.path.exists(cmdline_path):
            with open(cmdline_path, "rb") as f:
                raw = f.read()
                cmdline = raw.decode("utf-8", errors="replace").replace("\x00", " ").strip()
    except (OSError, ProcessLookupError, PermissionError):
        cmdline = "[exited]"

    return comm, cmdline


def get_peer_credentials(sock: Any) -> PeerCredentials:
    """Extracts SO_PEERCRED from a Unix domain socket and enriches via /proc.

    Raises:
        AuthenticationError: If getsockopt fails or struct ucred unpacking fails.
    """
    if hasattr(sock, "_sock"):
        sock = getattr(sock, "_sock")

    if not isinstance(sock, socket.socket) and not hasattr(sock, "getsockopt"):
        raise AuthenticationError("Provided object is not a valid socket.")

    try:
        cred_bytes = sock.getsockopt(socket.SOL_SOCKET, SO_PEERCRED, UCRED_SIZE)
        if len(cred_bytes) < UCRED_SIZE:
            raise AuthenticationError(f"SO_PEERCRED returned {len(cred_bytes)} bytes, expected {UCRED_SIZE}")
        pid, uid, gid = struct.unpack(UCRED_FORMAT, cred_bytes[:UCRED_SIZE])
    except (OSError, struct.error) as exc:
        raise AuthenticationError(f"Failed to extract SO_PEERCRED: {exc}") from exc

    comm, cmdline = get_process_info(pid)
    return PeerCredentials(pid=pid, uid=uid, gid=gid, comm=comm, cmdline=cmdline)


# Function alias for architectural flexibility
extract_peer_credentials = get_peer_credentials


def is_arm_authorized(
    peer_uid: int,
    allow_user_arm: bool = False,
    socket_owner_uid: Optional[int] = None,
) -> bool:
    """Evaluates whether peer_uid is authorized to arm the runner.

    In production (allow_user_arm=False): strictly requires peer_uid == 0.

    In development/test mode (allow_user_arm=True): any local peer that can
    reach the socket is permitted, so a developer can arm the unprivileged
    daemon they are running. This mode is refused for a root daemon (see
    ``run_daemon_main``), so it can never grant a non-root user root arming.
    """
    if peer_uid == 0:
        return True
    if allow_user_arm and peer_uid >= 0:
        return True
    return False


def check_arm_permission(
    creds: PeerCredentials,
    allow_user_arm: bool = False,
    socket_owner_uid: Optional[int] = None,
) -> Tuple[bool, str]:
    """Evaluates arm permission and returns a status tuple (allowed, reason)."""
    if creds.uid == 0:
        return True, "Root credentials verified."
    if allow_user_arm and creds.uid >= 0:
        return True, "User arm permitted in development/test mode."
    return False, (
        f"Permission denied: Arming requires root privileges (peer_uid == 0, got {creds.uid}). "
        "Run 'sudo agent-root-runner arm' to enable."
    )


def check_disarm_permission(
    creds: PeerCredentials,
    allow_user_arm: bool = False,
) -> Tuple[bool, str]:
    """Emergency disarm is permitted by root or any authorized socket peer."""
    return True, "Disarm permitted."
