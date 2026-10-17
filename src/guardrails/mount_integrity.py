"""Mount And Namespace Integrity Defense.

Part of Milestone 4 (M4) of Agent Root Runner.
Blocks remount/umount of critical mounts, bind mounts shadowing system paths,
and tmpfs overlays on /etc /usr /var. Avoids false positives on read-only
queries (mount list, df, findmnt) and mounts of non-critical paths.
"""

from __future__ import annotations

import os
from typing import List, Optional, Tuple

from src.guardrails.parser import ParsedCommand

RULE_MOUNT_INTEGRITY = "RULE_MOUNT_INTEGRITY"

CRITICAL_TARGETS = {
    "/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var",
    "/boot", "/opt", "/sysroot", "/home", "/root",
}


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _last_non_flag(args: List[str]) -> Optional[str]:
    """Returns the last argument that is not a flag, or None if all flags."""
    for arg in reversed(args):
        if not arg.startswith("-"):
            return arg
    return None


def check_mount_integrity(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates mount/umount commands against mount integrity rules."""
    try:
        exe = os.path.basename(cmd.executable or "")
        args = list(cmd.args or [])
        if exe == "mount":
            target = _last_non_flag(args)
            if target is None:
                return None
            target_norm = _norm(target)
            if target_norm not in CRITICAL_TARGETS:
                return None
            return (
                "mount_integrity",
                RULE_MOUNT_INTEGRITY,
                f"Mount targeting critical path {target_norm!r} blocked",
            )
        elif exe == "umount":
            for arg in args:
                if arg.startswith("-"):
                    continue
                arg_norm = _norm(arg)
                if arg_norm in CRITICAL_TARGETS:
                    return (
                        "mount_integrity",
                        RULE_MOUNT_INTEGRITY,
                        f"Unmount of critical mount {arg_norm!r} blocked",
                    )
    except Exception:
        return None
    return None
