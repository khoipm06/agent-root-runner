"""Guardrail against destructive package-state operations.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects the host package database and critical packages (systemd, glibc,
kernel*, openssh*, python3*) from removal, downgrade, and rpmdb rebuilds that
could brick the machine or the tool. Read-only queries (dnf list, rpm -q,
apt list) stay allowed to avoid false positives.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

DOMAIN = "package_state"
RULE_PACKAGE_STATE_DESTRUCTION = "RULE_PACKAGE_STATE_DESTRUCTION"

_PROTECTED_EXACT_RE = re.compile(
    r"^(?:systemd|glibc|dnf|rpm|bash|coreutils|sudo|filesystem)(?:-\d.*)?$"
)
_PROTECTED_PREFIXES = ("kernel", "openssh", "python3")
_NON_PACKAGE_ARGS = {"remove", "purge", "erase", "autoremove"}


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _is_protected(pkg: str) -> bool:
    """True when a package name is a protected exact name or prefix family."""
    return bool(_PROTECTED_EXACT_RE.match(pkg)) or pkg.startswith(_PROTECTED_PREFIXES)


def check_package_state(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Blocks destructive package removal, rpmdb rebuilds, and release downgrades."""
    exe = os.path.basename(cmd.executable)
    args = cmd.args

    if exe == "rpm" and "--rebuilddb" in args:
        return (
            DOMAIN,
            RULE_PACKAGE_STATE_DESTRUCTION,
            "Blocked: rpm --rebuilddb rebuilds the package database.",
        )

    if exe == "rpm" and ("-e" in args or "--erase" in args) and "--nodeps" in args:
        return (
            DOMAIN,
            RULE_PACKAGE_STATE_DESTRUCTION,
            "Blocked: rpm erase with --nodeps breaks dependency integrity.",
        )

    if (
        exe in {"dnf", "yum"}
        and "downgrade" in args
        and any(a.startswith("--releasever") for a in args)
    ):
        return (
            DOMAIN,
            RULE_PACKAGE_STATE_DESTRUCTION,
            "Blocked: dnf/yum downgrade across releasever.",
        )

    removal = (
        (exe in {"dnf", "yum"} and "remove" in args)
        or (exe == "rpm" and ("-e" in args or "--erase" in args))
        or (exe in {"apt", "apt-get"} and ("remove" in args or "purge" in args))
    )
    if removal:
        for arg in args:
            if arg.startswith("-") or arg in _NON_PACKAGE_ARGS:
                continue
            if _is_protected(arg):
                return (
                    DOMAIN,
                    RULE_PACKAGE_STATE_DESTRUCTION,
                    f"Blocked: removal of protected package '{arg}'.",
                )
    return None
