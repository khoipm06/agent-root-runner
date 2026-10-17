"""Critical Authentication & Access Files Defense.

Part of Milestone 2 (M2) of Agent Root Runner.
Protects /etc/pam.d/*, /etc/sudoers*, /etc/shadow, /etc/passwd,
and SSH authorized_keys from mutations (rm, mv, sed -i, truncate, chmod, chown, shred, find).
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

PROTECTED_AUTH_PATHS: Tuple[str, ...] = (
    "/etc/pam.d",
    "/etc/pam.conf",
    "/etc/security",
    "/etc/sudoers",
    "/etc/shadow",
    "/etc/passwd",
    "/etc/group",
    "/etc/gshadow",
    "/root/.ssh",
    ".ssh/authorized_keys",
    "/etc/ssh/sshd_config",
)

CRITICAL_AUTH_BASENAMES: frozenset[str] = frozenset({
    "shadow",
    "gshadow",
    "sudoers",
    "passwd",
    "group",
    "pam.conf",
    "authorized_keys",
    "sshd_config",
})

MUTATING_OPERATIONS: frozenset[str] = frozenset({
    "rm",
    "unlink",
    "truncate",
    "chmod",
    "chown",
    "chgrp",
    "mv",
    "cp",
    "install",
    "tee",
    "touch",
    "shred",
})


def matches_protected_auth(path_str: str) -> Optional[str]:
    """Checks if a path references a protected authentication asset."""
    norm = os.path.normpath(path_str)
    if ".ssh/authorized_keys" in norm or norm.endswith("authorized_keys"):
        return "~/.ssh/authorized_keys"

    base = os.path.basename(norm)
    if norm in CRITICAL_AUTH_BASENAMES or base in CRITICAL_AUTH_BASENAMES:
        if norm in CRITICAL_AUTH_BASENAMES or norm.startswith("etc/") or norm.startswith("/etc/"):
            return f"/etc/{base}"

    if norm == "pam.d" or norm.startswith("pam.d/") or norm.startswith("etc/pam.d"):
        return "/etc/pam.d"

    if norm == "sudoers.d" or norm.startswith("sudoers.d/") or norm.startswith("etc/sudoers.d"):
        return "/etc/sudoers.d"

    for p in PROTECTED_AUTH_PATHS:
        if (
            norm == p
            or norm.startswith(p + "/")
            or norm.endswith("/" + os.path.basename(p))
            or p in norm
            or norm == os.path.basename(p)
        ):
            return p

    return None


def check_auth_files_safety(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against authentication and access file protection rules."""
    # 1. Redirection writes to protected auth files (> /etc/sudoers)
    for r in cmd.redirections:
        asset = matches_protected_auth(r.target)
        if asset:
            return (
                "auth",
                "RULE_AUTH_FILE_MUTATION",
                f"Modification of critical authentication asset {asset} blocked",
            )

    # 2. Mutating commands (rm, chmod, chown, mv, cp, truncate, shred)
    if cmd.executable in MUTATING_OPERATIONS:
        for arg in cmd.args:
            if not arg.startswith("-"):
                asset = matches_protected_auth(arg)
                if asset:
                    return (
                        "auth",
                        "RULE_AUTH_FILE_MUTATION",
                        f"Modification of critical authentication asset {asset} blocked",
                    )

    # 3. Find commands with -delete or -exec
    if cmd.executable == "find":
        if any(a in cmd.args for a in ("-delete", "-exec", "-execdir")):
            for a in cmd.args:
                if not a.startswith("-"):
                    asset = matches_protected_auth(a)
                    if asset:
                        return (
                            "auth",
                            "RULE_AUTH_FILE_MUTATION",
                            f"Destructive find command targeting critical authentication asset {asset} blocked",
                        )

    # 4. In-place stream modification (sed -i, perl -i)
    if cmd.executable == "sed" and any(
        a.startswith("-i") or a == "--in-place" for a in cmd.args
    ):
        for arg in cmd.args:
            if not arg.startswith("-"):
                asset = matches_protected_auth(arg)
                if asset:
                    return (
                        "auth",
                        "RULE_AUTH_FILE_MUTATION",
                        f"Modification of critical authentication asset {asset} blocked",
                    )

    if cmd.executable in ("perl", "python", "python3") and "-i" in cmd.args:
        for arg in cmd.args:
            if not arg.startswith("-"):
                asset = matches_protected_auth(arg)
                if asset:
                    return (
                        "auth",
                        "RULE_AUTH_FILE_MUTATION",
                        f"Modification of critical authentication asset {asset} blocked",
                    )

    # 5. Critical account tampering (passwd -d root, userdel root, usermod -L root)
    if cmd.executable == "passwd" and "-d" in cmd.args:
        return (
            "auth",
            "RULE_AUTH_FILE_MUTATION",
            f"Account password deletion blocked: {cmd.raw_str}",
        )
    if cmd.executable in ("userdel",) and "root" in cmd.args:
        return (
            "auth",
            "RULE_AUTH_FILE_MUTATION",
            f"Root account deletion blocked: {cmd.raw_str}",
        )
    if cmd.executable in ("usermod",) and "-L" in cmd.args and "root" in cmd.args:
        return (
            "auth",
            "RULE_AUTH_FILE_MUTATION",
            f"Root account locking blocked: {cmd.raw_str}",
        )

    return None
