"""Blocks destructive recursive permission changes and binary crippling.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects system directories from `chmod/chown/chgrp -R`, system binaries from
mode 000 / permission-stripping chmod, and critical flags via chattr +i/-i.
False positives: recursive changes inside user dirs (e.g. /home/user/project),
`chmod +x deploy.sh`, and normal chown/chmod on /tmp, /home stay allowed.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

RULE_RECURSIVE_PERM_CHANGE = "RULE_RECURSIVE_PERM_CHANGE"

CRITICAL = {
    "/usr", "/etc", "/var", "/boot", "/sysroot", "/opt", "/home", "/root",
    "/lib", "/lib64", "/bin", "/sbin", "/usr/lib", "/usr/bin", "/usr/sbin",
}

_BINARY_PATH_RE = re.compile(r"^/(usr/)?(bin|sbin|lib|lib64)/[^/]+$")
_CRIPPLE_MODE_RE = re.compile(r"[ugoa]*-[rwxXst]+")
_CHATTR_IMMUTABLE_RE = re.compile(r"^[+-][a-zA-Z]*i[a-zA-Z]*$")
_MODE_ARG_RE = re.compile(r"^[0-7]{3,4}$|^[ugoa]*[=+-][rwxXst]+$")
_OCTAL_MODE_RE = re.compile(r"^[0-7]{3,4}$")


def _mode_denies_exec(arg: str) -> bool:
    """True if a chmod mode argument grants no execute bits (e.g. 644, -x, =rw)."""
    if not _MODE_ARG_RE.fullmatch(arg):
        return False
    if _OCTAL_MODE_RE.fullmatch(arg):
        return not int(arg, 8) & 0o111
    return not ("x" in arg and not _CRIPPLE_MODE_RE.search(arg))


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _is_recursive_flag(arg: str) -> bool:
    """True for -R, --recursive, or combined short flags containing R."""
    if arg == "--recursive":
        return True
    if arg.startswith("-") and not arg.startswith("--"):
        return "R" in arg
    return False


def _norm_path_args(cmd: ParsedCommand) -> list:
    """Returns normalized absolute path args (args starting with '/')."""
    return [_norm(a) for a in cmd.args if a.startswith("/")]


def check_recursive_perm(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Blocks recursive chmod/chown/chgrp on critical dirs, binary crippling, chattr +i."""
    domain = "recursive_perm"

    if cmd.executable in ("chmod", "chown", "chgrp"):
        if any(_is_recursive_flag(a) for a in cmd.args):
            for path in _norm_path_args(cmd):
                if path == "/" or path in CRITICAL:
                    return (domain, RULE_RECURSIVE_PERM_CHANGE,
                            "Refusing recursive permission change on critical path: " + path)

    if cmd.executable == "chmod":
        paths = _norm_path_args(cmd)
        crippling_mode = any(
            a in ("000", "0000") or _CRIPPLE_MODE_RE.fullmatch(a) for a in cmd.args
        )
        if any(p in CRITICAL for p in paths) and crippling_mode:
            return (domain, RULE_RECURSIVE_PERM_CHANGE,
                    "Refusing to cripple critical directory permissions")
        if any(_BINARY_PATH_RE.match(p) for p in paths) and (
            crippling_mode or any(_mode_denies_exec(a) for a in cmd.args)
        ):
            return (domain, RULE_RECURSIVE_PERM_CHANGE,
                    "Refusing to cripple system binary permissions")

    if cmd.executable == "chattr":
        if any(_CHATTR_IMMUTABLE_RE.match(a) for a in cmd.args):
            for path in _norm_path_args(cmd):
                if path in CRITICAL or path.startswith(("/etc/", "/boot/", "/usr/lib/systemd/")):
                    return (domain, RULE_RECURSIVE_PERM_CHANGE,
                            "Refusing chattr immutable-flag change on critical path: " + path)
                if path in ("/etc", "/boot", "/usr/lib/systemd"):
                    return (domain, RULE_RECURSIVE_PERM_CHANGE,
                            "Refusing chattr immutable-flag change on critical path: " + path)
                if _BINARY_PATH_RE.match(path):
                    return (domain, RULE_RECURSIVE_PERM_CHANGE,
                            "Refusing chattr immutable-flag change on system binary/library: " + path)

    return None
