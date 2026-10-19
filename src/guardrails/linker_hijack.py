"""Dynamic Linker Hijack Defense.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects /etc/ld.so.preload, /etc/ld.so.conf and /etc/ld.so.conf.d/* from any
mutation, blocks overwrite/deletion of shared objects under /usr/lib* and /lib*,
and blocks LD_PRELOAD / LD_LIBRARY_PATH injection aimed at system binaries.
Avoids false positives on read-only queries (ls, cat, ldd).
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand, has_inplace_flag

RULE_LINKER_HIJACK = "RULE_LINKER_HIJACK"

LD_SO_TARGETS: Tuple[str, ...] = (
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
)

LD_SO_CONF_DIR = "/etc/ld.so.conf.d"

# F10: stream editors mutate only when invoked in place (sed -i / perl -i).
_INPLACE_EDITORS = {"sed", "perl"}

MUTATING_OPERATIONS: frozenset[str] = frozenset({
    "rm",
    "unlink",
    "mv",
    "cp",
    "install",
    "ln",
    "tee",
    "truncate",
    "chmod",
    "chown",
    "touch",
    "shred",
})

SHARED_OBJECT_OPERATIONS: frozenset[str] = frozenset({
    "rm",
    "unlink",
    "mv",
    "cp",
    "install",
    "ln",
    "truncate",
    "tee",
})

LD_ENV_VARS: frozenset[str] = frozenset({"LD_PRELOAD", "LD_LIBRARY_PATH"})

SYSTEM_BINARY_PREFIXES: Tuple[str, ...] = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/libexec/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
)


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _is_ld_so_path(path_str: str) -> bool:
    """Checks whether a path references dynamic linker configuration."""
    norm = _norm(path_str)
    if norm in LD_SO_TARGETS:
        return True
    return norm == LD_SO_CONF_DIR or norm.startswith(LD_SO_CONF_DIR + "/")


def _is_shared_object_path(path_str: str) -> bool:
    """Checks whether a path is a shared object under /usr/lib* or /lib*."""
    norm = _norm(path_str)
    if not (norm.startswith("/usr/lib") or norm.startswith("/lib")):
        return False
    return ".so" in os.path.basename(norm)


def _has_ld_env_injection(cmd: ParsedCommand) -> bool:
    """Checks for LD_PRELOAD / LD_LIBRARY_PATH assignments, incl. via env(1)."""
    if any(k in LD_ENV_VARS for k in cmd.env_vars):
        return True
    if cmd.executable == "env":
        return any(a.split("=", 1)[0] in LD_ENV_VARS for a in cmd.args if "=" in a)
    return False


def _targets_system_binary(cmd: ParsedCommand) -> bool:
    """Checks whether the wrapped final target is an absolute system binary path."""
    if not cmd.tokens:
        return False
    token: Optional[str] = cmd.tokens[0]
    if cmd.executable == "env":
        token = next((a for a in cmd.args if "=" not in a and not a.startswith("-")), None)
    if not token:
        return False
    return _norm(token).startswith(SYSTEM_BINARY_PREFIXES)


def check_linker_safety(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against dynamic linker hijack rules."""
    # 1. Redirection writes to linker configuration or shared objects
    for r in cmd.redirections:
        if _is_ld_so_path(r.target):
            return (
                "linker",
                RULE_LINKER_HIJACK,
                f"Write to dynamic linker configuration {_norm(r.target)} blocked",
            )
        if _is_shared_object_path(r.target):
            return (
                "linker",
                RULE_LINKER_HIJACK,
                f"Overwrite of shared object {_norm(r.target)} blocked",
            )

    # 2. Mutating utilities targeting linker configuration or shared objects
    # F10: sed/perl count as mutating only when editing in place (-i).
    inplace_edit = cmd.executable in _INPLACE_EDITORS and has_inplace_flag(cmd.args)
    if cmd.executable in MUTATING_OPERATIONS or inplace_edit:
        for a in cmd.args:
            if a.startswith("-"):
                continue
            if _is_ld_so_path(a):
                return (
                    "linker",
                    RULE_LINKER_HIJACK,
                    f"Mutation of dynamic linker configuration {_norm(a)} blocked",
                )
            if cmd.executable in SHARED_OBJECT_OPERATIONS and _is_shared_object_path(a):
                return (
                    "linker",
                    RULE_LINKER_HIJACK,
                    f"Overwrite or deletion of shared object {_norm(a)} blocked",
                )

    # 3. dd of=<ld.so path or shared object> (raw write)
    if cmd.executable == "dd":
        for a in cmd.args:
            if not a.startswith("of="):
                continue
            target = a[3:]
            if _is_ld_so_path(target):
                return (
                    "linker",
                    RULE_LINKER_HIJACK,
                    f"Raw write to dynamic linker configuration {_norm(target)} blocked",
                )
            if _is_shared_object_path(target):
                return (
                    "linker",
                    RULE_LINKER_HIJACK,
                    f"Raw write to shared object {_norm(target)} blocked",
                )

    # 4. LD_PRELOAD / LD_LIBRARY_PATH injection against a system binary
    if _has_ld_env_injection(cmd) and _targets_system_binary(cmd):
        return (
            "linker",
            RULE_LINKER_HIJACK,
            f"Dynamic linker environment injection into system binary blocked: {cmd.raw_str}",
        )

    return None
