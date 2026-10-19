"""Boot Configuration Integrity Defense.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects early boot configuration (/etc/fstab, /etc/default/grub,
/etc/kernel/cmdline, grub.cfg) from mutation via redirections and mutating
utilities, and blocks destructive systemd state transitions (set-default,
isolate, mask of core units, daemon-reexec, emergency/rescue/halt/poweroff/reboot).
Avoids false positives on read-only queries (cat, grep, systemctl status).
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand, has_inplace_flag

RULE_BOOT_CONFIG_INTEGRITY = "RULE_BOOT_CONFIG_INTEGRITY"

BOOT_CONFIG_PATHS: Tuple[str, ...] = (
    "/etc/fstab",
    "/etc/default/grub",
    "/etc/kernel/cmdline",
)

GRUB_CFG_PATTERN = re.compile(r"^/boot/grub[^/]*/grub\.cfg$")

MUTATING_OPERATIONS: frozenset[str] = frozenset({
    "rm",
    "unlink",
    "mv",
    "truncate",
    "tee",
    "cp",
    "chmod",
    "chown",
    "install",
    "shred",
    "ln",
    "touch",
})

SYSTEM_UNIT_PREFIXES: Tuple[str, ...] = (
    "systemd-",
    "dbus",
    "getty",
    "sshd",
    "auditd",
    "polkit",
)

SYSTEMD_DESTRUCTIVE_VERBS: frozenset[str] = frozenset({"set-default", "isolate", "mask"})

SYSTEMD_TARGET_MODES: frozenset[str] = frozenset({
    "emergency",
    "rescue",
    "halt",
    "poweroff",
    "reboot",
})


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _is_boot_config_path(path_str: str) -> bool:
    """Checks whether a path references protected boot configuration."""
    norm = _norm(path_str)
    if GRUB_CFG_PATTERN.match(norm):
        return True
    return norm in BOOT_CONFIG_PATHS


def _is_inplace_edit(cmd: ParsedCommand) -> bool:
    """Checks whether a stream editor performs an in-place edit."""
    return has_inplace_flag(cmd.args)


def check_boot_config_safety(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against boot configuration integrity rules."""
    # 1. Redirection writes to boot configuration files (> /etc/fstab)
    for r in cmd.redirections:
        if _is_boot_config_path(r.target):
            return (
                "boot_config",
                RULE_BOOT_CONFIG_INTEGRITY,
                f"Write to boot configuration {_norm(r.target)} blocked",
            )

    # 2. Mutating commands targeting boot configuration files (rm, mv, cp, chmod, ...)
    # F1: for cp/install/ln/touch only the destination (last positional) matters, so
    # that legitimate copy FROM boot config (e.g. cp /etc/fstab /tmp/backup) or a
    # symlink INTO tmp (ln -s /etc/fstab /tmp/link) stays allowed.
    if cmd.executable in MUTATING_OPERATIONS:
        positional = [a for a in cmd.args if not a.startswith("-")]
        targets = (
            positional[-1:]
            if cmd.executable in ("cp", "install", "ln", "touch")
            else positional
        )
        for a in targets:
            if _is_boot_config_path(a):
                return (
                    "boot_config",
                    RULE_BOOT_CONFIG_INTEGRITY,
                    f"Mutation of boot configuration {_norm(a)} blocked",
                )

    # 3. In-place stream edits (sed -i / perl -i /etc/fstab)
    if cmd.executable in ("sed", "perl") and _is_inplace_edit(cmd):
        for a in cmd.args:
            if not a.startswith("-") and _is_boot_config_path(a):
                return (
                    "boot_config",
                    RULE_BOOT_CONFIG_INTEGRITY,
                    f"In-place edit of boot configuration {_norm(a)} blocked",
                )

    # 4. dd of=/etc/fstab
    if cmd.executable == "dd":
        for a in cmd.args:
            if a.startswith("of=") and _is_boot_config_path(a[3:]):
                return (
                    "boot_config",
                    RULE_BOOT_CONFIG_INTEGRITY,
                    f"Raw write to boot configuration {_norm(a[3:])} blocked",
                )

    # 5. Destructive systemd state transitions
    if cmd.executable == "systemctl":
        for verb in SYSTEMD_DESTRUCTIVE_VERBS:
            if verb not in cmd.args:
                continue
            for a in cmd.args:
                if a.startswith("-") or a in SYSTEMD_DESTRUCTIVE_VERBS:
                    continue
                unit = a[: -len(".service")] if a.endswith(".service") else a
                if any(unit.startswith(prefix) for prefix in SYSTEM_UNIT_PREFIXES):
                    return (
                        "boot_config",
                        RULE_BOOT_CONFIG_INTEGRITY,
                        f"Destructive systemctl {verb} on core unit {a} blocked",
                    )
                unit_base = unit[: -len(".target")] if unit.endswith(".target") else unit
                if unit_base in SYSTEMD_TARGET_MODES:
                    return (
                        "boot_config",
                        RULE_BOOT_CONFIG_INTEGRITY,
                        f"Destructive systemctl {verb} to {a} blocked",
                    )
        if "daemon-reexec" in cmd.args:
            return (
                "boot_config",
                RULE_BOOT_CONFIG_INTEGRITY,
                f"systemd daemon-reexec blocked: {cmd.raw_str}",
            )
        for mode in SYSTEMD_TARGET_MODES:
            if mode in cmd.args:
                return (
                    "boot_config",
                    RULE_BOOT_CONFIG_INTEGRITY,
                    f"Systemd transition into {mode} mode blocked: {cmd.raw_str}",
                )

    return None
