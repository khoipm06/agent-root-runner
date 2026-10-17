"""Bootloader and Kernel Tampering Defense.

Part of Milestone 2 (M2) of Agent Root Runner.
Protects bootloaders (grub, efibootmgr, ostree), boot assets (/boot, /sys/firmware/efi/efivars),
and kernel runtime (rmmod, modprobe -r).
Avoids false positives on read-only queries (grep, echo, cat).
"""

from __future__ import annotations

import os
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

BOOTLOADER_UTILITIES: frozenset[str] = frozenset({
    "grub-install", "grub2-install", "grub-mkconfig", "grub2-mkconfig",
    "grubby", "efibootmgr", "ostree", "rmmod", "insmod", "modprobe",
})

SYS_REBOOT_TRIGGERS: Tuple[str, ...] = (
    "/proc/sysrq-trigger",
)


def check_bootloader_safety(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against bootloader and kernel tampering rules."""
    # 1. File deletions targeting /boot or /sys/firmware/efi/efivars (recursive or non-recursive)
    if cmd.executable in ("rm", "unlink", "shred"):
        for a in cmd.args:
            if not a.startswith("-"):
                norm_a = os.path.normpath(a)
                if (
                    norm_a == "/boot"
                    or norm_a.startswith("/boot/")
                    or norm_a == "/sys/firmware/efi/efivars"
                    or norm_a.startswith("/sys/firmware/efi/efivars/")
                ):
                    return (
                        "bootloader",
                        "RULE_BOOTLOADER_TAMPERING",
                        f"Deletion of boot assets ({norm_a}) blocked: {cmd.raw_str}",
                    )

    # 2. Sysrq trigger or boot asset writes via redirection
    for r in cmd.redirections:
        for t in SYS_REBOOT_TRIGGERS:
            if t in r.target:
                return (
                    "bootloader",
                    "RULE_BOOTLOADER_TAMPERING",
                    f"Kernel trigger modification blocked: {r.target}",
                )
        norm_t = os.path.normpath(r.target)
        if norm_t == "/boot" or norm_t.startswith("/boot/") or "/sys/firmware/efi/efivars" in norm_t:
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Write to boot assets ({r.target}) blocked",
            )

    # 3. Dedicated bootloader and kernel module utilities
    if cmd.executable in BOOTLOADER_UTILITIES:
        if cmd.executable in ("grub-install", "grub2-install", "grub-mkconfig", "grub2-mkconfig"):
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Grub modification blocked: {cmd.raw_str}",
            )
        if cmd.executable == "grubby" and any(
            a.startswith(
                (
                    "--remove-kernel",
                    "--update-kernel",
                    "--remove-args",
                    "--add-args",
                    "--args",
                    "--set-",
                )
            )
            for a in cmd.args
        ):
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Grubby kernel modification blocked: {cmd.raw_str}",
            )
        if cmd.executable == "efibootmgr":
            if any(
                flag in cmd.args
                for flag in ("-B", "-o", "-c", "--delete-bootnum", "--bootorder", "--create")
            ):
                return (
                    "bootloader",
                    "RULE_BOOTLOADER_TAMPERING",
                    f"Efibootmgr modification blocked: {cmd.raw_str}",
                )
        if cmd.executable == "ostree" and "admin" in cmd.args and any(
            sub in cmd.args for sub in ("unlock", "undeploy", "cleanup")
        ):
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Ostree administration command blocked: {cmd.raw_str}",
            )
        if cmd.executable in ("rmmod", "insmod"):
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Kernel module manipulation blocked: {cmd.raw_str}",
            )
        if cmd.executable == "modprobe" and any(a in ("-r", "--remove") for a in cmd.args):
            return (
                "bootloader",
                "RULE_BOOTLOADER_TAMPERING",
                f"Kernel module removal blocked: {cmd.raw_str}",
            )

    return None
