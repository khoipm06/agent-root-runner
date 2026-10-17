"""Blocks process-integrity attacks: PID 1 kills, killall5, kernel tunable writes.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects PID 1 / system-wide killall and kernel.modprobe, kernel.core_pattern,
and /proc/sys/vm/ tunables (arbitrary code exec via module loading / core dumps).
False positives: killing ordinary PIDs, `killall <name>`, `sysctl -a`, plain
reads of /proc stay allowed.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

RULE_PROCESS_INTEGRITY = "RULE_PROCESS_INTEGRITY"

_PROTECTED_PROC_PATHS = {
    "/proc/sys/kernel/core_pattern",
    "/proc/sys/kernel/modprobe",
}

_SYSCTL_KEYS = ("kernel.modprobe", "kernel.core_pattern")


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def check_process_integrity(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Blocks PID 1 kills, killall5, and protected kernel tunable writes."""
    domain = "process_integrity"

    if cmd.executable == "kill":
        for arg in cmd.args:
            if arg == "-1":
                return (domain, RULE_PROCESS_INTEGRITY,
                        "Refusing to kill all processes (kill -1)")
            if arg.startswith("-"):
                continue
            if arg in ("1", "01"):
                return (domain, RULE_PROCESS_INTEGRITY,
                        "Refusing to kill PID 1 (init)")

    if cmd.executable == "killall5":
        return (domain, RULE_PROCESS_INTEGRITY,
                "Refusing to run killall5 (kills all processes)")

    for r in cmd.redirections:
        target = _norm(r.target)
        if target in _PROTECTED_PROC_PATHS:
            return (domain, RULE_PROCESS_INTEGRITY,
                    "Refusing to write protected kernel tunable: " + r.target)
        if target.startswith("/proc/sys/vm/"):
            return (domain, RULE_PROCESS_INTEGRITY,
                    "Refusing to write /proc/sys/vm/ tunable: " + r.target)

    if cmd.executable == "sysctl" and ("-w" in cmd.args or "--write" in cmd.args):
        for arg in cmd.args:
            if arg.startswith(_SYSCTL_KEYS):
                return (domain, RULE_PROCESS_INTEGRITY,
                        "Refusing to write protected sysctl key: " + arg)

    return None
