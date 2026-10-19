"""Guardrail against tampering with system persistence and log surfaces.

Part of Milestone 4 (M4) of Agent Root Runner.
Protects systemd units, cron entries, shell profile files, resolver/hosts
config, and everything under /var/log (including the tool's own audit log)
from writes, deletes, and renames. Read-only access and lifecycle commands
(systemctl status/daemon-reload, cat, grep) stay allowed; the tool's own unit
file /etc/systemd/system/agent-root-runner.service is explicitly exempt.
"""

from __future__ import annotations

import os
import re
from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand, has_inplace_flag

DOMAIN = "persistence_tamper"
RULE_PERSISTENCE_TAMPER = "RULE_PERSISTENCE_TAMPER"

_SELF_UNIT = "/etc/systemd/system/agent-root-runner.service"
_WRITE_EXES = {
    "rm",
    "unlink",
    "mv",
    "cp",
    "install",
    "tee",
    "truncate",
    "shred",
    "chmod",
    "chown",
    "touch",
    "ln",
}
# F10: stream editors mutate only when invoked in place (sed -i / perl -i).
_INPLACE_EDITORS = {"sed", "perl"}
_UNIT_RE = re.compile(r"^/etc/systemd/system/[^/]+\.(?:service|timer)$")
_CRON_D_RE = re.compile(r"^/etc/cron\.d/[^/]+$")
_PROFILE_D_RE = re.compile(r"^/etc/profile\.d/[^/]+$")
_EXACT_PROTECTED = {
    "/etc/crontab",
    "/var/spool/cron",
    "/etc/profile",
    "/etc/bashrc",
    "/etc/zshrc",
    "/root/.bashrc",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/etc/nsswitch.conf",
}
# F11: narrowed from a blanket /var/log/ rule; keep evidence-bearing system
# logs and their rotated variants, plus the tool's own audit directory.
_SENSITIVE_LOG_RE = re.compile(
    r"^/var/log/(?:auth\.log|secure|messages|syslog|wtmp|btmp|audit\.log)"
    r"(?:\.\d+)?(?:\.gz)?$"
)
_LOG_DIR_PREFIXES = ("/var/log/audit/", "/var/log/agent-root-runner/")


def _norm(path_str: str) -> str:
    """Normalizes a path to an absolute form for comparison."""
    return "/" + os.path.normpath(path_str).lstrip("/")


def _is_protected(path: str) -> bool:
    """True when a normalized path is a protected persistence/log surface."""
    if path == _SELF_UNIT:
        return False
    if path.startswith("/usr/lib/systemd/system/"):
        return True
    if _UNIT_RE.match(path) or _CRON_D_RE.match(path) or _PROFILE_D_RE.match(path):
        return True
    if path == "/var/spool/cron" or path.startswith("/var/spool/cron/"):
        return True
    if path in _EXACT_PROTECTED:
        return True
    if _SENSITIVE_LOG_RE.match(path):
        return True
    if path.startswith(_LOG_DIR_PREFIXES):
        return True
    return False


def check_persistence_tamper(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Blocks writes/mutations of protected persistence, config, and log paths."""
    exe = os.path.basename(cmd.executable)
    args = cmd.args

    if exe == "journalctl" and any(a.startswith("--vacuum") for a in args):
        return (
            DOMAIN,
            RULE_PERSISTENCE_TAMPER,
            "Blocked: journalctl --vacuum destroys system journal history.",
        )

    if exe == "history" and "-c" in args:
        return (
            DOMAIN,
            RULE_PERSISTENCE_TAMPER,
            "Blocked: history -c clears shell history evidence.",
        )

    # F10: crontab -r removes the caller's crontab wholesale (crontab -l stays read-only).
    if exe == "crontab" and "-r" in args:
        return (
            DOMAIN,
            RULE_PERSISTENCE_TAMPER,
            "Blocked: crontab -r removes scheduled persistence entries.",
        )

    # F4: systemctl enable/link/preset of an out-of-tree unit path plants a
    # persistence unit outside the packaged system; the tool's own unit is exempt.
    if exe == "systemctl":
        positionals = [a for a in args if not a.startswith("-")]
        if positionals and positionals[0] in ("enable", "link", "preset"):
            for a in positionals[1:]:
                if (
                    a.startswith("/")
                    and a.endswith((".service", ".timer", ".socket"))
                    and _norm(a) != _SELF_UNIT
                ):
                    return (
                        DOMAIN,
                        RULE_PERSISTENCE_TAMPER,
                        "Blocked: systemctl enable/link of out-of-tree unit " + a,
                    )

    candidates = [_norm(r.target) for r in cmd.redirections if r.target]
    inplace_edit = exe in _INPLACE_EDITORS and has_inplace_flag(args)
    if exe in _WRITE_EXES or inplace_edit:
        candidates += [_norm(a) for a in args if a.startswith("/")]

    for path in candidates:
        if _is_protected(path):
            return (
                DOMAIN,
                RULE_PERSISTENCE_TAMPER,
                f"Blocked: write/mutation of protected path '{path}'.",
            )
    return None
