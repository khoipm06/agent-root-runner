"""Top-level Guardrail Command Analyzer Pipeline.

Part of Milestone 2 (M2) of Agent Root Runner.
Provides the evaluate_command() evaluation pipeline and CommandAnalyzer class.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator, Optional

from src.guardrails.bootloader import check_bootloader_safety
from src.guardrails.network import check_network_safety
from src.guardrails.parser import FORK_BOMB_PATTERNS, parse_command_chain
from src.guardrails.storage import StorageDAG, check_storage_safety
from src.guardrails.boot_config import check_boot_config_safety
from src.guardrails.linker_hijack import check_linker_safety
from src.guardrails.mount_integrity import check_mount_integrity
from src.guardrails.package_state import check_package_state
from src.guardrails.persistence_tamper import check_persistence_tamper
from src.guardrails.process_integrity import check_process_integrity
from src.guardrails.recursive_perm import check_recursive_perm
from src.guardrails.system_files import check_auth_files_safety


@dataclass(frozen=True)
class GuardrailVerdict:
    """Immutable verdict result of guardrail command evaluation.

    Supports both attribute access (.allowed, .category, .matched_rule, .reason, .rule)
    and 3-tuple unpacking: allowed, rule, reason = verdict.
    """

    allowed: bool
    reason: str
    category: Optional[str] = None  # "storage", "auth", "network", "bootloader", "resource", "evasion"
    matched_rule: Optional[str] = None

    @property
    def rule(self) -> Optional[str]:
        """Backward compatibility alias for matched_rule."""
        return self.matched_rule

    def __iter__(self) -> Iterator[object]:
        """Allows 3-tuple unpacking: allowed, rule, reason = verdict."""
        yield self.allowed
        yield self.matched_rule
        yield self.reason


class CommandAnalyzer:
    """Reusable command analyzer maintaining a cached StorageDAG instance."""

    def __init__(self, storage_dag: Optional[StorageDAG] = None) -> None:
        self.storage_dag = storage_dag or StorageDAG()

    def evaluate(self, cmd_str: str) -> GuardrailVerdict:
        """Evaluates command string and returns GuardrailVerdict."""
        return evaluate_command(cmd_str, storage_dag=self.storage_dag)

    def refresh(self) -> None:
        """Refreshes storage DAG from host mountpoints."""
        self.storage_dag.refresh()


def evaluate_command(
    cmd_str: str, storage_dag: Optional[StorageDAG] = None
) -> GuardrailVerdict:
    """Evaluates a raw shell command string against all Destabilization Guardrails."""
    stripped = cmd_str.strip()
    if not stripped:
        return GuardrailVerdict(
            allowed=True,
            reason="Empty command string",
            category=None,
            matched_rule=None,
        )

    # 1. Global Fork Bomb Evasion Check on raw string
    for pat in FORK_BOMB_PATTERNS:
        if pat.search(stripped):
            return GuardrailVerdict(
                allowed=False,
                category="resource",
                matched_rule="RULE_RESOURCE_FORK_BOMB",
                reason="Fork bomb pattern detected",
            )

    dag = storage_dag or StorageDAG()
    parsed_commands = parse_command_chain(stripped)

    # Queue all atomic commands, peeled wrappers, and subshells for evaluation
    queue = list(parsed_commands)
    while queue:
        cmd = queue.pop(0)

        # Syntax error fail-closed check
        if cmd.has_syntax_error:
            return GuardrailVerdict(
                allowed=False,
                category="evasion",
                matched_rule="RULE_EVASION_SYNTAX_ERROR",
                reason="Command contains syntax error or unbalanced quotes/parentheses",
            )

        # 2. Pipe-to-Shell Stream Evasion
        if cmd.is_pipe_to_shell:
            return GuardrailVerdict(
                allowed=False,
                category="evasion",
                matched_rule="RULE_EVASION_PIPE_SHELL",
                reason="Piping arbitrary stream into shell interpreter is prohibited",
            )

        # 3. Fork Bomb within command segment
        if cmd.is_fork_bomb:
            return GuardrailVerdict(
                allowed=False,
                category="resource",
                matched_rule="RULE_RESOURCE_FORK_BOMB",
                reason="Fork bomb pattern detected",
            )

        # 4. Unresolvable Variables in Destructive Commands
        if cmd.has_unresolved_var:
            return GuardrailVerdict(
                allowed=False,
                category="evasion",
                matched_rule="RULE_EVASION_UNRESOLVED_VAR",
                reason="Unresolvable variable expansion in destructive command",
            )

        # 5. Critical Authentication & Access Files Safety
        #    Evaluated before storage so specific auth assets (e.g. /etc/pam.d)
        #    report RULE_AUTH_FILE_MUTATION rather than the broader mountpoint rule.
        auth_violation = check_auth_files_safety(cmd)
        if auth_violation:
            cat, rule, reason = auth_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 5b. Pipeline Dataflow: critical paths streamed into an xargs mutator
        #     (blocker computed in parser, which has cross-segment context).
        if cmd.is_xargs_critical_dataflow:
            return GuardrailVerdict(
                allowed=False,
                category="storage",
                matched_rule="RULE_PIPELINE_XARGS_DATAFLOW",
                reason="Critical system paths piped into xargs mutating command",
            )

        # 6. Storage DAG & Block Device Safety
        storage_violation = check_storage_safety(cmd, dag)
        if storage_violation:
            cat, rule, reason = storage_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 7. Network Isolation Safety
        network_violation = check_network_safety(cmd)
        if network_violation:
            cat, rule, reason = network_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 8. Bootloader & Kernel Tampering Safety
        bootloader_violation = check_bootloader_safety(cmd)
        if bootloader_violation:
            cat, rule, reason = bootloader_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 9. Boot Configuration Integrity Safety
        boot_config_violation = check_boot_config_safety(cmd)
        if boot_config_violation:
            cat, rule, reason = boot_config_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 10. Dynamic Linker Hijack Safety
        linker_violation = check_linker_safety(cmd)
        if linker_violation:
            cat, rule, reason = linker_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 11. Process Integrity Safety
        process_violation = check_process_integrity(cmd)
        if process_violation:
            cat, rule, reason = process_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 12. Recursive Permission Change Safety
        perm_violation = check_recursive_perm(cmd)
        if perm_violation:
            cat, rule, reason = perm_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 13. Package State Destruction Safety
        package_violation = check_package_state(cmd)
        if package_violation:
            cat, rule, reason = package_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 14. Persistence Tamper Safety
        persistence_violation = check_persistence_tamper(cmd)
        if persistence_violation:
            cat, rule, reason = persistence_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # 15. Mount Integrity Safety
        mount_violation = check_mount_integrity(cmd)
        if mount_violation:
            cat, rule, reason = mount_violation
            return GuardrailVerdict(
                allowed=False, category=cat, matched_rule=rule, reason=reason
            )

        # Enqueue unwrapped wrapper commands (e.g. inner commands inside sudo, sh -c, eval)
        queue.extend(cmd.unwrapped_commands)

        # Parse and enqueue subshell commands
        for sub in cmd.subshells:
            queue.extend(parse_command_chain(sub))

    return GuardrailVerdict(
        allowed=True,
        reason="Command permitted by guardrails",
        category=None,
        matched_rule=None,
    )
