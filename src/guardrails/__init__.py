"""Destabilization Guardrails Engine Package.

Part of Milestone 2 (M2) of Agent Root Runner.
Exports the analyzer pipeline, parser, and domain safety checkers.
"""

from src.guardrails.analyzer import (
    CommandAnalyzer,
    GuardrailVerdict,
    evaluate_command,
)
from src.guardrails.boot_config import check_boot_config_safety
from src.guardrails.bootloader import check_bootloader_safety
from src.guardrails.linker_hijack import check_linker_safety
from src.guardrails.mount_integrity import check_mount_integrity
from src.guardrails.package_state import check_package_state
from src.guardrails.persistence_tamper import check_persistence_tamper
from src.guardrails.process_integrity import check_process_integrity
from src.guardrails.recursive_perm import check_recursive_perm
from src.guardrails.network import check_network_safety
from src.guardrails.parser import (
    ParsedCommand,
    Redirection,
    parse_command_chain,
)
from src.guardrails.storage import (
    StorageDAG,
    check_storage_safety,
)
from src.guardrails.system_files import check_auth_files_safety

__all__ = [
    "CommandAnalyzer",
    "GuardrailVerdict",
    "evaluate_command",
    "ParsedCommand",
    "Redirection",
    "parse_command_chain",
    "StorageDAG",
    "check_storage_safety",
    "check_auth_files_safety",
    "check_network_safety",
    "check_bootloader_safety",
    "check_boot_config_safety",
    "check_linker_safety",
    "check_process_integrity",
    "check_recursive_perm",
    "check_package_state",
    "check_persistence_tamper",
    "check_mount_integrity",
]
