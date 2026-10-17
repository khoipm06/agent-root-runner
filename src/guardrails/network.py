"""Network Isolation Defense.

Part of Milestone 2 (M2) of Agent Root Runner.
Blocks commands that drop host connectivity or flush firewalls without rollback
(iptables -F, nft flush ruleset, ip link set ... down, systemctl stop NetworkManager).
Avoids false positives on read-only queries (grep, echo, cat).
"""

from __future__ import annotations

from typing import Optional, Tuple

from src.guardrails.parser import ParsedCommand

NETWORK_UTILITIES: frozenset[str] = frozenset({
    "iptables", "ip6tables", "nft", "ip", "ifconfig",
    "systemctl", "nmcli", "ufw", "firewall-cmd",
})


def check_network_safety(cmd: ParsedCommand) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against network isolation rules."""
    if cmd.executable not in NETWORK_UTILITIES:
        return None

    # 1. iptables / ip6tables flush or chain deletion (with any flag order)
    if cmd.executable in ("iptables", "ip6tables"):
        if any(
            a in ("-F", "-X", "--flush", "--delete-chain")
            or a.startswith("-F")
            or a.startswith("-X")
            for a in cmd.args
        ):
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Flushing firewall ruleset blocked: {cmd.raw_str}",
            )

    # 2. nft flush ruleset / flush table / delete table
    if cmd.executable == "nft":
        if any(a in cmd.args for a in ("flush", "delete")):
            if any(a in cmd.args for a in ("ruleset", "table", "chain")):
                return (
                    "network",
                    "RULE_NETWORK_ISOLATION",
                    f"Flushing nftables ruleset blocked: {cmd.raw_str}",
                )

    # 3. ip link set ... down
    if cmd.executable == "ip":
        if "link" in cmd.args and "set" in cmd.args and "down" in cmd.args:
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Bringing network interface down blocked: {cmd.raw_str}",
            )

    # 4. ifconfig ... down
    if cmd.executable == "ifconfig":
        if "down" in cmd.args:
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Bringing network interface down blocked: {cmd.raw_str}",
            )

    # 5. systemctl stop/disable/mask NetworkManager or systemd-networkd
    if cmd.executable == "systemctl":
        if any(a in ("stop", "disable", "mask") for a in cmd.args):
            for target in (
                "NetworkManager", "NetworkManager.service",
                "systemd-networkd", "systemd-networkd.service",
                "firewalld", "firewalld.service"
            ):
                if target in cmd.args:
                    return (
                        "network",
                        "RULE_NETWORK_ISOLATION",
                        f"Stopping or disabling network service blocked: {cmd.raw_str}",
                    )

    # 6. nmcli networking/radio off, device disconnect
    if cmd.executable == "nmcli":
        if ("networking" in cmd.args and "off" in cmd.args) or \
           ("radio" in cmd.args and "all" in cmd.args and "off" in cmd.args) or \
           ("device" in cmd.args and "disconnect" in cmd.args):
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Disabling networking via nmcli blocked: {cmd.raw_str}",
            )

    # 7. ufw disable / reset
    if cmd.executable == "ufw":
        if any(a in ("disable", "reset") for a in cmd.args):
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Disabling ufw firewall blocked: {cmd.raw_str}",
            )

    # 8. firewall-cmd --panic-on
    if cmd.executable == "firewall-cmd":
        if "--panic-on" in cmd.args:
            return (
                "network",
                "RULE_NETWORK_ISOLATION",
                f"Activating firewall panic mode blocked: {cmd.raw_str}",
            )

    return None
