"""Mock diagnostic tools and audit log parsing helpers for E2E tests."""

import json
import os
import stat
from typing import Any, Dict, List, Optional


def create_mock_binaries(target_dir: str) -> Dict[str, str]:
    """Create executable mock binaries for diagnostic commands in target_dir.

    Returns a dict mapping command name to full file path.
    """
    os.makedirs(target_dir, exist_ok=True)
    binaries = {}

    # 1. smartctl mock
    smartctl_path = os.path.join(target_dir, "smartctl")
    with open(smartctl_path, "w", encoding="utf-8") as f:
        f.write(
            """#!/bin/sh
if [ "$1" = "-a" ] || [ "$1" = "-H" ] || [ "$1" = "--all" ]; then
    echo "smartctl 7.4 2023-08-01 r5530 [x86_64-linux]"
    echo "=== START OF INFORMATION SECTION ==="
    echo "Model Number:                       SAMSUNG MZVLB1T0HALR-00000"
    echo "Serial Number:                      S3W6NA0M123456"
    echo "Firmware Version:                   EDA7300Q"
    echo "PCI Vendor/Subsystem ID:            0x144d"
    echo "IEEE OUI Identifier:                0x002538"
    echo "Total NVM Capacity:                 1,024,209,543,168 [1.02 TB]"
    echo "=== START OF READ SMART DATA SECTION ==="
    echo "SMART overall-health self-assessment test result: PASSED"
    echo "Temperature:                        38 Celsius"
    exit 0
fi
echo "smartctl: unrecognized option '$*'" >&2
exit 1
"""
        )
    os.chmod(smartctl_path, os.stat(smartctl_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    binaries["smartctl"] = smartctl_path

    # 2. hdparm mock
    hdparm_path = os.path.join(target_dir, "hdparm")
    with open(hdparm_path, "w", encoding="utf-8") as f:
        f.write(
            """#!/bin/sh
if [ "$1" = "-I" ]; then
    echo "/dev/nvme0n1:"
    echo "SG_IO: bad/missing sense data"
    echo "ATA device, with non-removable media"
    echo "Model Number:       Micron_2400_MTFDKBA1T0QFM"
    echo "Serial Number:      23103DA23101"
    echo "Firmware Revision:  HPS0001"
    exit 0
fi
echo "hdparm: invalid option '$*'" >&2
exit 1
"""
        )
    os.chmod(hdparm_path, os.stat(hdparm_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    binaries["hdparm"] = hdparm_path

    # 3. iptables mock
    iptables_path = os.path.join(target_dir, "iptables")
    with open(iptables_path, "w", encoding="utf-8") as f:
        f.write(
            """#!/bin/sh
if [ "$1" = "-L" ] || [ "$1" = "-S" ] || [ "$1" = "--list" ]; then
    echo "Chain INPUT (policy ACCEPT)"
    echo "target     prot opt source               destination"
    echo "ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0            state RELATED,ESTABLISHED"
    echo "Chain FORWARD (policy DROP)"
    echo "Chain OUTPUT (policy ACCEPT)"
    exit 0
fi
echo "iptables: action executed"
exit 0
"""
        )
    os.chmod(iptables_path, os.stat(iptables_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    binaries["iptables"] = iptables_path

    # 4. systemctl mock
    systemctl_path = os.path.join(target_dir, "systemctl")
    with open(systemctl_path, "w", encoding="utf-8") as f:
        f.write(
            """#!/bin/sh
if [ "$1" = "status" ]; then
    echo "● $2.service - Example Service"
    echo "     Loaded: loaded (/usr/lib/systemd/system/$2.service; enabled; preset: disabled)"
    echo "     Active: active (running) since Tue 2026-10-06 14:00:00 UTC; 35min ago"
    echo "   Main PID: 1234 ($2)"
    echo "      Tasks: 4 (limit: 1024)"
    exit 0
fi
echo "systemctl: action '$*' executed"
exit 0
"""
        )
    os.chmod(systemctl_path, os.stat(systemctl_path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    binaries["systemctl"] = systemctl_path

    return binaries


def read_audit_log(log_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """Parse structured NDJSON audit log file into list of dicts."""
    target = log_path or os.environ.get(
        "AGENT_ROOT_RUNNER_AUDIT_LOG", "/var/log/agent-root-runner/audit.log"
    )
    if not os.path.exists(target):
        return []

    entries = []
    with open(target, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            stripped = line.strip()
            if stripped:
                try:
                    entries.append(json.loads(stripped))
                except json.JSONDecodeError:
                    pass
    return entries
