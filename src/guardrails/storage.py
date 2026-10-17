"""Dynamic Protected Storage DAG and Block Device Guardrails.

Part of Milestone 2 (M2) of Agent Root Runner.
Discovers host storage DAG from /proc/mounts, /proc/swaps, and /sys/class/block.
Blocks destructive raw disk writes (dd, cp), formatting (mkfs), and partition wiping (fdisk, sgdisk)
while permitting read-only diagnostics (smartctl, hdparm -I, lsblk, fdisk -l, sgdisk -p).
"""

from __future__ import annotations

import os
from typing import List, Optional, Set, Tuple

from src.guardrails.parser import ParsedCommand


class StorageDAG:
    """Dynamic Directed Acyclic Graph of OS storage devices and mountpoints."""

    DEFAULT_PROTECTED_DISKS: Tuple[str, ...] = (
        "/dev/nvme0n1",
        "/dev/nvme0n1p",
        "/dev/sda",
        "/dev/vda",
        "/dev/mapper/",
        "/dev/root",
        "/dev/boot",
    )

    BLOCK_DEV_PREFIXES: Tuple[str, ...] = (
        "nvme",
        "sd",
        "vd",
        "dm-",
        "loop",
        "zram",
        "md",
        "xvd",
        "hd",
    )

    BLOCK_DEV_NAMES: Tuple[str, ...] = (
        "root",
        "boot",
        "swap",
    )

    CRITICAL_MOUNTS: frozenset[str] = frozenset({
        "/",
        "/sysroot",
        "/boot",
        "/boot/efi",
        "/etc",
        "/var",
        "/usr",
        "/home",
        "/root",
        "/opt",
        "/lib",
        "/lib64",
        "/bin",
        "/sbin",
    })

    SAFE_PSEUDO_DEVICES: frozenset[str] = frozenset({
        "/dev/null",
        "/dev/zero",
        "/dev/urandom",
        "/dev/random",
        "/dev/stdout",
        "/dev/stderr",
        "/dev/stdin",
    })

    def __init__(
        self,
        mounts_path: str = "/proc/mounts",
        swaps_path: str = "/proc/swaps",
        sysfs_block_path: str = "/sys/class/block",
    ) -> None:
        self.mounts_path = mounts_path
        self.swaps_path = swaps_path
        self.sysfs_block_path = sysfs_block_path
        self.protected_devices: Set[str] = set(self.DEFAULT_PROTECTED_DISKS)
        self.refresh()

    def refresh(self) -> None:
        """Dynamically scans host mounts, swaps, and sysfs block devices."""
        self.protected_devices = set(self.DEFAULT_PROTECTED_DISKS)
        self._scan_mounts()
        self._scan_swaps()

    def _add_device_and_ancestors(self, dev_path: str) -> None:
        if not dev_path.startswith("/dev/"):
            return
        if dev_path in self.SAFE_PSEUDO_DEVICES:
            return
        self.protected_devices.add(dev_path)
        try:
            real_path = os.path.realpath(dev_path)
            self.protected_devices.add(real_path)
            dev_name = os.path.basename(real_path)

            # Traverse sysfs block slaves
            slaves_dir = os.path.join(self.sysfs_block_path, dev_name, "slaves")
            if os.path.exists(slaves_dir):
                for slave in os.listdir(slaves_dir):
                    slave_path = f"/dev/{slave}"
                    self.protected_devices.add(slave_path)
                    try:
                        self.protected_devices.add(os.path.realpath(slave_path))
                    except OSError:
                        pass

            # Traverse parent partition in sysfs
            dev_sysfs = os.path.join(self.sysfs_block_path, dev_name)
            if os.path.exists(dev_sysfs):
                parent_dir = os.path.basename(
                    os.path.dirname(os.path.realpath(dev_sysfs))
                )
                if os.path.exists(os.path.join(self.sysfs_block_path, parent_dir)):
                    self.protected_devices.add(f"/dev/{parent_dir}")
        except Exception:
            pass

    def _scan_mounts(self) -> None:
        if not os.path.exists(self.mounts_path):
            return
        try:
            with open(self.mounts_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        dev, mnt = parts[0], parts[1]
                        if (
                            mnt in self.CRITICAL_MOUNTS
                            or mnt.startswith("/sysroot")
                            or mnt.startswith("/boot")
                        ):
                            self._add_device_and_ancestors(dev)
        except Exception:
            pass

    def _scan_swaps(self) -> None:
        if not os.path.exists(self.swaps_path):
            return
        try:
            with open(self.swaps_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if parts and parts[0].startswith("/dev/"):
                        self._add_device_and_ancestors(parts[0])
        except Exception:
            pass

    def is_protected(self, target: str) -> bool:
        """Determines whether a target block device path is part of the protected storage DAG."""
        if not target or target.startswith("-"):
            return False

        norm = os.path.normpath(target)
        if norm in self.SAFE_PSEUDO_DEVICES:
            return False

        candidates = [norm]
        derived_from_device = norm.startswith("/dev/")

        if not norm.startswith("/"):
            if norm.startswith(self.BLOCK_DEV_PREFIXES) or norm in self.BLOCK_DEV_NAMES:
                candidates.append(f"/dev/{norm}")
                candidates.append(f"/dev/mapper/{norm}")

        for cand in candidates:
            if cand in self.SAFE_PSEUDO_DEVICES:
                continue
            try:
                real = os.path.realpath(cand)
            except Exception:
                real = cand

            for p in self.protected_devices:
                if p.endswith("/"):
                    # For directory prefixes like /dev/mapper/, only match if cand != p
                    # and cand was derived from a valid device path or is an existing block device node.
                    is_valid_cand = (
                        derived_from_device
                        or os.path.exists(cand)
                        or os.path.exists(
                            os.path.join(self.sysfs_block_path, os.path.basename(cand))
                        )
                        or (cand in self.protected_devices and cand != p)
                    )
                    if cand != p and cand.startswith(p) and is_valid_cand:
                        return True
                    if real != p and real.startswith(p) and is_valid_cand:
                        return True
                else:
                    if cand == p or cand.startswith(p) or real == p or real.startswith(p):
                        return True
        return False


def check_storage_safety(
    cmd: ParsedCommand, dag: StorageDAG
) -> Optional[Tuple[str, str, str]]:
    """Evaluates command against storage destabilization rules."""
    # 1. Redirection writes to block devices (> /dev/...)
    for r in cmd.redirections:
        if not r.target.startswith("-") and dag.is_protected(r.target):
            return (
                "storage",
                "RULE_BLOCK_DEV_RAW_WRITE",
                f"Redirection to protected block device {r.target} blocked",
            )

    # 2. dd raw device write
    if cmd.executable == "dd":
        for a in cmd.args:
            if a.startswith("of="):
                target = a[3:].strip("\"'")
                if not target.startswith("-") and dag.is_protected(target):
                    return (
                        "storage",
                        "RULE_BLOCK_DEV_RAW_WRITE",
                        f"Raw write to protected block device {target} blocked",
                    )

    # 3. cp raw device write
    if cmd.executable == "cp":
        non_flags = [a for a in cmd.args if not a.startswith("-")]
        if len(non_flags) >= 2:
            dest = non_flags[-1]
            if dag.is_protected(dest):
                return (
                    "storage",
                    "RULE_BLOCK_DEV_RAW_WRITE",
                    f"Raw write via cp to protected block device {dest} blocked",
                )

    # 4. tee write to protected block device
    if cmd.executable == "tee":
        for a in cmd.args:
            if not a.startswith("-") and dag.is_protected(a):
                return (
                    "storage",
                    "RULE_BLOCK_DEV_RAW_WRITE",
                    f"Raw write via tee to protected block device {a} blocked",
                )

    # 5. mkfs filesystem formatting
    if cmd.executable.startswith("mkfs") or cmd.executable in (
        "mke2fs",
        "mkswap",
    ):
        for a in cmd.args:
            if not a.startswith("-") and dag.is_protected(a):
                return (
                    "storage",
                    "RULE_BLOCK_DEV_FORMAT",
                    f"Formatting protected block device {a} blocked",
                )

    # 6. wipefs & blkdiscard
    if cmd.executable in ("wipefs", "blkdiscard"):
        for a in cmd.args:
            if not a.startswith("-") and dag.is_protected(a):
                return (
                    "storage",
                    "RULE_BLOCK_DEV_PARTITION",
                    f"Wiping block device {a} blocked",
                )

    # 7. Destructive fdisk / gdisk / sfdisk (without -l / --list)
    if cmd.executable in ("fdisk", "gdisk", "sfdisk"):
        if not any(flag in cmd.args for flag in ("-l", "--list")):
            for a in cmd.args:
                if not a.startswith("-") and dag.is_protected(a):
                    return (
                        "storage",
                        "RULE_BLOCK_DEV_PARTITION",
                        f"Destructive fdisk on {a} blocked",
                    )

    # 8. sgdisk partition manipulation (without -p / --print)
    if cmd.executable == "sgdisk":
        is_read_only = any(f in cmd.args for f in ("-p", "--print")) and not any(
            f in cmd.args
            for f in (
                "-z", "-Z", "--zap", "--zap-all", "-d", "-n", "-o", "--clear", "-c", "-t"
            )
        )
        if not is_read_only:
            for a in cmd.args:
                if not a.startswith("-") and dag.is_protected(a):
                    return (
                        "storage",
                        "RULE_BLOCK_DEV_PARTITION",
                        f"Destructive sgdisk on {a} blocked",
                    )

    # 9. Destructive parted (without print or -l)
    if cmd.executable == "parted":
        if not ("print" in cmd.args or "-l" in cmd.args or "--list" in cmd.args):
            for a in cmd.args:
                if not a.startswith("-") and dag.is_protected(a):
                    return (
                        "storage",
                        "RULE_BLOCK_DEV_PARTITION",
                        f"Destructive parted on {a} blocked",
                    )

    # 10. Low-level overwrite utilities (shred, badblocks -w)
    if cmd.executable in ("shred",) or (
        cmd.executable == "badblocks" and "-w" in cmd.args
    ):
        for a in cmd.args:
            if not a.startswith("-") and dag.is_protected(a):
                return (
                    "storage",
                    "RULE_BLOCK_DEV_RAW_WRITE",
                    f"Destructive disk overwrite {cmd.executable} on {a} blocked",
                )

    # 11. Cryptsetup erasing / formatting
    if cmd.executable == "cryptsetup":
        if any(
            sub in cmd.args
            for sub in ("erase", "luksFormat", "luksKillSlot", "luksErase", "format")
        ):
            for a in cmd.args:
                if not a.startswith("-") and dag.is_protected(a):
                    return (
                        "storage",
                        "RULE_BLOCK_DEV_PARTITION",
                        f"Destructive cryptsetup action on {a} blocked",
                    )

    # 12. Destructive LVM commands
    if cmd.executable in ("lvremove", "vgreduce", "vgremove", "pvremove"):
        return (
            "storage",
            "RULE_BLOCK_DEV_PARTITION",
            f"Destructive LVM action {cmd.raw_str} blocked",
        )

    # 13. Recursive root filesystem deletion (rm -rf /, rm -rf /sysroot, etc.)
    if cmd.executable in ("rm", "unlink"):
        if _is_recursive_delete(cmd.args):
            for arg in cmd.args:
                if not arg.startswith("-"):
                    target = os.path.normpath(arg)
                    if _is_critical_mountpoint(target, dag):
                        return (
                            "storage",
                            "RULE_FS_RECURSIVE_ROOT_DELETE",
                            f"Recursive deletion of critical mountpoint {target} blocked",
                        )

    # 14. Find with -delete targeting critical mountpoints
    if cmd.executable == "find":
        if any(a in cmd.args for a in ("-delete", "-exec", "-execdir")):
            for a in cmd.args:
                if not a.startswith("-"):
                    target = os.path.normpath(a)
                    if _is_critical_mountpoint(target, dag):
                        return (
                            "storage",
                            "RULE_FS_RECURSIVE_ROOT_DELETE",
                            f"Destructive find command on critical mountpoint {target} blocked",
                        )

    # 15. Plain (non-recursive) mutating ops whose target IS a critical
    #     mountpoint itself. Exact match only: descendants like /etc/fstab,
    #     /bin/ls or /var/tmp/x are owned by other rules/modules.
    #     Recursive rm/unlink excluded: rule 13 owns them, and its /boot
    #     carve-out keeps bootloader category ownership.
    if cmd.executable in ("rm", "unlink", "mv", "shred", "truncate") and not (
        cmd.executable in ("rm", "unlink") and _is_recursive_delete(cmd.args)
    ):
        for arg in cmd.args:
            if not arg.startswith("-") and _is_critical_mount_root(arg, dag):
                return (
                    "storage",
                    "RULE_FS_RECURSIVE_ROOT_DELETE",
                    f"Destructive {cmd.executable} on critical mountpoint "
                    f"{os.path.normpath(arg)} blocked",
                )

    # 16. Archive extraction / rsync write into a critical mountpoint (dest-only)
    dest_path: Optional[str] = None
    if cmd.executable in ("tar", "unzip"):
        flag = "-C" if cmd.executable == "tar" else "-d"
        for i, a in enumerate(cmd.args):
            if a == flag and i + 1 < len(cmd.args):
                dest_path = cmd.args[i + 1]
    elif cmd.executable == "rsync":
        non_flags = [a for a in cmd.args if not a.startswith("-")]
        if non_flags:
            dest_path = non_flags[-1]
    if dest_path is not None:
        target = os.path.normpath(dest_path)
        if _is_critical_mountpoint(target, dag):
            return (
                "storage",
                "RULE_FS_RECURSIVE_ROOT_DELETE",
                f"Extraction into critical mountpoint {target} blocked",
            )

    return None


def _is_recursive_delete(args: List[str]) -> bool:
    """Check if rm command has recursive (-r, -R, -rf, -fr, --recursive) flag."""
    recursive_flags = {"-r", "-R", "--recursive", "-rf", "-fr", "-rvf", "-rfv"}
    for arg in args:
        if arg in recursive_flags:
            return True
        if arg.startswith("-") and not arg.startswith("--"):
            # Check combined flags like -rf, -fr
            if "r" in arg[1:] or "R" in arg[1:]:
                return True
    return False


def _is_critical_mountpoint(path: str, dag: StorageDAG) -> bool:
    """Check if path is a critical mountpoint that should not be recursively deleted.

    /boot is delegated to bootloader guardrails (RULE_BOOTLOADER_TAMPERING).
    """
    if path.startswith("/boot"):
        return False

    # Exact matches for critical mounts
    if path in dag.CRITICAL_MOUNTS:
        return True

    # Root directory variants
    if path in ("/", "/."):
        return True

    # Wildcard variants: /*, /./*, //*
    if path.startswith("/") and all(c in "./*" for c in path[1:]):
        return True

    # Paths under critical mounts (e.g., /etc/passwd, /usr/lib)
    for mount in dag.CRITICAL_MOUNTS:
        if mount != "/" and (path == mount or path.startswith(mount + "/")):
            return True

    return False


def _is_critical_mount_root(path: str, dag: StorageDAG) -> bool:
    """Exact critical mountpoint root only (no descendants), for plain
    non-recursive mutating ops. /boot carve-out intentionally not applied:
    plain `rm /boot` must block here.
    """
    return os.path.normpath(path) in dag.CRITICAL_MOUNTS
