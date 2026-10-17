"""M4 adversarial tests: destabilization / sabotage commands (R7).

Plain unittest (pytest NOT installed).
Style mirrors tests/adversarial/test_m2_challenger.py.

Probe-based adjustments (see W7T report):
- KNOWN LIMITATION (documented): substitution-assembled argv (e.g.
  sh -c "$(echo chmod) 000 /usr/bin/ls") is not reassembled by the parser;
  direct/subshell payloads ARE blocked.
- `rm -rf /usr/lib64/libssl.so.3` is blocked but by RULE_FS_RECURSIVE_ROOT_DELETE
  (fires before RULE_LINKER_HIJACK) -> asserted as blocked-generic.
"""

import unittest

from src.guardrails.analyzer import evaluate_command


class TestM4Destabilization(unittest.TestCase):
    def _assert_blocked(self, cmd, rule):
        v = evaluate_command(cmd)
        self.assertFalse(v.allowed, f"NOT BLOCKED: {cmd}")
        self.assertEqual(v.matched_rule, rule, f"{cmd} -> {v.matched_rule}")

    def _assert_blocked_any_rule(self, cmd):
        v = evaluate_command(cmd)
        self.assertFalse(v.allowed, f"NOT BLOCKED: {cmd}")
        self.assertTrue(
            v.matched_rule is not None and v.matched_rule.startswith("RULE_"),
            f"{cmd} -> {v.matched_rule}",
        )

    def test_rule_boot_config_integrity(self):
        cases = [
            "rm -f /etc/fstab",
            "echo x > /etc/fstab",
            "sed -i s/a/b/ /etc/default/grub",
            "dd if=/dev/zero of=/boot/grub2/grub.cfg",
            "truncate -s 0 /boot/grub/grub.cfg",
            "cp /tmp/evil /etc/fstab",
            "shred /etc/fstab",
            "systemctl set-default rescue.target",
            "systemctl isolate emergency.target",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_BOOT_CONFIG_INTEGRITY")

    def test_rule_linker_hijack(self):
        cases = [
            "echo /tmp/evil.so > /etc/ld.so.preload",
            "rm -f /etc/ld.so.preload",
            "echo /usr/lib/evil >> /etc/ld.so.conf",
            "cp /tmp/evil.so /usr/lib/libc.so.6",
            "LD_PRELOAD=/tmp/x.so /usr/bin/sudo -l",
            "dd of=/etc/ld.so.preload",
            "echo x | dd of=/etc/ld.so.conf",
            "dd of=/usr/lib64/libc.so.6",
            "shred /etc/ld.so.preload",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_LINKER_HIJACK")
        # Blocked, but RULE_FS_RECURSIVE_ROOT_DELETE takes precedence over
        # RULE_LINKER_HIJACK for this path.
        with self.subTest(cmd="rm -rf /usr/lib64/libssl.so.3"):
            self._assert_blocked_any_rule("rm -rf /usr/lib64/libssl.so.3")

    def test_rule_process_integrity(self):
        cases = [
            "kill -9 1",
            "kill -SEGV 1",
            "kill -9 -1",
            "killall5",
            "echo x > /proc/sys/kernel/core_pattern",
            "sysctl -w kernel.modprobe=/tmp/x",
            "echo x > /proc/sys/vm/swappiness",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_PROCESS_INTEGRITY")

    def test_rule_recursive_perm_change(self):
        cases = [
            "chmod -R 777 /",
            "chown -R nobody /etc",
            "chmod -Rv 755 /usr",
            "chmod 000 /usr/bin/ls",
            "chmod -x /bin/bash",
            "chattr +i /etc/fstab",
            "chattr +i /usr/bin/ls",
            "chattr +i /bin/bash",
            "chattr +i /usr/sbin/sshd",
            "chattr +i /usr/lib/libc.so.6",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_RECURSIVE_PERM_CHANGE")

    def test_rule_package_state_destruction(self):
        cases = [
            "dnf remove systemd",
            "rpm -e glibc",
            "apt purge coreutils",
            "apt-get remove sudo",
            "dnf remove kernel-core",
            "rpm -e --nodeps bash",
            "dnf --releasever=40 downgrade systemd",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_PACKAGE_STATE_DESTRUCTION")

    def test_rule_persistence_tamper(self):
        cases = [
            "echo x > /etc/systemd/system/evil.service",
            "echo x > /etc/cron.d/evil",
            "echo x >> /etc/profile",
            "echo x > /root/.bashrc",
            "echo x > /etc/hosts",
            "journalctl --vacuum-time=1d",
            "history -c",
            "systemctl enable /tmp/evil.service",
            "systemctl link /tmp/evil.service",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_PERSISTENCE_TAMPER")

    def test_rule_mount_integrity(self):
        cases = [
            "mount -o remount,ro /",
            "mount --bind /tmp /etc",
            "mount -t tmpfs tmpfs /var",
            "umount /",
            "umount -l /usr",
            "umount /home",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, "RULE_MOUNT_INTEGRITY")

    def test_bypass_vectors_exact_rule(self):
        cases = [
            ("sudo bash -c 'echo pwned > /etc/fstab'", "RULE_BOOT_CONFIG_INTEGRITY"),
            ("bash -c 'echo x > /etc/ld.so.preload'", "RULE_LINKER_HIJACK"),
            ("echo x | tee /etc/fstab", "RULE_BOOT_CONFIG_INTEGRITY"),
            ("F=/etc/fstab; echo x > $F", "RULE_EVASION_UNRESOLVED_VAR"),
            ("cat /tmp/x | dd of=/etc/ld.so.preload", "RULE_LINKER_HIJACK"),
        ]
        for cmd, rule in cases:
            with self.subTest(cmd=cmd):
                self._assert_blocked(cmd, rule)

    def test_bypass_vectors_blocked_generic(self):
        cases = [
            "echo ZWNobyB4ID4gL2V0Yy9mc3RhYg== | base64 -d | sh",
            r"find /etc -name passwd -exec chmod 000 {} \;",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                v = evaluate_command(cmd)
                self.assertFalse(v.allowed, f"NOT BLOCKED: {cmd}")
                self.assertTrue(
                    v.matched_rule is not None and v.matched_rule.startswith("RULE_"),
                    f"{cmd} -> {v.matched_rule}",
                )

    def test_false_positives_allowed(self):
        cases = [
            "cat /etc/fstab",
            "grep -r foo /etc/systemd/system",
            "systemctl status sshd",
            "ls -la /etc/ld.so.cache",
            "dnf list installed",
            "chmod 755 /tmp/x",
            "cp /etc/fstab /tmp/backup",
            "install -m644 /etc/fstab /tmp/b",
            "shred /tmp/x",
            "chattr -i /tmp/x",
            "chattr +i /home/user/notes.txt",
            "systemctl enable sshd",
            "systemctl enable --now agent-root-runner",
            "systemctl enable /etc/systemd/system/agent-root-runner.service",
            "chown user:user /home/user/f",
            "cp /tmp/x /etc/systemd/system/agent-root-runner.service",
            "mount",
            "kill -9 12345",
            "dd if=/dev/zero of=/tmp/x",
            "systemctl set-default graphical.target",
            "cat /etc/ld.so.preload",
        ]
        for cmd in cases:
            with self.subTest(cmd=cmd):
                v = evaluate_command(cmd)
                self.assertTrue(v.allowed, f"FALSE POSITIVE: {cmd} -> {v.matched_rule}")
                self.assertIsNone(v.matched_rule, f"{cmd} -> {v.matched_rule}")


if __name__ == "__main__":
    unittest.main()
