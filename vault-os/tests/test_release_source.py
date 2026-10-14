"""vaultgates.release_source: init and property rules of the release-source gate (the whole
gate runs end to end in test-release-gates.sh and test-release-gate-gaps.sh)."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from vaultgates.release_source import init_violations, logical_lines, property_violations  # noqa: E402


def violations(text):
    return list(init_violations("vault.rc", text))


class InitRulesTest(unittest.TestCase):
    def test_start_enable_exec_start(self):
        for keyword in ("start", "restart", "enable", "exec_start"):
            with self.subTest(keyword=keyword):
                self.assertEqual(violations(f"on property:sys.boot_completed=1\n    {keyword} adbd\n"),
                                 [f"vault.rc:2: release init script starts adbd: "
                                  f"[on property:sys.boot_completed=1] {keyword} adbd"])

    def test_expanded_service_name_counts_as_adbd(self):
        self.assertEqual(len(violations("on boot\n    start ${ro.vendor.svc}\n")), 1)

    def test_indented_on_ends_the_debuggable_block(self):
        text = ("on property:ro.debuggable=1\n    write /dev/null 0\n  on boot\n"
                "    mkdir /dev/usb-ffs/adb 0770 shell shell\n")
        self.assertEqual(violations(text), [
            "vault.rc:4: ADB endpoint outside a ro.debuggable=1 trigger: [on boot] "
            "mkdir /dev/usb-ffs/adb 0770 shell shell"])

    def test_endpoint_inside_the_debuggable_trigger_is_allowed(self):
        self.assertEqual(violations("on property:ro.debuggable=1\n    mkdir /dev/usb-ffs/adb 0770 shell shell\n"), [])

    def test_continuation_keeps_the_starting_line_number(self):
        self.assertEqual(violations("on boot\n    start \\\n        adbd\n"),
                         ["vault.rc:2: release init script starts adbd: [on boot] start  adbd"])

    def test_setprop_adb_and_expanded_values(self):
        self.assertEqual(len(violations("on boot\n    setprop persist.sys.usb.config adb\n")), 1)
        self.assertEqual(len(violations("on boot\n    setprop sys.usb.config ${x}\n")), 1)
        self.assertEqual(violations("on boot\n    setprop sys.usb.config mtp\n"), [])

    def test_adbd_service_and_writable_import(self):
        self.assertEqual(violations("service a /system/bin/adbd\nimport /data/x.rc\nimport x.rc\n"), [
            "vault.rc:1: release configuration defines an adbd service",
            "vault.rc:2: release init script imports from a writable or unresolved location: import /data/x.rc",
            "vault.rc:3: release init script imports from a writable or unresolved location: import x.rc"])


class PropertyRulesTest(unittest.TestCase):
    def test_rules(self):
        self.assertEqual(list(property_violations("f", "persist.sys.usb.config=none")), [])
        # persist.sys.usb.config=adb breaks both USB rules.
        self.assertEqual(list(property_violations("f", "persist.sys.usb.config=adb")), [
            "f: persist.sys.usb.config must be none in release configuration: persist.sys.usb.config=adb",
            "f: USB configuration property enables adb: sys.usb.config=adb"])
        self.assertEqual(len(list(property_violations("f", "ro.adb.secure=0"))), 1)
        self.assertEqual(len(list(property_violations("f", "ro.debuggable=1 ro.force.debuggable=1"))), 2)

    def test_logical_lines(self):
        self.assertEqual(list(logical_lines("A := \\\n  b # c\n# d\n\nE=f\n")), ["A :=    b", "E=f"])


if __name__ == "__main__":
    unittest.main()
