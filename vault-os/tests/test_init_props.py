"""vaultgates.init_props: Android init property-file parsing and ExpandProps."""

import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from vaultgates import init_props  # noqa: E402
from vaultgates.init_props import UNRESOLVED, build_time_constant, expand  # noqa: E402


class PropertyLineTest(unittest.TestCase):
    def test_whitespace_around_key_equals_and_value_is_stripped(self):
        for raw in ("ro.adb.secure = 0", "  ro.adb.secure=0", "\tro.adb.secure =\t0 \r",
                    "ro.adb.secure=0"):
            with self.subTest(raw=raw):
                key = init_props.property_key(raw)
                self.assertEqual(init_props.split_assignment(key), ("ro.adb.secure", "0"))

    def test_comment_only_at_line_start(self):
        self.assertIsNone(init_props.property_key("# ro.debuggable=1"))
        self.assertIsNone(init_props.property_key("   # ro.debuggable=1"))
        self.assertIsNone(init_props.property_key(" \t "))
        key = init_props.property_key("ro.debuggable=1 # not a comment")
        self.assertEqual(init_props.split_assignment(key), ("ro.debuggable", "1 # not a comment"))

    def test_line_without_equals_is_not_an_assignment(self):
        self.assertIsNone(init_props.split_assignment("ro.debuggable"))

    def test_value_may_contain_equals(self):
        self.assertEqual(init_props.split_assignment("a.b=c=d"), ("a.b", "c=d"))

    def test_import_with_and_without_filter(self):
        self.assertEqual(init_props.split_import("import /vendor/etc/vault.prop"),
                         ("/vendor/etc/vault.prop", ""))
        self.assertEqual(init_props.split_import("import   /vendor/etc/vault.prop   ro.adb.*"),
                         ("/vendor/etc/vault.prop", "ro.adb.*"))
        self.assertIsNone(init_props.split_import("imports=1"))
        self.assertIsNone(init_props.split_import("import.x=1"))

    def test_filter(self):
        self.assertTrue(init_props.matches_filter("ro.adb.secure", ""))
        self.assertTrue(init_props.matches_filter("ro.adb.secure", "ro.adb.*"))
        self.assertTrue(init_props.matches_filter("ro.adb.secure", "ro.adb.secure"))
        self.assertFalse(init_props.matches_filter("ro.adb.secure", "ro.adb"))
        self.assertFalse(init_props.matches_filter("ro.debuggable", "ro.adb.*"))

    def test_never_applied_from_a_file(self):
        self.assertFalse(init_props.applied_from_file("ctl.start"))
        self.assertFalse(init_props.applied_from_file("sys.powerctl"))
        self.assertTrue(init_props.applied_from_file("ro.adb.secure"))

    def test_parse_properties_in_file_order(self):
        text = "\n".join([
            "# header",
            " ro.debuggable = 0 ",
            "import /vendor/etc/vault.prop ro.*",
            "garbage line",
            "persist.sys.usb.config=none",
        ])
        self.assertEqual(list(init_props.parse_properties(text)), [
            ("property", "ro.debuggable", "0"),
            ("import", "/vendor/etc/vault.prop", "ro.*"),
            ("property", "persist.sys.usb.config", "none"),
        ])


class ExpandTest(unittest.TestCase):
    properties = {"ro.vendor.vault.svc": "adbd", "ro.empty": "", "ro.indirect": "${x}",
                  "vendor.mutable": "adb", "ro.boot.vault": "adbd"}

    def run_expand(self, text):
        return expand(text, self.properties, build_time_constant)

    def test_braced_name(self):
        self.assertEqual(self.run_expand("${ro.vendor.vault.svc}"), ("adbd", []))

    def test_default_applies_to_an_empty_value(self):
        self.assertEqual(self.run_expand("${ro.empty:-none}"), ("none", []))

    def test_dollar_escape_and_plain_text(self):
        self.assertEqual(self.run_expand("a$$b"), ("a$b", []))

    def test_unbraced_name_runs_to_the_end(self):
        self.assertEqual(self.run_expand("x$ro.vendor.vault.svc"), ("xadbd", []))

    def test_mutable_and_runtime_first_properties_are_unresolved(self):
        for name in ("vendor.mutable", "ro.boot.vault", "ro.missing", "ro.indirect"):
            with self.subTest(name=name):
                value, unresolved = self.run_expand("${" + name + "}")
                self.assertEqual((value, unresolved), (UNRESOLVED, [name]))

    def test_unterminated_brace_is_unresolved(self):
        value, unresolved = self.run_expand("a${ro.x")
        self.assertEqual(value, "a" + UNRESOLVED)
        self.assertEqual(unresolved, ["${ro.x"])

    def test_build_time_constant(self):
        self.assertTrue(build_time_constant("ro.vendor.vault.usb"))
        for name in ("ro.boot.serialno", "ro.kernel.qemu", "ro.hardware", "ro.serialno",
                     "persist.sys.usb.config", "vendor.vault.usb"):
            with self.subTest(name=name):
                self.assertFalse(build_time_constant(name))


if __name__ == "__main__":
    unittest.main()
