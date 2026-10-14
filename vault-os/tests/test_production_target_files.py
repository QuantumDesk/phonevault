"""vaultgates.production_target_files: the init model behind verify-production-target-files.sh
(the cases test-release-gate-gaps.sh attacks end to end, checked at the module level)."""

import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from vaultgates import production_target_files  # noqa: E402

BASELINE = {
    "META/misc_info.txt": "build_type=user\n",
    "SYSTEM/build.prop": "ro.system.build.tags=release-keys\npersist.sys.usb.config=none\n",
    "VENDOR/build.prop": "ro.vendor.build.tags=release-keys\n",
    "PRODUCT/etc/build.prop": "ro.product.build.tags=release-keys\n",
    "BOOT/RAMDISK/prop.default": "ro.debuggable=0\nro.secure=1\nro.adb.secure=1\n",
    "SYSTEM/etc/init/hw/init.usb.rc":
        "service adbd /system/bin/adbd --root_seclabel=u:r:su:s0\n    class core\n    disabled\n",
}
VAULT_RC = "VENDOR/etc/init/vault.rc"


def model(changes=None, remove=()):
    """Run the module on BASELINE with `changes` appended to (or creating) files and the
    paths in `remove` deleted. Returns (exit code, property occurrences, effective
    properties, init report, stderr)."""
    files = {path: text for path, text in BASELINE.items() if path not in remove}
    for path, text in (changes or {}).items():
        files[path] = files.get(path, "") + text
    with tempfile.TemporaryDirectory() as directory:
        root = pathlib.Path(directory)
        archive = root / "target_files.zip"
        with zipfile.ZipFile(archive, "w") as handle:
            for path, text in files.items():
                handle.writestr(path, text)
        outputs = [root / name for name in ("properties", "effective", "init")]
        for output in outputs:
            output.write_text("")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            code = production_target_files.main([str(archive)] + [str(o) for o in outputs])
        properties, effective, report = (o.read_text().splitlines() for o in outputs)
    effective = dict(line.split("=", 1) for line in effective)
    return code, properties, effective, report, stderr.getvalue()


def effective_of(changes):
    return model(changes)[2]


def report_of(rc_text, changes=None):
    return model(dict(changes or {}, **{VAULT_RC: rc_text}))[3]


class PropertyFilesTest(unittest.TestCase):
    def test_baseline(self):
        code, properties, effective, report, stderr = model()
        self.assertEqual((code, report, stderr), (0, [], ""))
        self.assertEqual(effective["ro.adb.secure"], "1")
        self.assertIn("persist.sys.usb.config=none", properties)

    def test_whitespace_around_equals_overrides_the_boot_ramdisk(self):
        _code, properties, effective, _report, _err = model({"VENDOR/build.prop": "ro.adb.secure = 0\n"})
        self.assertEqual(effective["ro.adb.secure"], "0")
        self.assertIn("ro.adb.secure=0", properties)

    def test_leading_whitespace(self):
        self.assertEqual(effective_of({"ODM/etc/build.prop": "  ro.adb.secure=0\n"})["ro.adb.secure"], "0")

    def test_partition_precedence(self):
        # product is loaded after vendor, vendor after system and the boot ramdisk; for ro.*
        # too (write-once applies only to values set before the files are loaded).
        effective = effective_of({"SYSTEM/build.prop": "ro.vault.order=system\n",
                                  "VENDOR/build.prop": "ro.vault.order=vendor\n",
                                  "PRODUCT/etc/build.prop": "ro.vault.order=product\n"})
        self.assertEqual(effective["ro.vault.order"], "product")
        self.assertEqual(effective_of({"PRODUCT/etc/build.prop": "ro.debuggable = 1\n"})["ro.debuggable"], "1")

    def test_debug_ramdisk_property_file_is_loaded_last(self):
        effective = effective_of({"BOOT/RAMDISK/adb_debug.prop": "ro.debuggable=1\n",
                                  "PRODUCT/etc/build.prop": "ro.debuggable=0\n"})
        self.assertEqual(effective["ro.debuggable"], "1")

    def test_import_loads_a_property_file_of_any_name(self):
        _code, properties, effective, _report, _err = model({
            "VENDOR/build.prop": "import /vendor/etc/vault.prop\n",
            "VENDOR/etc/vault.prop": "ro.debuggable=1\npersist.sys.usb.config=adb\n"})
        self.assertEqual(effective["ro.debuggable"], "1")
        self.assertIn("persist.sys.usb.config=adb", properties)

    def test_import_filter(self):
        properties = model({"VENDOR/build.prop": "import /vendor/etc/vault.prop ro.adb.*\n",
                            "VENDOR/etc/vault.prop": "ro.adb.secure=0\nro.debuggable=1\n"})[1]
        self.assertIn("ro.adb.secure=0", properties)
        self.assertNotIn("ro.debuggable=1", properties)

    def test_import_from_a_writable_location_fails(self):
        code, _props, _effective, _report, stderr = model(
            {"VENDOR/build.prop": "import /data/local/tmp/vault.prop\n"})
        self.assertEqual(code, 1)
        self.assertEqual(stderr, "production property file VENDOR/build.prop imports from outside "
                                 "the image: import /data/local/tmp/vault.prop\n")

    def test_no_property_files(self):
        code, _props, _effective, _report, stderr = model(
            remove=[path for path in BASELINE if path.endswith((".prop", "prop.default"))])
        self.assertEqual(code, 1)
        self.assertEqual(stderr, "production target-files lacks installed property files\n")


class InitFilesTest(unittest.TestCase):
    def test_enable_and_exec_start_count_like_start(self):
        for keyword in ("start", "restart", "enable", "exec_start"):
            with self.subTest(keyword=keyword):
                self.assertEqual(report_of(f"on boot\n    {keyword} adbd\n"),
                                 [f"{VAULT_RC}: [on boot]     {keyword} adbd"])

    def test_exec_of_the_adbd_binary(self):
        self.assertEqual(len(report_of("on boot\n    exec_background - root -- /system/bin/adbd\n")), 1)

    def test_line_continuation(self):
        self.assertEqual(report_of("on boot\n    start \\\n        adbd\n"),
                         [f"{VAULT_RC}: [on boot]     start  adbd"])

    def test_indented_section_after_a_service(self):
        self.assertEqual(report_of("service vaultd /system/bin/true\n    oneshot\n  on boot\n    start adbd\n"),
                         [f"{VAULT_RC}: [on boot]     start adbd"])

    def test_imported_init_file_outside_etc_init(self):
        self.assertEqual(report_of("import /vendor/etc/vault/adb.rc\n",
                                   {"VENDOR/etc/vault/adb.rc": "on boot\n    start adbd\n"}),
                         ["VENDOR/etc/vault/adb.rc: [on boot]     start adbd"])

    def test_import_from_a_writable_location(self):
        self.assertEqual(report_of("import /data/vault.rc\n"),
                         [f"{VAULT_RC}: imports an init file from outside the image: import /data/vault.rc"])

    def test_property_expansion(self):
        start = "on boot\n    start ${ro.vendor.vault.svc}\n"
        self.assertEqual(len(report_of(start, {"VENDOR/build.prop": "ro.vendor.vault.svc=adbd\n"})), 1)
        self.assertEqual(report_of(start, {"VENDOR/build.prop": "ro.vendor.vault.svc=vaultd\n"}), [])
        setprop = "on boot\n    setprop persist.sys.usb.config ${ro.vendor.vault.usb}\n"
        self.assertEqual(len(report_of(setprop, {"VENDOR/build.prop": "ro.vendor.vault.usb=adb\n"})), 1)
        self.assertEqual(report_of(setprop, {"VENDOR/build.prop": "ro.vendor.vault.usb=mtp\n"}), [])
        # A runtime-first or mutable property cannot be resolved: it counts as adbd / adb.
        self.assertEqual(len(report_of("on boot\n    start ${ro.boot.vault_svc}\n")), 1)
        self.assertEqual(len(report_of("on boot\n    setprop sys.usb.config ${vendor.usb:-none}\n")), 1)

    def test_debuggable_and_usb_function_triggers(self):
        self.assertEqual(report_of("on property:ro.debuggable=1\n    start adbd\n"), [])
        self.assertEqual(report_of("on property:sys.usb.config=adb && property:sys.usb.configfs=1\n"
                                   "    start adbd\n"), [])
        self.assertEqual(len(report_of("on boot && property:sys.usb.configfs=1\n    start adbd\n")), 1)
        self.assertEqual(len(report_of("on property:ro.debuggable=*\n    mkdir /dev/usb-ffs/adb 0770 shell shell\n")), 1)

    def test_adbd_service(self):
        self.assertEqual(model()[3], [])
        self.assertEqual(report_of("service vaultadb /system/bin/adbd\n    class core\n"), [
            f"{VAULT_RC}: adbd service defined outside init.usb.rc: service vaultadb /system/bin/adbd",
            f"{VAULT_RC}: adbd service is not disabled: service vaultadb /system/bin/adbd"])
        usb_rc = "SYSTEM/etc/init/hw/init.usb.rc"
        report = model({usb_rc: "service adbd /system/bin/adbd\n    class core\n"}, remove=[usb_rc])[3]
        self.assertEqual(report, [f"{usb_rc}: adbd service is not disabled: service adbd /system/bin/adbd"])


if __name__ == "__main__":
    unittest.main()
