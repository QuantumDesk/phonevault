"""vaultgates.overrides: Blueprint `overrides` parsing and the target-files absence check."""

import contextlib
import io
import pathlib
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "scripts"))

from vaultgates import overrides  # noqa: E402
from vaultgates.overrides import OverridesError, packaged, parse_overrides, remaining_apps  # noqa: E402

VAULT = pathlib.Path(__file__).resolve().parents[1]


class ParseTest(unittest.TestCase):
    def test_names_on_the_opening_line_count(self):
        # The line parsers this replaced dropped "A" and "B" here.
        text = 'android_app_import {\n    overrides: ["A", "B",\n        "C"],\n}\n'
        self.assertEqual(parse_overrides(text), ["A", "B", "C"])

    def test_one_line_list_does_not_swallow_later_strings(self):
        text = ('android_app_import {\n    overrides: ["A"],\n'
                '    required: ["NotAnOverride"],\n    name: "PhoneVault",\n}\n')
        self.assertEqual(parse_overrides(text), ["A"])

    def test_closing_bracket_after_a_name(self):
        text = 'x {\n    overrides: [\n        "A",\n        "B"],\n    required: ["R"],\n}\n'
        self.assertEqual(parse_overrides(text), ["A", "B"])

    def test_comments_are_not_entries(self):
        text = ('x {\n'
                '    // overrides: ["Commented"],\n'
                '    overrides: [\n'
                '        "A", // was "B"\n'
                '        /* "C", */\n'
                '        // "D",\n'
                '        "E",\n'
                '    ],\n'
                '}\n')
        self.assertEqual(parse_overrides(text), ["A", "E"])

    def test_every_list_in_the_file(self):
        text = 'a {\n    overrides: ["A"],\n}\nb {\n    overrides: [\n        "B",\n    ],\n}\n'
        self.assertEqual(parse_overrides(text), ["A", "B"])

    def test_only_the_overrides_property(self):
        text = 'x {\n    my_overrides: ["No"],\n    description: "overrides: [\\"No\\"]",\n}\n'
        self.assertEqual(parse_overrides(text), [])

    def test_no_active_list(self):
        self.assertEqual(parse_overrides('x {\n    // overrides: ["A"],\n}\n'), [])
        self.assertEqual(parse_overrides('x {\n    overrides: [],\n}\n'), [])

    def test_non_literal_entries_are_refused(self):
        for text in ('x { overrides: ["A"] + common }', 'x { overrides: ["A"] /* c */\n + ["B"] }',
                     'x { overrides: [common_list] }', 'x { overrides: ["A", ',
                     'x { overrides: ["A" /* unterminated'):
            with self.subTest(text=text):
                with self.assertRaises(OverridesError):
                    parse_overrides(text)

    def test_repository_lists_parse(self):
        release = overrides.read_overrides(VAULT / "vendor/phonevault/prebuilt/Android.bp")
        self.assertGreater(len(release), 100)
        self.assertEqual(len(release), len(set(release)))
        for blueprint in sorted(VAULT.glob("dev-ladder*/rung-*/Android.bp")):
            with self.subTest(blueprint=blueprint.relative_to(VAULT)):
                overrides.read_overrides(blueprint)


class PackagedTest(unittest.TestCase):
    entries = [
        "SYSTEM/app/Gallery2/Gallery2.apk",
        "SYSTEM_EXT/priv-app/TrebuchetQuickStep/lib/arm64/libx.so",
        "PRODUCT/overlay/IconPackKai/IconPackKaiOverlay.apk",
        "PRODUCT/overlay/Camera2__vault_bluejay__auto_generated_rro_product.apk",
        "VENDOR/bin/hw/android.hardware.nfc-service",
        "VENDOR/etc/vintf/manifest/nfc.xml",
        "SYSTEM/etc/permissions/android.software.webview.xml",
        "SYSTEM/app/Gallery2Extra/Gallery2Extra.apk",
        "META/overlay/Gallery2.apk",
    ]

    def test_app_dirs_overlays_and_rros(self):
        self.assertEqual(packaged("Gallery2", self.entries), ["SYSTEM/app/Gallery2/Gallery2.apk"])
        self.assertEqual(packaged("TrebuchetQuickStep", self.entries),
                         ["SYSTEM_EXT/priv-app/TrebuchetQuickStep/lib/arm64/libx.so"])
        self.assertEqual(packaged("IconPackKaiOverlay", self.entries),
                         ["PRODUCT/overlay/IconPackKai/IconPackKaiOverlay.apk"])
        self.assertEqual(packaged("Camera2", self.entries),
                         ["PRODUCT/overlay/Camera2__vault_bluejay__auto_generated_rro_product.apk"])

    def test_native_files_only_when_asked(self):
        for name, entry in (("android.hardware.nfc-service", "VENDOR/bin/hw/android.hardware.nfc-service"),
                            ("nfc.xml", "VENDOR/etc/vintf/manifest/nfc.xml"),
                            ("android.software.webview.prebuilt.xml",
                             "SYSTEM/etc/permissions/android.software.webview.xml")):
            with self.subTest(name=name):
                self.assertEqual(packaged(name, self.entries), [])
                self.assertEqual(packaged(name, self.entries, native=True), [entry])

    def test_remaining_apps(self):
        self.assertEqual(remaining_apps(self.entries),
                         ["SYSTEM/app/Gallery2", "SYSTEM/app/Gallery2Extra"])


class CheckTest(unittest.TestCase):
    def run_check(self, blueprint_text, entries, require=False):
        with tempfile.TemporaryDirectory() as directory:
            blueprint = pathlib.Path(directory, "Android.bp")
            blueprint.write_text(blueprint_text)
            archive = pathlib.Path(directory, "target_files.zip")
            with zipfile.ZipFile(archive, "w") as handle:
                for entry in entries:
                    handle.writestr(entry, "x")
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = overrides.check(str(blueprint), str(archive), require_overrides=require)
            return code, stdout.getvalue(), stderr.getvalue()

    def test_survivor_fails_with_its_apk(self):
        code, out, _err = self.run_check('x { overrides: ["Gallery2", "Music"] }',
                                         ["SYSTEM/app/Gallery2/Gallery2.apk",
                                          "SYSTEM/app/Gallery2/oat/arm64/Gallery2.odex"])
        self.assertEqual(code, 1)
        self.assertIn("2 active overrides; 1 APKs remain in the image:", out)
        self.assertIn("    Gallery2: SYSTEM/app/Gallery2/Gallery2.apk", out)

    def test_stale_leftover_is_reported(self):
        code, out, _err = self.run_check('x { overrides: ["Gallery2"] }',
                                         ["SYSTEM/app/Gallery2/lib/arm64/libjni.so"])
        self.assertEqual(code, 1)
        self.assertIn("(no APK: stale staging leftover)", out)

    def test_clean_image_passes(self):
        code, out, _err = self.run_check('x { overrides: ["Gallery2"] }',
                                         ["SYSTEM/app/PhoneVault/PhoneVault.apk"])
        self.assertEqual(code, 0)
        self.assertTrue(out.endswith("OK: no overridden module is packaged\n"))

    def test_empty_list_passes_for_a_dev_rung_and_fails_for_the_release(self):
        blueprint = 'x {\n    // overrides: ["Gallery2"],\n}\n'
        self.assertEqual(self.run_check(blueprint, ["SYSTEM/app/A/A.apk"])[0], 0)
        code, out, err = self.run_check(blueprint, ["SYSTEM/app/A/A.apk"], require=True)
        self.assertEqual((code, out), (1, ""))
        self.assertIn("FAIL: no active overrides found in", err)

    def test_command_line(self):
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(overrides.main([]), 2)
            self.assertEqual(overrides.main(["check", "a.bp"]), 2)
            self.assertEqual(overrides.main(["check", "a.bp", "tf.zip", "--other"]), 2)


if __name__ == "__main__":
    unittest.main()
