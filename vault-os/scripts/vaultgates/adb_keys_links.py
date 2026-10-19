"""Which `adb_keys` entries of a target-files archive are real key files.

  vaultgate.py adb-keys-links TARGET_FILES < NAMES

Reads archive entry names (one per line) on stdin and prints those that must be treated as a
pre-authorised adb host key. An entry is inert, and not printed, only when it is a symlink to an
absolute path on a verified read-only partition (/product, /system, /system_ext, /vendor, /odm)
that does not exist anywhere in the image. AOSP's rootdir installs `/adb_keys ->
/product/etc/security/adb_keys` in the root and vendor_boot ramdisks on every build, user builds
included; without PRODUCT_ADB_KEYS its target is never installed, so adbd finds no key there, and
nothing at run time can create a file on a dm-verity partition. A regular file, a relative link,
or a link to a writable or unresolved location (/data, /metadata, ${...}) still counts.
"""

import sys

from vaultgates.production_target_files import TargetFiles

VERIFIED_READ_ONLY = {"product", "system", "system_ext", "vendor", "odm"}


def inert(image, name):
    info = image.entries.get(name)
    if info is None or not image.is_symlink(name):
        return False
    target = image.archive.read(name).decode("utf-8", "replace").strip()
    if not target.startswith("/") or "$" in target:
        return False
    top = target.lstrip("/").split("/", 1)[0]
    if top not in VERIFIED_READ_ONLY:
        return False
    return image.locate(target, image.tree_of(name)) == []


def main(argv):
    image = TargetFiles(argv[0])
    for line in sys.stdin:
        name = line.strip()
        if name and not inert(image, name):
            print(name)
    return 0
