#!/usr/bin/env bash
# Release-source gate: the release configuration (vault-os/vendor/phonevault,
# vault-os/device/phonevault) carries no development deviation. Run by
# install-overlay.sh before a release tree is prepared and by sign-release.sh
# before anything is signed.
#   verify-release-source.sh [REPOSITORY_ROOT]
#
# Development-only settings (adb as the default USB function, insecure adb,
# pre-authorised adb keys, early-boot adb init scripts, DEBUG-NN bisection
# markers, backup copies of release files) belong in vault-os/dev-ladder*/
# rung directories only. 2026-08/10: a DEBUG-38 `persist.sys.usb.config=adb`
# and a DEBUG-41 early-adbd init script sat in the release common.mk, next to
# tracked *.rel-bak / *.b38-bak copies.
set -euo pipefail

REPOSITORY_ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 - "${REPOSITORY_ROOT}" <<'PY'
import pathlib
import re
import sys

root = pathlib.Path(sys.argv[1]).resolve()
vault = root / "vault-os"
release_dirs = [vault / "vendor/phonevault", vault / "device/phonevault"]
errors = []


def fail(message):
    errors.append(message)


for directory in release_dirs:
    if not directory.is_dir():
        fail(f"missing release configuration directory: {directory.relative_to(root)}")

files = sorted(
    path
    for directory in release_dirs
    if directory.is_dir()
    for path in directory.rglob("*")
    if path.is_file() and "keys" not in path.relative_to(directory).parts[:1]
)

forbidden_names = re.compile(
    r"(\.|-|_)(bak|orig|rej|old|tmp)$|~$|\.swp$|zzz-debug|debug_adbkey|(^|/)adb_?keys?(\.pub)?$",
    re.IGNORECASE,
)
for path in files:
    relative = path.relative_to(root).as_posix()
    if forbidden_names.search(path.name) or "zzz-debug" in relative:
        fail(f"development leftover file in release configuration: {relative}")

# Bisection markers used while the boot was being debugged (DEBUG-38, DEBUG48, ...).
debug_marker = re.compile(r"\bDEBUG-?[0-9]+|\bDEBUG-")
text_files = {}
for path in files:
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        continue
    text_files[path] = text
    relative = path.relative_to(root).as_posix()
    for number, line in enumerate(text.splitlines(), 1):
        if debug_marker.search(line):
            fail(f"{relative}:{number}: development marker in release configuration: {line.strip()}")


def logical_lines(text):
    """Make logical lines: join backslash continuations, drop comments."""
    joined = re.sub(r"\\\n", " ", text)
    for line in joined.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


makefiles = [p for p in text_files if p.suffix == ".mk"]
property_rules = [
    (re.compile(r"\bpersist\.sys\.usb\.config=(\S*)"), lambda v: v != "none",
     "persist.sys.usb.config must be none in release configuration"),
    (re.compile(r"\b(?:sys|vendor|persist\.vendor)\.usb\.config=(\S*)"), lambda v: "adb" in v.lower(),
     "USB configuration property enables adb"),
    (re.compile(r"\bro\.adb\.secure=(\S*)"), lambda v: v != "1",
     "ro.adb.secure must not be relaxed"),
    (re.compile(r"\bro\.(?:force\.)?debuggable=(\S*)"), lambda v: v != "0",
     "release configuration must not make the build debuggable"),
    (re.compile(r"\bpersist\.adb\.notify=(\S*)"), lambda v: True,
     "persist.adb.notify is a development setting"),
    (re.compile(r"\bservice\.adb\.(?:root|tcp\.port)=(\S*)"), lambda v: True,
     "adb root/TCP properties are development settings"),
]
for path in makefiles:
    relative = path.relative_to(root).as_posix()
    for line in logical_lines(text_files[path]):
        if re.search(r"\b(PRODUCT_ADB_KEYS|WITH_ADB_INSECURE|ADB_INSECURE)\b", line):
            fail(f"{relative}: adb key/insecure-adb setting in release configuration: {line}")
        for pattern, bad, message in property_rules:
            for match in pattern.finditer(line):
                if bad(match.group(1)):
                    fail(f"{relative}: {message}: {match.group(0)}")
        if re.search(r"etc/init/[^\s:]*debug[^\s:]*\.rc", line, re.IGNORECASE):
            fail(f"{relative}: installs a debug init script: {line}")

common = text_files.get(vault / "vendor/phonevault/config/common.mk", "")
if not re.search(r"(?m)^\s*persist\.sys\.usb\.config=none\s*$", common):
    fail("vendor/phonevault/config/common.mk must set persist.sys.usb.config=none")


def init_violations(relative, text):
    trigger = ""
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():
            trigger = line if line.startswith("on ") else ""
            if line.startswith("service ") and re.search(r"(^|/)adbd(\s|$)", line.split()[2] if len(line.split()) > 2 else ""):
                yield f"{relative}:{number}: release configuration defines an adbd service"
            continue
        debuggable = "property:ro.debuggable=1" in trigger
        if re.match(r"\s+(start|restart)\s+adbd\b", line):
            yield f"{relative}:{number}: release init script starts adbd: [{trigger}] {line.strip()}"
        elif re.search(r"functions/ffs\.adb|/dev/usb-ffs/adb|functionfs\s+adb", line) and not debuggable:
            yield f"{relative}:{number}: ADB endpoint outside a ro.debuggable=1 trigger: [{trigger}] {line.strip()}"
        elif re.match(r"\s+setprop\s+(persist\.)?(sys|vendor)\.usb\.config\s+\S*adb", line) and not debuggable:
            yield f"{relative}:{number}: init selects adb as USB function: [{trigger}] {line.strip()}"


for path, text in text_files.items():
    if path.suffix == ".rc":
        for violation in init_violations(path.relative_to(root).as_posix(), text):
            fail(violation)

# Project-owned, monotonically increasing AVB rollback index.
version_mk = text_files.get(vault / "vendor/phonevault/config/release-version.mk", "")
index_match = re.search(r"(?m)^PHONEVAULT_AVB_ROLLBACK_INDEX\s*:=\s*([0-9]+)\s*$", version_mk)
if index_match is None:
    fail("release-version.mk must define PHONEVAULT_AVB_ROLLBACK_INDEX := <integer>")
elif not re.fullmatch(r"20[0-9]{2}(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])[0-9]{2}", index_match.group(1)):
    fail("PHONEVAULT_AVB_ROLLBACK_INDEX must be YYYYMMDDNN")
board = text_files.get(vault / "vendor/phonevault/config/BoardConfigVault.mk", "")
for required in (
    "include vendor/phonevault/config/release-version.mk",
    "BOARD_AVB_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)",
):
    if required not in board:
        fail(f"BoardConfigVault.mk lacks: {required}")

# No kiosk escape through the keyguard Emergency button.
core_overlay = text_files.get(
    vault / "vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml", "")
for resource in ("config_voice_capable", "config_sms_capable"):
    if not re.search(rf'<bool name="{resource}">false</bool>', core_overlay):
        fail(f"framework overlay must set {resource}=false")

# Recovery must not offer "Install anyway?" / recovery ADB on user builds.
recovery_patches = sorted((vault / "patches/bootable-recovery").glob("*.patch"))
if not any("PhoneVaultDevelopmentOverridesAllowed" in p.read_text(encoding="utf-8")
           for p in recovery_patches):
    fail("patches/bootable-recovery lacks the user-build recovery hardening patch")
installer = (vault / "scripts/install-overlay.sh")
if installer.is_file() and "patches/bootable-recovery" not in installer.read_text(encoding="utf-8"):
    fail("install-overlay.sh does not apply patches/bootable-recovery")

if errors:
    print("release source gate failed:", file=sys.stderr)
    for error in errors:
        print(f"  {error}", file=sys.stderr)
    raise SystemExit(1)
print(f"Release source gate passed: {len(files)} release configuration files checked.")
PY
