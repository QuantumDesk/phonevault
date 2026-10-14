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


def check_property(relative, assignment):
    for pattern, bad, message in property_rules:
        for match in pattern.finditer(assignment):
            if bad(match.group(1)):
                fail(f"{relative}: {message}: {match.group(0)}")


# A pre-authorised adb host key, whatever its source file is called: any
# install destination (PRODUCT_COPY_FILES src:dest, a Soong/Make module
# filename/stem) named adb_keys.
adb_keys_destination = re.compile(r":(?:\S*/)?adb_keys(?=\s|:|$)")
adb_keys_module = re.compile(r"""["'](?:[^"'\s]*/)?adb_keys["']|\bLOCAL_MODULE_STEM\s*:?=\s*adb_keys\b""")
# Property files the build installs: TARGET_<PARTITION>_PROP lists and
# PRODUCT_<PARTITION>_PROPERTIES entries that name a file.
property_file_reference = re.compile(r"^\s*(TARGET_\w*_PROP|PRODUCT_\w*_PROPERTIES)\s*[:+?]?=\s*(.*)$")
referenced_property_files = set()
installed_init_sources = set()
for path in makefiles:
    relative = path.relative_to(root).as_posix()
    for line in logical_lines(text_files[path]):
        if re.search(r"\b(PRODUCT_ADB_KEYS|WITH_ADB_INSECURE|ADB_INSECURE)\b", line):
            fail(f"{relative}: adb key/insecure-adb setting in release configuration: {line}")
        check_property(relative, line)
        if re.search(r"etc/init/[^\s:]*debug[^\s:]*\.rc", line, re.IGNORECASE):
            fail(f"{relative}: installs a debug init script: {line}")
        if adb_keys_destination.search(line) or adb_keys_module.search(line):
            fail(f"{relative}: installs a pre-authorised adb host key: {line}")
        reference = property_file_reference.match(line)
        if reference:
            for word in reference.group(2).split():
                if word.endswith(".prop"):
                    referenced_property_files.add((relative, word))
        for word in line.split():
            source, colon, destination = word.partition(":")
            if colon and (re.search(r"(^|/)etc/init/", destination) or destination.endswith(".rc")):
                installed_init_sources.add(source)
for path in (p for p in text_files if p.name in ("Android.bp", "Android.mk") or p.suffix == ".bp"):
    relative = path.relative_to(root).as_posix()
    body = re.sub(r"//[^\n]*|#[^\n]*", "", text_files[path])
    if adb_keys_module.search(body):
        fail(f"{relative}: installs a pre-authorised adb host key")

common = text_files.get(vault / "vendor/phonevault/config/common.mk", "")
if not re.search(r"(?m)^\s*persist\.sys\.usb\.config=none\s*$", common):
    fail("vendor/phonevault/config/common.mk must set persist.sys.usb.config=none")


def source_path(word):
    """Map a build-tree path (vendor/phonevault/..., device/phonevault/...) into the repository."""
    word = word.strip()
    for prefix in ("vendor/phonevault/", "device/phonevault/"):
        if word.startswith(prefix):
            return vault / word
    return None


# Property files are parsed the way Android init reads them
# (property_service.cpp LoadProperties): whitespace around the key, '=' and the
# value is stripped and '#' starts a comment only at the start of a line.
property_files = {p for p in text_files if p.suffix == ".prop"}
for makefile, word in sorted(referenced_property_files):
    mapped = source_path(word)
    if mapped is None or not mapped.is_file():
        fail(f"{makefile}: release property file is not in the release configuration: {word}")
    else:
        property_files.add(mapped)
whitespace = " \t\n\v\f\r"
for path in sorted(property_files):
    relative = path.relative_to(root).as_posix()
    text = text_files.get(path)
    if text is None:
        fail(f"{relative}: release property file is not text")
        continue
    for number, raw in enumerate(text.split("\n"), 1):
        key = raw.strip(whitespace)
        if not key or key.startswith("#"):
            continue
        if key.startswith("import "):
            fail(f"{relative}:{number}: property import in release configuration: {key}")
            continue
        name, equals, value = key.partition("=")
        if not equals:
            continue
        check_property(f"{relative}:{number}", f"{name.rstrip(whitespace)}={value.lstrip(whitespace)}")


def init_lines(text):
    """Android init tokenizer (init/tokenizer.cpp): yields (line, args, raw).
    Backslash-newline continues a line, quotes group, '#' at a token start
    comments out the rest of the line."""
    data = text + "\n"
    n = len(data)
    pos = 0
    line = 1
    start_line = 1
    args = []
    line_start = 0
    while pos < n:
        c = data[pos]
        if c == "\n":
            if args:
                yield start_line, args, data[line_start:pos]
            pos += 1
            line += 1
            start_line = line
            args = []
            line_start = pos
            continue
        if c in " \t\r":
            pos += 1
            continue
        if c == "#":
            while pos < n and data[pos] != "\n":
                pos += 1
            continue
        token = []
        while pos < n:
            c = data[pos]
            if c in " \t\r":
                pos += 1
                break
            if c == "\n":
                break
            if c == '"':
                pos += 1
                while pos < n and data[pos] != '"':
                    if data[pos] == "\n":
                        line += 1
                    token.append(data[pos])
                    pos += 1
                if pos >= n:
                    return
                pos += 1
                continue
            if c == "\\":
                pos += 1
                if pos >= n:
                    break
                escaped = data[pos]
                if escaped in "nrt\\":
                    token.append({"n": "\n", "r": "\r", "t": "\t", "\\": "\\"}[escaped])
                    pos += 1
                elif escaped == "\r" and data[pos + 1: pos + 2] != "\n":
                    pos += 1
                elif escaped in "\r\n":
                    pos += 2 if escaped == "\r" else 1
                    line += 1
                    while pos < n and data[pos] in " \t":
                        pos += 1
                else:
                    token.append(escaped)
                    pos += 1
                continue
            token.append(c)
            pos += 1
        args.append("".join(token))


WRITABLE_MOUNTS = {"data", "cache", "mnt", "metadata", "persist", "sdcard", "storage", "tmp",
                   "dev", "sys", "proc", "config", "acct", "debug_ramdisk",
                   "second_stage_resources", "linkerconfig", "data_mirror", "efs"}


def init_violations(relative, text):
    """Section keywords (on/service/import) count at any indentation
    (init/parser.cpp); `enable`/`exec_start` start a service like `start`; init
    property-expands every builtin argument, so an expanded service name or USB
    function value is treated as adbd/adb."""
    section = ""
    trigger = ""
    trigger_args = []
    for number, args, raw in init_lines(text):
        shown = re.sub(r"\\\r?\n[ \t]*", " ", raw).strip()
        keyword = args[0]
        if keyword in ("on", "service", "import"):
            section = keyword
            trigger, trigger_args = (shown, args) if keyword == "on" else ("", [])
            if keyword == "service" and len(args) > 2 and re.search(r"(^|/)adbd$", args[2]):
                yield f"{relative}:{number}: release configuration defines an adbd service"
            if keyword == "import":
                target = args[1] if len(args) > 1 else ""
                top = target.lstrip("/").split("/", 1)[0]
                if "$" in target or top in WRITABLE_MOUNTS or not target.startswith("/"):
                    yield f"{relative}:{number}: release init script imports from a writable or unresolved location: {shown}"
            continue
        if section != "on":
            continue
        debuggable = "property:ro.debuggable=1" in trigger_args
        command = " ".join(args)
        if keyword in ("start", "restart", "enable", "exec_start") and len(args) > 1 \
                and (args[1] == "adbd" or "$" in args[1]):
            yield f"{relative}:{number}: release init script starts adbd: [{trigger}] {shown}"
        elif keyword in ("exec", "exec_background") and any(re.search(r"(^|/)adbd$", a) for a in args[1:]):
            yield f"{relative}:{number}: release init script starts adbd: [{trigger}] {shown}"
        elif re.search(r"functions/ffs\.adb|/dev/usb-ffs/adb|functionfs\s+adb", command) and not debuggable:
            yield f"{relative}:{number}: ADB endpoint outside a ro.debuggable=1 trigger: [{trigger}] {shown}"
        elif keyword == "setprop" and len(args) > 2 and not debuggable \
                and (re.match(r"(persist\.)?(sys|vendor)\.usb\.config$", args[1]) or "$" in args[1]) \
                and ("adb" in args[2].lower() or "$" in args[2]):
            yield f"{relative}:{number}: init selects adb as USB function: [{trigger}] {shown}"


init_files = {p for p in text_files if p.suffix == ".rc"}
for word in installed_init_sources:
    mapped = source_path(word)
    if mapped is not None and mapped in text_files:
        init_files.add(mapped)
for path in sorted(init_files):
    for violation in init_violations(path.relative_to(root).as_posix(), text_files[path]):
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
