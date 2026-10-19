"""Release-source gate: the release configuration (vault-os/vendor/phonevault,
vault-os/device/phonevault) carries no development deviation.

  vaultgate.py release-source REPOSITORY_ROOT [--bluejay-beta BETA]

With --bluejay-beta, the bluejay beta configuration release-bluejay/BETA is checked too, as it is
resolved for the build tree (its BASE chain down to a dev-ladder-bluejay rung, the beta's files
replacing the rung's): the effective common.mk / BoardConfigVault.mk / Android.bp get the same
adb, property, init and adb-key rules as the release configuration, plus the bluejay beta
invariants (beta AVB key, never the dev key; project rollback index; no serial/early console or
printk.devkmsg on the kernel command line; usbcore.authorized_default=0 kept; recovery hardening
applied by sync-beta.sh). config_voice_capable=false is reported, not required: rung b4d, the
first image to carry it, did not boot, so the first beta leaves it out (beta1-novoice tests it).

Development-only settings (adb as the default USB function, insecure adb, pre-authorised
adb keys, early-boot adb init scripts, DEBUG-NN bisection markers, backup copies of
release files such as *.rel-bak) belong in vault-os/dev-ladder*/ rung directories only.
"""

import pathlib
import re
import sys

from vaultgates import init_props
from vaultgates.init_rc import (
    ADB_ENDPOINT, ADBD_PATH, DEBUGGABLE_TRIGGER, EXEC_KEYWORDS, SECTION_KEYWORDS,
    START_KEYWORDS, display, init_lines)

FORBIDDEN_NAMES = re.compile(
    r"(\.|-|_)(bak|orig|rej|old|tmp)$|~$|\.swp$|zzz-debug|debug_adbkey|(^|/)adb_?keys?(\.pub)?$",
    re.IGNORECASE,
)
# Development markers (DEBUG-NN or DEBUGNN) tag experimental changes; none may remain in
# the release configuration.
DEBUG_MARKER = re.compile(r"\bDEBUG-?[0-9]+|\bDEBUG-")
PROPERTY_RULES = [
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
# A pre-authorised adb host key, whatever its source file is called: any install
# destination (PRODUCT_COPY_FILES src:dest, a Soong/Make module filename/stem) named
# adb_keys.
ADB_KEYS_DESTINATION = re.compile(r":(?:\S*/)?adb_keys(?=\s|:|$)")
ADB_KEYS_MODULE = re.compile(r"""["'](?:[^"'\s]*/)?adb_keys["']|\bLOCAL_MODULE_STEM\s*:?=\s*adb_keys\b""")
# Property files the build installs: TARGET_<PARTITION>_PROP lists and
# PRODUCT_<PARTITION>_PROPERTIES entries that name a file.
PROPERTY_FILE_REFERENCE = re.compile(r"^\s*(TARGET_\w*_PROP|PRODUCT_\w*_PROPERTIES)\s*[:+?]?=\s*(.*)$")
USB_CONFIG = re.compile(r"(persist\.)?(sys|vendor)\.usb\.config$")


def logical_lines(text):
    """Make logical lines: join backslash continuations, drop comments."""
    joined = re.sub(r"\\\n", " ", text)
    for line in joined.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            yield line


def property_violations(relative, assignment):
    for pattern, bad, message in PROPERTY_RULES:
        for match in pattern.finditer(assignment):
            if bad(match.group(1)):
                yield f"{relative}: {message}: {match.group(0)}"


def init_violations(relative, text):
    """Section keywords (on/service/import) count at any indentation (init/parser.cpp);
    `enable`/`exec_start` start a service like `start`; init property-expands every
    builtin argument, so an expanded service name or USB function value is treated as
    adbd/adb."""
    section = ""
    trigger = ""
    trigger_args = []
    for number, args, raw in init_lines(text):
        shown = display(raw).strip()
        keyword = args[0]
        if keyword in SECTION_KEYWORDS:
            section = keyword
            trigger, trigger_args = (shown, args) if keyword == "on" else ("", [])
            if keyword == "service" and len(args) > 2 and ADBD_PATH.search(args[2]):
                yield f"{relative}:{number}: release configuration defines an adbd service"
            if keyword == "import":
                target = args[1] if len(args) > 1 else ""
                top = target.lstrip("/").split("/", 1)[0]
                if "$" in target or top in init_props.WRITABLE_MOUNTS or not target.startswith("/"):
                    yield f"{relative}:{number}: release init script imports from a writable or unresolved location: {shown}"
            continue
        if section != "on":
            continue
        debuggable = DEBUGGABLE_TRIGGER in trigger_args
        command = " ".join(args)
        if keyword in START_KEYWORDS and len(args) > 1 \
                and (args[1] == "adbd" or "$" in args[1]):
            yield f"{relative}:{number}: release init script starts adbd: [{trigger}] {shown}"
        elif keyword in EXEC_KEYWORDS and any(ADBD_PATH.search(a) for a in args[1:]):
            yield f"{relative}:{number}: release init script starts adbd: [{trigger}] {shown}"
        elif ADB_ENDPOINT.search(command) and not debuggable:
            yield f"{relative}:{number}: ADB endpoint outside a ro.debuggable=1 trigger: [{trigger}] {shown}"
        elif keyword == "setprop" and len(args) > 2 and not debuggable \
                and (USB_CONFIG.match(args[1]) or "$" in args[1]) \
                and ("adb" in args[2].lower() or "$" in args[2]):
            yield f"{relative}:{number}: init selects adb as USB function: [{trigger}] {shown}"


def check(root):
    """Return (errors, number of release configuration files checked)."""
    vault = root / "vault-os"
    release_dirs = [vault / "vendor/phonevault", vault / "device/phonevault"]
    errors = []
    fail = errors.append

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

    for path in files:
        relative = path.relative_to(root).as_posix()
        if FORBIDDEN_NAMES.search(path.name) or "zzz-debug" in relative:
            fail(f"development leftover file in release configuration: {relative}")

    text_files = {}
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        text_files[path] = text
        relative = path.relative_to(root).as_posix()
        for number, line in enumerate(text.splitlines(), 1):
            if DEBUG_MARKER.search(line):
                fail(f"{relative}:{number}: development marker in release configuration: {line.strip()}")

    makefiles = [p for p in text_files if p.suffix == ".mk"]
    referenced_property_files = set()
    installed_init_sources = set()
    for path in makefiles:
        relative = path.relative_to(root).as_posix()
        for line in logical_lines(text_files[path]):
            if re.search(r"\b(PRODUCT_ADB_KEYS|WITH_ADB_INSECURE|ADB_INSECURE)\b", line):
                fail(f"{relative}: adb key/insecure-adb setting in release configuration: {line}")
            errors.extend(property_violations(relative, line))
            if re.search(r"etc/init/[^\s:]*debug[^\s:]*\.rc", line, re.IGNORECASE):
                fail(f"{relative}: installs a debug init script: {line}")
            if ADB_KEYS_DESTINATION.search(line) or ADB_KEYS_MODULE.search(line):
                fail(f"{relative}: installs a pre-authorised adb host key: {line}")
            reference = PROPERTY_FILE_REFERENCE.match(line)
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
        if ADB_KEYS_MODULE.search(body):
            fail(f"{relative}: installs a pre-authorised adb host key")

    common = text_files.get(vault / "vendor/phonevault/config/common.mk", "")
    if not re.search(r"(?m)^\s*persist\.sys\.usb\.config=none\s*$", common):
        fail("vendor/phonevault/config/common.mk must set persist.sys.usb.config=none")

    def source_path(word):
        """Map a build-tree path (vendor/phonevault/..., device/phonevault/...) into the
        repository."""
        word = word.strip()
        for prefix in ("vendor/phonevault/", "device/phonevault/"):
            if word.startswith(prefix):
                return vault / word
        return None

    # Property files are parsed the way Android init reads them (init_props).
    property_files = {p for p in text_files if p.suffix == ".prop"}
    for makefile, word in sorted(referenced_property_files):
        mapped = source_path(word)
        if mapped is None or not mapped.is_file():
            fail(f"{makefile}: release property file is not in the release configuration: {word}")
        else:
            property_files.add(mapped)
    for path in sorted(property_files):
        relative = path.relative_to(root).as_posix()
        text = text_files.get(path)
        if text is None:
            fail(f"{relative}: release property file is not text")
            continue
        for number, raw in enumerate(text.split("\n"), 1):
            key = init_props.property_key(raw)
            if key is None:
                continue
            if init_props.split_import(key) is not None:
                fail(f"{relative}:{number}: property import in release configuration: {key}")
                continue
            assignment = init_props.split_assignment(key)
            if assignment is None:
                continue
            errors.extend(property_violations(f"{relative}:{number}", "=".join(assignment)))

    init_files = {p for p in text_files if p.suffix == ".rc"}
    for word in installed_init_sources:
        mapped = source_path(word)
        if mapped is not None and mapped in text_files:
            init_files.add(mapped)
    for path in sorted(init_files):
        errors.extend(init_violations(path.relative_to(root).as_posix(), text_files[path]))

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
    installer = vault / "scripts/install-overlay.sh"
    if installer.is_file() and "patches/bootable-recovery" not in installer.read_text(encoding="utf-8"):
        fail("install-overlay.sh does not apply patches/bootable-recovery")

    return errors, len(files)


BETA_FILES = ("common.mk", "BoardConfigVault.mk", "Android.bp", "config.xml",
              "device-google-bluejay.diff", "device-google-gs101.diff",
              "vendor-google-bluejay.diff", "device-google-bluejay-kernels.diff")
CMDLINE_REMOVED = ("earlycon=", "console=", "androidboot.console=", "printk.devkmsg=")


def resolve_beta(vault, beta, depth=0):
    """(effective {name: path}, beta directories in the chain) for release-bluejay/BETA,
    exactly as release-bluejay/resolve-beta.sh resolves it."""
    directory = vault / "release-bluejay" / beta
    if depth > 8 or not (directory / "BASE").is_file():
        raise ValueError(f"release-bluejay/{beta}: missing or looping BASE")
    kind, _, name = (directory / "BASE").read_text(encoding="utf-8").strip().partition(" ")
    name = name.strip()
    if kind == "rung":
        rung = vault / "dev-ladder-bluejay" / f"rung-{name}"
        if not rung.is_dir():
            raise ValueError(f"release-bluejay/{beta}: BASE names a missing rung: {name}")
        effective = {f: rung / f for f in BETA_FILES if (rung / f).is_file()}
        chain = []
    elif kind == "beta":
        effective, chain = resolve_beta(vault, name, depth + 1)
    else:
        raise ValueError(f"release-bluejay/{beta}: bad BASE: {kind} {name}")
    for path in sorted(directory.iterdir()):
        if path.name in BETA_FILES:
            effective[path.name] = path
    return effective, chain + [directory]


def check_bluejay_beta(root, beta):
    """Return (errors, warnings, number of files checked) for release-bluejay/BETA."""
    vault = root / "vault-os"
    errors, warnings = [], []
    fail = errors.append
    try:
        effective, chain = resolve_beta(vault, beta)
    except ValueError as error:
        return [str(error)], [], 0

    # The beta's own files: no development leftovers or markers.
    own = [p for d in chain for p in sorted(d.iterdir()) if p.is_file()]
    for path in own:
        relative = path.relative_to(root).as_posix()
        if FORBIDDEN_NAMES.search(path.name) or "zzz-debug" in relative:
            fail(f"development leftover file in the beta configuration: {relative}")
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if DEBUG_MARKER.search(line):
                fail(f"{relative}:{number}: development marker in the beta configuration: {line.strip()}")

    def text_of(name):
        path = effective.get(name)
        return (path.relative_to(root).as_posix(), path.read_text(encoding="utf-8")) if path else (name, "")

    # Effective makefiles: the release rules.
    for name in ("common.mk", "BoardConfigVault.mk"):
        relative, text = text_of(name)
        if not text:
            fail(f"release-bluejay/{beta}: no effective {name}")
            continue
        for line in logical_lines(text):
            if re.search(r"\b(PRODUCT_ADB_KEYS|WITH_ADB_INSECURE|ADB_INSECURE|PV_DEV_ADB_KEY)\b", line) \
                    or "debug_adbkey" in line:
                fail(f"{relative}: adb key/insecure-adb setting in the beta configuration: {line}")
            errors.extend(property_violations(relative, line))
            if re.search(r"etc/init/[^\s:]*debug[^\s:]*\.rc", line, re.IGNORECASE):
                fail(f"{relative}: installs a debug init script: {line}")
            if ADB_KEYS_DESTINATION.search(line) or ADB_KEYS_MODULE.search(line):
                fail(f"{relative}: installs a pre-authorised adb host key: {line}")
    relative, blueprint = text_of("Android.bp")
    if ADB_KEYS_MODULE.search(re.sub(r"//[^\n]*|#[^\n]*", "", blueprint)):
        fail(f"{relative}: installs a pre-authorised adb host key")

    _, common = text_of("common.mk")
    if not re.search(r"(?m)^\s*persist\.sys\.usb\.config=none\s*$", common):
        fail(f"release-bluejay/{beta}: effective common.mk must set persist.sys.usb.config=none")

    relative, board = text_of("BoardConfigVault.mk")
    board_lines = list(logical_lines(board))
    for required in ("include vendor/phonevault/config/release-version.mk",
                     "BOARD_AVB_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)"):
        if required not in board_lines:
            fail(f"{relative} lacks: {required}")
    keys = [l.split(":=", 1)[1].strip() for l in board_lines
            if re.match(r"PHONEVAULT_AVB_KEY\s*:=", l)]
    if keys != ["vendor/phonevault/keys/avb_bluejay_beta.pem"]:
        fail(f"{relative}: PHONEVAULT_AVB_KEY must be exactly vendor/phonevault/keys/avb_bluejay_beta.pem: {keys}")
    for line in board_lines:
        if re.search(r"avb_bluejay_dev|_DEV_rsa|keys/avb\.pem|testkey", line):
            fail(f"{relative}: names a development/test AVB key: {line}")
    removed = " ".join(l.split(":=", 1)[1] for l in board_lines
                       if re.match(r"PHONEVAULT_KERNEL_CMDLINE_REMOVED\s*:=", l))
    for word in CMDLINE_REMOVED:
        if f"{word}%" not in removed.split():
            fail(f"{relative}: kernel command line keeps {word}* (PHONEVAULT_KERNEL_CMDLINE_REMOVED)")
    if "BOARD_KERNEL_CMDLINE := $(filter-out $(PHONEVAULT_KERNEL_CMDLINE_REMOVED),$(BOARD_KERNEL_CMDLINE))" \
            not in board_lines:
        fail(f"{relative}: PHONEVAULT_KERNEL_CMDLINE_REMOVED is not filtered out of BOARD_KERNEL_CMDLINE")
    if not any(re.match(r"PHONEVAULT_KERNEL_CMDLINE\s*:?=.*\busbcore\.authorized_default=0\b", l)
               for l in board_lines):
        fail(f"{relative}: usbcore.authorized_default=0 (rung b2) is missing")

    # Recovery hardening reaches the bluejay tree only through sync-beta.sh.
    sync = vault / "release-bluejay/sync-beta.sh"
    if not sync.is_file() or "patches/bootable-recovery" not in sync.read_text(encoding="utf-8"):
        fail("release-bluejay/sync-beta.sh does not apply patches/bootable-recovery")

    # Kiosk escape: reported, not required (see module docstring).
    _, overlay = text_of("config.xml")
    if not overlay:
        overlay = (vault / "vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
                   ).read_text(encoding="utf-8")
    for resource in ("config_voice_capable", "config_sms_capable"):
        if not re.search(rf'<bool name="{resource}">false</bool>', overlay):
            warnings.append(f"release-bluejay/{beta}: framework overlay leaves {resource} at its default "
                            "(known beta1 gap: keyguard Emergency button; beta1-novoice tests it)")
    return errors, warnings, len(own) + len(effective)


def main(argv):
    if len(argv) not in (1, 3) or (len(argv) == 3 and argv[1] != "--bluejay-beta"):
        print("usage: vaultgate.py release-source REPOSITORY_ROOT [--bluejay-beta BETA]", file=sys.stderr)
        return 2
    root = pathlib.Path(argv[0]).resolve()
    errors, checked = check(root)
    warnings = []
    beta_note = ""
    if len(argv) == 3:
        beta_errors, warnings, beta_checked = check_bluejay_beta(root, argv[2])
        errors += beta_errors
        beta_note = f"; bluejay beta {argv[2]}: {beta_checked} files checked"
    for warning in warnings:
        print(f"WARNING: {warning}", file=sys.stderr)
    if errors:
        print("release source gate failed:", file=sys.stderr)
        for error in errors:
            print(f"  {error}", file=sys.stderr)
        return 1
    print(f"Release source gate passed: {checked} release configuration files checked{beta_note}.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
