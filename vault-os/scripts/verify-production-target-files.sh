#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 TARGET_FILES_ZIP [EXPECTED_BUILD_TAGS]" >&2
  exit 2
fi

TARGET_FILES="$1"
EXPECTED_TAGS="${2:-}"
[[ -s "${TARGET_FILES}" ]] || {
  echo "missing production target-files archive: ${TARGET_FILES}" >&2
  exit 1
}
if [[ -n "${EXPECTED_TAGS}" \
    && ! "${EXPECTED_TAGS}" =~ ^[A-Za-z0-9._-]+$ ]]; then
  echo "invalid expected production build tags" >&2
  exit 2
fi

listing="$(mktemp -t phone-vault-production-listing.XXXXXX)"
properties_file="$(mktemp -t phone-vault-production-properties.XXXXXX)"
effective_file="$(mktemp -t phone-vault-production-effective.XXXXXX)"
init_report="$(mktemp -t phone-vault-production-init.XXXXXX)"
trap 'rm -f "${listing}" "${properties_file}" "${effective_file}" "${init_report}"' EXIT
unzip -Z1 "${TARGET_FILES}" > "${listing}"

misc_info='META/misc_info.txt'
grep -Fqx "${misc_info}" "${listing}" || {
  echo "production target-files lacks META/misc_info.txt" >&2
  exit 1
}
misc_policy="$(unzip -p "${TARGET_FILES}" "${misc_info}")"
grep -Fqx 'build_type=user' <<<"${misc_policy}" || {
  echo "production signing requires build_type=user" >&2
  exit 1
}

# ---- Android init model ----------------------------------------------------
# Property files and init files are read the way Android init reads them
# (system/core/init of the Lineage 22.2 / 24.0 trees), not with line greps:
#   property_service.cpp LoadProperties: whitespace around keys, '=' and values
#   is stripped, '#' comments only at line start, `import <path> [filter]` loads
#   another property file; PropertyLoadBootDefaults loads, in order, the
#   (recovery) ramdisk prop.default, the second-stage ramdisk build.prop,
#   system, system_ext, system_dlkm, vendor default.prop + build.prop,
#   vendor_dlkm, odm_dlkm, odm and product into one map, so a LATER file wins
#   even for ro.* (write-once applies only to values set before the files are
#   loaded: ro.boot.*, ro.hardware, ro.serialno, ...), and finally the debug
#   ramdisk's adb_debug.prop.
#   tokenizer.cpp/parser.cpp: backslash-newline continues a line, quotes group,
#   `on`/`service`/`import` open a section at any indentation; every builtin
#   argument is property-expanded (${name}, ${name:-default}).
# Every property occurrence, normalised to name=value, goes to properties_file;
# the value init ends up with goes to effective_file; init violations go to
# init_report. A property or init import that resolves outside the image (a
# writable location) fails here.
python3 - "${TARGET_FILES}" "${properties_file}" "${effective_file}" "${init_report}" <<'PY'
import posixpath
import re
import stat
import sys
import zipfile

archive_path, properties_out, effective_out, init_out = sys.argv[1:5]
archive = zipfile.ZipFile(archive_path)
entries = {info.filename: info for info in archive.infolist() if not info.filename.endswith("/")}
names = sorted(entries)
directories = set()
for name in names:
    parent = posixpath.dirname(name)
    while parent and parent not in directories:
        directories.add(parent)
        parent = posixpath.dirname(parent)

# Image partitions as target-files lays them out (a partition built into its
# parent appears under the parent, e.g. VENDOR/odm, SYSTEM/system_ext).
PARTITION_ROOTS = {
    "system": ["SYSTEM/"],
    "system_ext": ["SYSTEM_EXT/", "SYSTEM/system_ext/"],
    "system_dlkm": ["SYSTEM_DLKM/", "SYSTEM/system_dlkm/"],
    "vendor": ["VENDOR/", "SYSTEM/vendor/"],
    "vendor_dlkm": ["VENDOR_DLKM/", "VENDOR/vendor_dlkm/"],
    "odm": ["ODM/", "VENDOR/odm/"],
    "odm_dlkm": ["ODM_DLKM/", "VENDOR/odm_dlkm/"],
    "product": ["PRODUCT/", "SYSTEM/product/"],
}
RAMDISK_TREES = ["BOOT/RAMDISK/", "INIT_BOOT/RAMDISK/", "VENDOR_BOOT/RAMDISK/",
                 "RECOVERY/RAMDISK/", "ROOT/"]
# Read-only mounts whose content is not in the target-files tree.
OPAQUE_READ_ONLY = {"apex"}
# Mount points that are writable at runtime (or populated by init itself):
# an import from there loads content that is not part of the signed image.
WRITABLE = {"data", "cache", "mnt", "metadata", "persist", "sdcard", "storage", "tmp",
            "dev", "sys", "proc", "config", "acct", "debug_ramdisk",
            "second_stage_resources", "linkerconfig", "data_mirror", "efs"}
WS = " \t\n\v\f\r"
UNRESOLVED = "\x00"  # marks a ${...} part that cannot be resolved statically


def is_symlink(name):
    return stat.S_ISLNK(entries[name].external_attr >> 16)


def tree_of(name):
    for tree in RAMDISK_TREES:
        if name.startswith(tree):
            return tree
    return None


def locate(device_path, tree=None):
    """Archive files/directories a device path can denote; None when the path
    is outside the image. UNRESOLVED parts match within one path component."""
    relative = posixpath.normpath("/" + device_path).lstrip("/")
    top, _, rest = relative.partition("/")
    if top in WRITABLE or (rest and UNRESOLVED in top):
        return None
    if top in OPAQUE_READ_ONLY:
        return []

    def pattern(prefix, tail):
        return re.compile(re.escape(prefix) + "".join(
            "[^/]*" if part == UNRESOLVED else re.escape(part)
            for part in re.split(f"({UNRESOLVED})", tail)) + "$")

    patterns = [pattern(tree, relative)] if tree else []
    if top in PARTITION_ROOTS:
        patterns += [pattern(root, rest) for root in PARTITION_ROOTS[top]]
    else:
        patterns += [pattern(ramdisk, relative) for ramdisk in RAMDISK_TREES]
    found = sorted({name for name in list(entries) + sorted(directories)
                    for regex in patterns if regex.match(name)})
    if top not in PARTITION_ROOTS and rest and not found:
        return None
    return found


def resolve_entry(name, depth=0):
    """Follow symlinks inside the archive; None when the file is not in the image."""
    if name not in entries:
        return None
    if not is_symlink(name) or depth > 8:
        return name
    target = archive.read(name).decode("utf-8", "replace")
    if target.startswith("/"):
        for candidate in locate(target, tree_of(name)) or []:
            resolved = resolve_entry(candidate, depth + 1)
            if resolved:
                return resolved
        return None
    return resolve_entry(posixpath.normpath(posixpath.join(posixpath.dirname(name), target)),
                         depth + 1)


def read_text(name):
    resolved = resolve_entry(name)
    if resolved is None:
        return None
    return archive.read(resolved).decode("utf-8", "replace")


# Properties set before the property files are loaded (kernel command line,
# bootconfig, device tree, ExportKernelBootProps) win over every file.
RUNTIME_FIRST = re.compile(r"^ro\.(boot|boottime|kernel)\.|^ro\.(hardware|serialno|bootmode|baseband|bootloader|revision)$")


def expand(text, properties, allow):
    """init ExpandProps. Returns (value, unresolved) where unresolved lists names
    that cannot be resolved to a build-time constant (value then has \\0 there)."""
    out = []
    unresolved = []
    i = 0
    while i < len(text):
        c = text[i]
        if c != "$":
            out.append(c)
            i += 1
            continue
        if text[i + 1: i + 2] == "$":
            out.append("$")
            i += 2
            continue
        if i + 1 >= len(text):
            break
        if text[i + 1] == "{":
            end = text.find("}", i + 2)
            if end < 0:
                unresolved.append(text[i:])
                out.append("\x00")
                break
            body = text[i + 2: end]
            i = end + 1
        else:
            body = text[i + 1:]
            i = len(text)
        name, _, default = body.partition(":-")
        if allow(name) and name in properties and "$" not in properties[name]:
            out.append(properties[name] or default)
        else:
            unresolved.append(name)
            out.append("\x00")
    return "".join(out), unresolved


def build_time_constant(name):
    return name.startswith("ro.") and not RUNTIME_FIRST.search(name)


# ---- property files --------------------------------------------------------
fatal = []


def load_properties(name, prop_filter, sink, stack=()):
    text = read_text(name)
    if text is None or name in stack or len(stack) > 16:
        return
    for raw in (text + "\n").split("\n"):
        key = raw.lstrip(WS)
        if key.startswith("#"):
            continue
        key = key.rstrip(WS)
        if key.startswith("import ") and not prop_filter:
            rest = key[7:].lstrip(WS)
            filename, space, sub_filter = rest.partition(" ")
            sub_filter = sub_filter.lstrip(WS) if space else ""
            # ExpandProps here sees only the runtime-first properties.
            pattern, _unresolved = expand(filename, {}, lambda _n: False)
            matches = locate(pattern, tree_of(name))
            if matches is None:
                fatal.append(f"production property file {name} imports from outside the image: {key}")
                continue
            for match in matches:
                load_properties(match, sub_filter, sink, stack + (name,))
            continue
        prop, equals, value = key.partition("=")
        if not equals:
            continue
        prop = prop.rstrip(WS)
        value = value.lstrip(WS)
        if prop_filter:
            if prop_filter.endswith("*"):
                if not prop.startswith(prop_filter[:-1]):
                    continue
            elif prop != prop_filter:
                continue
        if prop.startswith("ctl.") or prop in ("sys.powerctl", "selinux.restorecon_recursive"):
            continue
        sink.append((name, prop, value))


property_names = [n for n in names
                  if re.search(r"(^|/)(build\.prop|default\.prop|prop\.default)$", n)]
if not property_names:
    print("production target-files lacks installed property files", file=sys.stderr)
    raise SystemExit(1)

occurrences = []
for name in property_names:
    load_properties(name, "", occurrences)


def partition_files(partition, legacy=True):
    files = []
    for root in PARTITION_ROOTS[partition]:
        canonical = root + "etc/build.prop"
        if canonical in entries:
            files.append(canonical)
        elif legacy:
            files.extend(f for f in (root + "default.prop", root + "build.prop") if f in entries)
    return files


load_order = []
for tree in RAMDISK_TREES:
    load_order += [tree + "prop.default", tree + "default.prop"]
for tree in RAMDISK_TREES:
    load_order.append(tree + "system/etc/ramdisk/build.prop")
load_order.append("SYSTEM/build.prop")
load_order += partition_files("system_ext")
load_order += partition_files("system_dlkm", legacy=False)
load_order += [root + "default.prop" for root in PARTITION_ROOTS["vendor"]]
load_order += [root + "build.prop" for root in PARTITION_ROOTS["vendor"]]
load_order += partition_files("vendor_dlkm", legacy=False)
load_order += partition_files("odm_dlkm", legacy=False)
load_order += partition_files("odm")
load_order += partition_files("product")
for tree in RAMDISK_TREES:
    load_order.append(tree + "adb_debug.prop")

effective = {}
seen_files = set()
for name in load_order:
    if name not in entries or name in seen_files:
        continue
    seen_files.add(name)
    loaded = []
    load_properties(name, "", loaded)
    for _source, prop, value in loaded:
        effective[prop] = value

with open(properties_out, "w", encoding="utf-8") as handle:
    for _source, prop, value in occurrences:
        handle.write(f"{prop}={value}\n")
with open(effective_out, "w", encoding="utf-8") as handle:
    for prop in sorted(effective):
        handle.write(f"{prop}={effective[prop]}\n")

# ---- init files ------------------------------------------------------------


def init_lines(text):
    """init tokenizer: yields (args, raw logical line)."""
    data = text + "\n"
    n = len(data)
    pos = 0
    args = []
    line_start = 0
    while pos < n:
        c = data[pos]
        if c == "\n":
            if args:
                yield args, data[line_start:pos]
            pos += 1
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
                    while pos < n and data[pos] in " \t":
                        pos += 1
                else:
                    token.append(escaped)
                    pos += 1
                continue
            token.append(c)
            pos += 1
        args.append("".join(token))


def display(raw):
    return re.sub(r"\\\r?\n[ \t]*", " ", raw)


def debuggable_only(trigger_args):
    return "property:ro.debuggable=1" in trigger_args


def usb_function_only(trigger_args):
    conditions = trigger_args[1::2]
    joiners = trigger_args[2::2]
    if not conditions or any(j != "&&" for j in joiners):
        return False
    return all(re.match(r"^property:sys\.usb\.(config|configfs|ffs\.ready)=", c)
               for c in conditions)


def safe_expand(text):
    value, unresolved = expand(text, effective, build_time_constant)
    return None if unresolved else value


USB_CONFIG = re.compile(r"^(persist\.)?(sys|vendor)\.usb\.config$")
ENDPOINT = re.compile(r"functions/ffs\.adb|/dev/usb-ffs/adb|functionfs\s+adb")


def analyse(name, text, queue, report):
    section = ""
    trigger_args = []
    trigger_text = ""
    service = None

    def end_service():
        if service and service["adbd"] and "disabled" not in service["options"]:
            report.append(f"{name}: adbd service is not disabled: {service['raw']}")

    for args, raw in init_lines(text):
        keyword = args[0]
        if keyword in ("on", "service", "import"):
            end_service()
            service = None
            section = keyword
            trigger_args, trigger_text = [], ""
            if keyword == "on":
                trigger_args, trigger_text = args, display(raw).strip()
            elif keyword == "service":
                path = args[2] if len(args) > 2 else ""
                is_adbd = bool(re.search(r"(^|/)adbd$", path))
                if is_adbd and not (re.search(r"(^|/)etc/init/hw/init\.usb\.rc$", name)
                                    and args[1] == "adbd"):
                    report.append(f"{name}: adbd service defined outside init.usb.rc: {display(raw)}")
                service = {"adbd": is_adbd, "options": set(), "raw": display(raw)}
            else:
                target = args[1] if len(args) > 1 else ""
                pattern, _unresolved = expand(target, effective, build_time_constant)
                matches = locate(pattern, tree_of(name))
                if matches is None:
                    report.append(f"{name}: imports an init file from outside the image: {display(raw)}")
                    continue
                for match in matches:
                    if match in directories:
                        queue.extend(n for n in names if posixpath.dirname(n) == match)
                    else:
                        queue.append(match)
            continue
        if section == "service" and service is not None:
            service["options"].add(keyword)
            continue
        if section != "on":
            continue
        gated = debuggable_only(trigger_args)
        usb_only = usb_function_only(trigger_args)
        line = display(raw)
        command = " ".join(args)
        if keyword in ("start", "restart", "enable", "exec_start") and len(args) > 1:
            target = safe_expand(args[1])
            if (target is None or target == "adbd") and not gated and not usb_only:
                report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword in ("exec", "exec_background") and any(
                re.search(r"(^|/)adbd$", a) for a in args[1:]) and not gated:
            report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword in ("mkdir", "mount", "write") and ENDPOINT.search(command):
            if not gated:
                report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword == "symlink" and "functions/ffs.adb" in command:
            if not gated and not usb_only:
                report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword == "setprop" and len(args) > 2:
            target = safe_expand(args[1])
            if target is not None and not USB_CONFIG.match(target):
                continue
            # init.usb.rc hands the boot-time selection to the framework with
            # `setprop sys.usb.config ${persist.sys.usb.config}`; this gate pins
            # persist.sys.usb.config to exactly none in every property file.
            if args[2] == "${persist.sys.usb.config}" and target == "sys.usb.config":
                continue
            value = safe_expand(args[2])
            if (value is None or "adb" in value.lower()) and not gated:
                report.append(f"{name}: [{trigger_text}] {line}")
    end_service()


installed = [n for n in names if re.search(
    r"(^|/)etc/init/.*\.rc$|^(ROOT|BOOT/RAMDISK|INIT_BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/.*\.rc$", n)]
queue = list(installed)
analysed = set()
report = []
while queue:
    name = queue.pop(0)
    resolved = resolve_entry(name)
    if resolved is None or name in analysed:
        continue
    analysed.add(name)
    text = archive.read(resolved).decode("utf-8", "replace")
    # The recovery ramdisk's own init.rc (bootable/recovery/etc/init.rc)
    # prepares the FunctionFS endpoint that `adb sideload` (minadbd) needs.
    # Recovery adbd itself is governed by the recovery binary
    # (patches/bootable-recovery), so only that exact file is exempt, and only
    # when it is the recovery init. With the recovery ramdisk in vendor_boot
    # (bluejay) it is VENDOR_BOOT/RAMDISK/system/etc/init/hw/init.rc.
    if re.match(r"^(BOOT|VENDOR_BOOT|RECOVERY)/RAMDISK/system/etc/init/hw/init\.rc$", name) \
            and any(args[:3] == ["service", "recovery", "/system/bin/recovery"]
                    for args, _raw in init_lines(text)):
        continue
    analyse(name, text, queue, report)

with open(init_out, "w", encoding="utf-8") as handle:
    for line in report:
        handle.write(line + "\n")

if fatal:
    for message in dict.fromkeys(fatal):
        print(message, file=sys.stderr)
    raise SystemExit(1)
PY

for required_property in \
    'ro.debuggable=0' \
    'ro.secure=1' \
    'ro.adb.secure=1'; do
  grep -Fqx "${required_property}" "${effective_file}" || {
    echo "production target-files lacks ${required_property}" >&2
    exit 1
  }
done
while IFS='|' read -r property_name expected_line; do
  contradictory="$(grep -E "^${property_name}=" "${properties_file}" | \
    grep -Fvx "${expected_line}" || true)"
  if [[ -n "${contradictory}" ]]; then
    echo "production target-files contains contradictory ${property_name}" >&2
    exit 1
  fi
done <<'EOF'
ro\.debuggable|ro.debuggable=0
ro\.secure|ro.secure=1
ro\.adb\.secure|ro.adb.secure=1
EOF

# ---- Release ADB policy -------------------------------------------------
# A production image has no USB debugging path: adb is never the default USB
# function, no host key is pre-authorised, no debug init script ships, and no
# init file brings up adbd or its FunctionFS endpoint outside triggers that a
# user build can never satisfy. (DEBUG-38/41, 2026-08: a release common.mk
# carried persist.sys.usb.config=adb and an early-boot adbd script.)
usb_config_lines="$(grep -E '^(persist\.)?(sys|vendor)\.usb\.config=' \
  "${properties_file}" || true)"
adb_usb_config="$(grep -Ei 'adb' <<<"${usb_config_lines}" || true)"
if [[ -n "${adb_usb_config}" ]]; then
  echo "production target-files makes adb a default USB function:" >&2
  printf '%s\n' "${adb_usb_config}" | sort -u >&2
  exit 1
fi
persist_usb_values="$(sed -n 's/^persist\.sys\.usb\.config=//p' \
  <<<"${usb_config_lines}" | sort -u)"
effective_persist_usb="$(sed -n 's/^persist\.sys\.usb\.config=//p' "${effective_file}")"
[[ "${persist_usb_values}" == none && "${effective_persist_usb}" == none ]] || {
  echo "production persist.sys.usb.config must be exactly none: ${persist_usb_values:-<missing>}" >&2
  exit 1
}
debug_properties="$(grep -E \
  '^(ro\.force\.debuggable=1|service\.adb\.root=1|ro\.adb\.secure\.recovery=0|persist\.adb\.notify=0|persist\.service\.adb\.enable=1|service\.adb\.tcp\.port=)' \
  "${properties_file}" || true)"
if [[ -n "${debug_properties}" ]]; then
  echo "production target-files contains debugging properties:" >&2
  printf '%s\n' "${debug_properties}" | sort -u >&2
  exit 1
fi

# Debug ramdisk (first_stage_init.cpp): /force_debuggable makes first-stage
# init copy /adb_debug.prop to /debug_ramdisk, which property_service.cpp loads
# last (ro.debuggable=1, ro.adb.secure=0) without an unlock check; only the
# userdebug sepolicy swap is gated on unlock. None of it may ship.
debug_artifacts="$(grep -Ei \
  '(^|/)adb_keys$|zzz-debug|debug_adbkey|(^|/)(force_debuggable|adb_debug\.prop)$|^(ROOT|BOOT/RAMDISK|INIT_BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/(.*/)?userdebug_plat_sepolicy\.cil$' \
  "${listing}" || true)"
if [[ -n "${debug_artifacts}" ]]; then
  echo "production target-files contains debug/ADB artifacts:" >&2
  printf '%s\n' "${debug_artifacts}" >&2
  exit 1
fi

# Installed init files (etc/init/** and the ramdisks) plus every file they
# import, wherever it lives in the image. Section keywords count at any
# indentation, continuations are joined, `enable`/`exec_start` count like
# `start`, and a property-expanded service name or USB function is a violation
# unless it resolves to a build-time ro.* constant.
adb_init_violations="$(cat "${init_report}")"
if [[ -n "${adb_init_violations}" ]]; then
  echo "production init files start adbd or set up its endpoint outside ro.debuggable=1:" >&2
  printf '%s\n' "${adb_init_violations}" >&2
  exit 1
fi

if [[ -n "${EXPECTED_TAGS}" ]]; then
  build_tags="$(sed -n -E \
    's/^ro(\.[a-z_]+)?\.build\.tags=([^[:space:]]+)$/\2/p' \
    "${properties_file}" | sort -u)"
  [[ "${build_tags}" == "${EXPECTED_TAGS}" ]] || {
    echo "production build tags are not exactly ${EXPECTED_TAGS}: ${build_tags:-<missing>}" >&2
    exit 1
  }
fi

echo "Production user-build policy passed."
