"""Android init model of a production target-files archive, for
verify-production-target-files.sh.

  vaultgate.py production-target-files TARGET_FILES PROPERTIES_OUT EFFECTIVE_OUT INIT_OUT

Property files and init files are read the way Android init reads them (system/core/init
of the Lineage 22.2 / 24.0 trees):
  property_service.cpp PropertyLoadBootDefaults loads, in order, the (recovery) ramdisk
  prop.default, the second-stage ramdisk build.prop, system, system_ext, system_dlkm,
  vendor default.prop + build.prop, vendor_dlkm, odm_dlkm, odm and product into one map,
  so a LATER file wins even for ro.* (write-once applies only to values set before the
  files are loaded: ro.boot.*, ro.hardware, ro.serialno, ...), and finally the debug
  ramdisk's adb_debug.prop. Every builtin argument is property-expanded.
Writes every property occurrence, normalised to name=value, to PROPERTIES_OUT; the value
init ends up with to EFFECTIVE_OUT; init violations to INIT_OUT. A property or init import
that resolves outside the image (a writable location) fails here (exit 1, stderr).
"""

import posixpath
import re
import stat
import sys
import zipfile

from vaultgates import init_props
from vaultgates.init_props import UNRESOLVED, WHITESPACE, build_time_constant, expand
from vaultgates.init_rc import (
    ADB_ENDPOINT, ADBD_PATH, DEBUGGABLE_TRIGGER, EXEC_KEYWORDS, SECTION_KEYWORDS,
    START_KEYWORDS, display, init_lines)

# Image partitions as target-files lays them out (a partition built into its parent
# appears under the parent, e.g. VENDOR/odm, SYSTEM/system_ext).
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
PROPERTY_FILE = re.compile(r"(^|/)(build\.prop|default\.prop|prop\.default)$")
INSTALLED_INIT = re.compile(
    r"(^|/)etc/init/.*\.rc$|^(ROOT|BOOT/RAMDISK|INIT_BOOT/RAMDISK|VENDOR_BOOT/RAMDISK|RECOVERY/RAMDISK)/.*\.rc$")
INIT_USB_RC = re.compile(r"(^|/)etc/init/hw/init\.usb\.rc$")
RECOVERY_INIT = re.compile(r"^(BOOT|VENDOR_BOOT|RECOVERY)/RAMDISK/system/etc/init/hw/init\.rc$")
USB_CONFIG = re.compile(r"^(persist\.)?(sys|vendor)\.usb\.config$")
USB_FUNCTION_TRIGGER = re.compile(r"^property:sys\.usb\.(config|configfs|ffs\.ready)=")


class TargetFiles:
    """The archive's files and directories, with in-image symlinks and device paths."""

    def __init__(self, path):
        self.archive = zipfile.ZipFile(path)
        self.entries = {info.filename: info for info in self.archive.infolist()
                        if not info.filename.endswith("/")}
        self.names = sorted(self.entries)
        self.directories = set()
        for name in self.names:
            parent = posixpath.dirname(name)
            while parent and parent not in self.directories:
                self.directories.add(parent)
                parent = posixpath.dirname(parent)

    def is_symlink(self, name):
        return stat.S_ISLNK(self.entries[name].external_attr >> 16)

    @staticmethod
    def tree_of(name):
        for tree in RAMDISK_TREES:
            if name.startswith(tree):
                return tree
        return None

    def locate(self, device_path, tree=None):
        """Archive files/directories a device path can denote; None when the path is
        outside the image. UNRESOLVED parts match within one path component."""
        relative = posixpath.normpath("/" + device_path).lstrip("/")
        top, _, rest = relative.partition("/")
        if top in init_props.WRITABLE_MOUNTS or (rest and UNRESOLVED in top):
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
        found = sorted({name for name in list(self.entries) + sorted(self.directories)
                        for regex in patterns if regex.match(name)})
        if top not in PARTITION_ROOTS and rest and not found:
            return None
        return found

    def resolve_entry(self, name, depth=0):
        """Follow symlinks inside the archive; None when the file is not in the image."""
        if name not in self.entries:
            return None
        if not self.is_symlink(name) or depth > 8:
            return name
        target = self.archive.read(name).decode("utf-8", "replace")
        if target.startswith("/"):
            for candidate in self.locate(target, self.tree_of(name)) or []:
                resolved = self.resolve_entry(candidate, depth + 1)
                if resolved:
                    return resolved
            return None
        return self.resolve_entry(
            posixpath.normpath(posixpath.join(posixpath.dirname(name), target)), depth + 1)

    def read_text(self, name):
        resolved = self.resolve_entry(name)
        if resolved is None:
            return None
        return self.archive.read(resolved).decode("utf-8", "replace")


# ---- property files --------------------------------------------------------

def load_properties(image, name, prop_filter, sink, fatal, stack=()):
    """Append (file, name, value) for every property `name` sets, imports included."""
    text = image.read_text(name)
    if text is None or name in stack or len(stack) > 16:
        return
    for raw in (text + "\n").split("\n"):
        key = init_props.property_key(raw)
        if key is None:
            continue
        imported = None if prop_filter else init_props.split_import(key)
        if imported is not None:
            filename, sub_filter = imported
            # ExpandProps here sees only the runtime-first properties.
            pattern, _unresolved = expand(filename, {}, lambda _n: False)
            matches = image.locate(pattern, image.tree_of(name))
            if matches is None:
                fatal.append(f"production property file {name} imports from outside the image: {key}")
                continue
            for match in matches:
                load_properties(image, match, sub_filter, sink, fatal, stack + (name,))
            continue
        assignment = init_props.split_assignment(key)
        if assignment is None:
            continue
        prop, value = assignment
        if not init_props.matches_filter(prop, prop_filter):
            continue
        if not init_props.applied_from_file(prop):
            continue
        sink.append((name, prop, value))


def partition_files(image, partition, legacy=True):
    files = []
    for root in PARTITION_ROOTS[partition]:
        canonical = root + "etc/build.prop"
        if canonical in image.entries:
            files.append(canonical)
        elif legacy:
            files.extend(f for f in (root + "default.prop", root + "build.prop")
                         if f in image.entries)
    return files


def load_order(image):
    """Property files in PropertyLoadBootDefaults order."""
    order = []
    for tree in RAMDISK_TREES:
        order += [tree + "prop.default", tree + "default.prop"]
    for tree in RAMDISK_TREES:
        order.append(tree + "system/etc/ramdisk/build.prop")
    order.append("SYSTEM/build.prop")
    order += partition_files(image, "system_ext")
    order += partition_files(image, "system_dlkm", legacy=False)
    order += [root + "default.prop" for root in PARTITION_ROOTS["vendor"]]
    order += [root + "build.prop" for root in PARTITION_ROOTS["vendor"]]
    order += partition_files(image, "vendor_dlkm", legacy=False)
    order += partition_files(image, "odm_dlkm", legacy=False)
    order += partition_files(image, "odm")
    order += partition_files(image, "product")
    for tree in RAMDISK_TREES:
        order.append(tree + "adb_debug.prop")
    return order


def effective_properties(image, fatal):
    effective = {}
    seen_files = set()
    for name in load_order(image):
        if name not in image.entries or name in seen_files:
            continue
        seen_files.add(name)
        loaded = []
        load_properties(image, name, "", loaded, fatal)
        for _source, prop, value in loaded:
            effective[prop] = value
    return effective


# ---- init files ------------------------------------------------------------

def debuggable_only(trigger_args):
    return DEBUGGABLE_TRIGGER in trigger_args


def usb_function_only(trigger_args):
    conditions = trigger_args[1::2]
    joiners = trigger_args[2::2]
    if not conditions or any(j != "&&" for j in joiners):
        return False
    return all(USB_FUNCTION_TRIGGER.match(c) for c in conditions)


def analyse(image, effective, name, text, queue, report):
    """Append init violations of one file to report; queue the files it imports."""
    def safe_expand(value):
        expanded, unresolved = expand(value, effective, build_time_constant)
        return None if unresolved else expanded

    section = ""
    trigger_args = []
    trigger_text = ""
    service = None

    def end_service():
        if service and service["adbd"] and "disabled" not in service["options"]:
            report.append(f"{name}: adbd service is not disabled: {service['raw']}")

    for _number, args, raw in init_lines(text):
        keyword = args[0]
        if keyword in SECTION_KEYWORDS:
            end_service()
            service = None
            section = keyword
            trigger_args, trigger_text = [], ""
            if keyword == "on":
                trigger_args, trigger_text = args, display(raw).strip()
            elif keyword == "service":
                path = args[2] if len(args) > 2 else ""
                is_adbd = bool(ADBD_PATH.search(path))
                if is_adbd and not (INIT_USB_RC.search(name) and args[1] == "adbd"):
                    report.append(f"{name}: adbd service defined outside init.usb.rc: {display(raw)}")
                service = {"adbd": is_adbd, "options": set(), "raw": display(raw)}
            else:
                target = args[1] if len(args) > 1 else ""
                pattern, _unresolved = expand(target, effective, build_time_constant)
                matches = image.locate(pattern, image.tree_of(name))
                if matches is None:
                    report.append(f"{name}: imports an init file from outside the image: {display(raw)}")
                    continue
                for match in matches:
                    if match in image.directories:
                        queue.extend(n for n in image.names if posixpath.dirname(n) == match)
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
        if keyword in START_KEYWORDS and len(args) > 1:
            target = safe_expand(args[1])
            if (target is None or target == "adbd") and not gated and not usb_only:
                report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword in EXEC_KEYWORDS and any(ADBD_PATH.search(a) for a in args[1:]) and not gated:
            report.append(f"{name}: [{trigger_text}] {line}")
        elif keyword in ("mkdir", "mount", "write") and ADB_ENDPOINT.search(command):
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


def is_recovery_init(name, text):
    """The recovery ramdisk's own init.rc (bootable/recovery/etc/init.rc) prepares the
    FunctionFS endpoint that `adb sideload` (minadbd) needs. Recovery adbd itself is
    governed by the recovery binary (patches/bootable-recovery), so only that exact file
    is exempt, and only when it is the recovery init. With the recovery ramdisk in
    vendor_boot (bluejay) it is VENDOR_BOOT/RAMDISK/system/etc/init/hw/init.rc."""
    return bool(RECOVERY_INIT.match(name)) and any(
        args[:3] == ["service", "recovery", "/system/bin/recovery"]
        for _number, args, _raw in init_lines(text))


def init_report(image, effective):
    """Installed init files (etc/init/** and the ramdisks) plus every file they import,
    wherever it lives in the image."""
    queue = [n for n in image.names if INSTALLED_INIT.search(n)]
    analysed = set()
    report = []
    while queue:
        name = queue.pop(0)
        resolved = image.resolve_entry(name)
        if resolved is None or name in analysed:
            continue
        analysed.add(name)
        text = image.archive.read(resolved).decode("utf-8", "replace")
        if is_recovery_init(name, text):
            continue
        analyse(image, effective, name, text, queue, report)
    return report


def main(argv):
    archive_path, properties_out, effective_out, init_out = argv[:4]
    image = TargetFiles(archive_path)
    fatal = []

    property_names = [n for n in image.names if PROPERTY_FILE.search(n)]
    if not property_names:
        print("production target-files lacks installed property files", file=sys.stderr)
        return 1
    occurrences = []
    for name in property_names:
        load_properties(image, name, "", occurrences, fatal)
    effective = effective_properties(image, fatal)

    with open(properties_out, "w", encoding="utf-8") as handle:
        for _source, prop, value in occurrences:
            handle.write(f"{prop}={value}\n")
    with open(effective_out, "w", encoding="utf-8") as handle:
        for prop in sorted(effective):
            handle.write(f"{prop}={effective[prop]}\n")

    report = init_report(image, effective)
    with open(init_out, "w", encoding="utf-8") as handle:
        for line in report:
            handle.write(line + "\n")

    if fatal:
        for message in dict.fromkeys(fatal):
            print(message, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
