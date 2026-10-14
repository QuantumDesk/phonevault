"""Android init property files, read the way init reads them (property_service.cpp of the
Lineage 22.2 / 24.0 trees), not with line greps.

LoadProperties: whitespace around the key, '=' and the value is stripped, '#' starts a
comment only at the start of a line, and `import <path> [filter]` loads another property
file (only that file's properties matching the filter: an exact name or a `prefix*`).
ExpandProps: ${name}, ${name:-default}, $name and $$ in an import path or init builtin
argument.
"""

import re

WHITESPACE = " \t\n\v\f\r"
# Marks a ${...} part that cannot be resolved statically.
UNRESOLVED = "\x00"
# Mount points that are writable at runtime (or populated by init itself): an import from
# there loads content that is not part of the signed image.
WRITABLE_MOUNTS = frozenset({
    "data", "cache", "mnt", "metadata", "persist", "sdcard", "storage", "tmp",
    "dev", "sys", "proc", "config", "acct", "debug_ramdisk",
    "second_stage_resources", "linkerconfig", "data_mirror", "efs"})
# Properties set before the property files are loaded (kernel command line, bootconfig,
# device tree, ExportKernelBootProps) win over every file.
RUNTIME_FIRST = re.compile(
    r"^ro\.(boot|boottime|kernel)\.|^ro\.(hardware|serialno|bootmode|baseband|bootloader|revision)$")
# Never applied from a file (LoadProperties skips them).
_IGNORED = ("sys.powerctl", "selinux.restorecon_recursive")


def property_key(raw):
    """One physical line with surrounding whitespace removed; None for a blank or
    comment line."""
    key = raw.strip(WHITESPACE)
    if not key or key.startswith("#"):
        return None
    return key


def split_import(key):
    """(path, filter) for an `import <path> [filter]` line, else None."""
    if not key.startswith("import "):
        return None
    rest = key[7:].lstrip(WHITESPACE)
    filename, space, sub_filter = rest.partition(" ")
    return filename, sub_filter.lstrip(WHITESPACE) if space else ""


def split_assignment(key):
    """(name, value) for a `name = value` line, else None."""
    name, equals, value = key.partition("=")
    if not equals:
        return None
    return name.rstrip(WHITESPACE), value.lstrip(WHITESPACE)


def matches_filter(name, prop_filter):
    """An import filter: empty (everything), `prefix*`, or an exact name."""
    if not prop_filter:
        return True
    if prop_filter.endswith("*"):
        return name.startswith(prop_filter[:-1])
    return name == prop_filter


def applied_from_file(name):
    """LoadProperties never sets ctl.* or these from a file."""
    return not (name.startswith("ctl.") or name in _IGNORED)


def parse_properties(text):
    """Yield ("import", path, filter) and ("property", name, value) records of one
    property file, in file order."""
    for raw in (text + "\n").split("\n"):
        key = property_key(raw)
        if key is None:
            continue
        imported = split_import(key)
        if imported is not None:
            yield ("import",) + imported
            continue
        assignment = split_assignment(key)
        if assignment is not None:
            yield ("property",) + assignment


def expand(text, properties, allow):
    """init ExpandProps. Returns (value, unresolved): unresolved lists the names that
    cannot be resolved to a build-time constant (allow(name) false, unknown, or itself
    containing '$'); value then has UNRESOLVED in their place."""
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
                out.append(UNRESOLVED)
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
            out.append(UNRESOLVED)
    return "".join(out), unresolved


def build_time_constant(name):
    """An ro.* property whose value comes only from the image's property files."""
    return name.startswith("ro.") and not RUNTIME_FIRST.search(name)
