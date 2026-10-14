"""Blueprint `overrides` lists, and proof that every overridden module is absent from a
target-files archive.

An override is silently defeated when another installed module names the target in
`required` (Trebuchet survives its override that way), so the built image, not the
Android.bp, is the proof.

  vaultgate.py overrides list ANDROID_BP
      the active override names, one per line (build-rung.sh scrubs their staging dirs)
  vaultgate.py overrides check ANDROID_BP TARGET_FILES [--require-overrides]
      exit 1 when an overridden app/overlay is still packaged; prints the APKs that remain.
      --require-overrides also fails when the Android.bp has no active override (the
      release list can never be empty: an unparsed list would prove nothing).

Only active entries count, exactly as Soong reads them: `//` and `/* */` comments are
ignored, names may share a line with `overrides: [` or `]`, and every `overrides` list in
the file counts. Anything in a list other than string literals (a variable, `+`) is an
error rather than a guess.
"""

import re
import sys
import zipfile

# Partitions an app or overlay can be packaged in.
PARTITIONS = ("SYSTEM", "SYSTEM_EXT", "PRODUCT", "VENDOR", "ODM")
APK_ENTRY = re.compile(r"(SYSTEM|SYSTEM_EXT|PRODUCT|VENDOR)/(app|priv-app)/[^/]+/[^/]+\.apk$")
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_LIST_START = re.compile(r"\s*:\s*\[")


class OverridesError(ValueError):
    """An Android.bp whose overrides cannot be read exactly."""


def _skip_string(text, pos):
    """Index just past the string literal starting at text[pos] ('"' or '`')."""
    quote = text[pos]
    i = pos + 1
    while i < len(text):
        if text[i] == "\\" and quote == '"':
            i += 2
            continue
        if text[i] == quote:
            return i + 1
        i += 1
    raise OverridesError(f"unterminated string literal at offset {pos}")


def _skip_comment(text, pos):
    """Index just past a comment starting at pos, or pos when there is none."""
    if text.startswith("//", pos):
        end = text.find("\n", pos)
        return len(text) if end < 0 else end
    if text.startswith("/*", pos):
        end = text.find("*/", pos + 2)
        if end < 0:
            raise OverridesError(f"unterminated comment at offset {pos}")
        return end + 2
    return pos


def _read_list(text, pos):
    """Names of the list whose '[' is at text[pos - 1]; returns (names, index after ']')."""
    names = []
    i = pos
    while i < len(text):
        c = text[i]
        if c in " \t\r\n,":
            i += 1
            continue
        after_comment = _skip_comment(text, i)
        if after_comment != i:
            i = after_comment
            continue
        if c == "]":
            return names, i + 1
        if c == '"':
            end = _skip_string(text, i)
            names.append(_unquote(text[i:end]))
            i = end
            continue
        line = text.count("\n", 0, i) + 1
        raise OverridesError(f"line {line}: overrides list holds something other than string literals")
    raise OverridesError("unterminated overrides list")


def _next_token(text, i):
    """The first character at or after i that is not blank or inside a comment."""
    while i < len(text):
        after_comment = _skip_comment(text, i)
        if after_comment != i:
            i = after_comment
        elif text[i] in " \t\r\n":
            i += 1
        else:
            return text[i]
    return ""


def _unquote(literal):
    body = literal[1:-1]
    return re.sub(r"\\(.)", r"\1", body)


def parse_overrides(text):
    """Every name in every active `overrides: [...]` list, in file order."""
    names = []
    i = 0
    while i < len(text):
        c = text[i]
        if c in "\"`":
            i = _skip_string(text, i)
            continue
        after_comment = _skip_comment(text, i)
        if after_comment != i:
            i = after_comment
            continue
        identifier = _IDENTIFIER.match(text, i)
        if identifier:
            i = identifier.end()
            if identifier.group() == "overrides":
                opening = _LIST_START.match(text, i)
                if opening:
                    found, i = _read_list(text, opening.end())
                    names += found
                    if _next_token(text, i) == "+":
                        raise OverridesError("overrides list is concatenated with another value")
            continue
        i += 1
    return names


def read_overrides(path):
    with open(path, encoding="utf-8") as handle:
        return parse_overrides(handle.read())


def packaged(module, entries, native=False):
    """Target-files entries that package `module`: its app/priv-app dir, an overlay APK
    named <module>.apk anywhere under overlay/ (icon packs sit in
    overlay/IconPackFooLauncher/IconPackFooLauncherOverlay.apk), or the app's
    auto-generated RRO (overlay/<module>__<product>__auto_generated_rro_*.apk).
    native=True also matches a vendor binary (bin/, bin/hw/), a VINTF fragment and a
    permissions XML of that name."""
    app_dirs = tuple(f"{p}/{d}/{module}/" for p in PARTITIONS for d in ("app", "priv-app"))
    files = set()
    if native:
        for p in PARTITIONS:
            files |= {f"{p}/bin/{module}", f"{p}/bin/hw/{module}",
                      f"{p}/etc/vintf/manifest/{module}", f"{p}/etc/permissions/{module}",
                      f"{p}/etc/permissions/{module.replace('.prebuilt.xml', '.xml')}"}

    def hit(entry):
        if entry.startswith(app_dirs) or entry in files:
            return True
        if entry.split("/")[0] in PARTITIONS and "/overlay/" in entry:
            base = entry.rsplit("/", 1)[-1]
            return base == f"{module}.apk" or base.startswith(f"{module}__")
        return False

    return [entry for entry in entries if hit(entry)]


def remaining_apps(entries):
    """<PARTITION>/<app|priv-app>/<name> of every APK still in the image."""
    return sorted({"/".join(e.split("/")[:3]) for e in entries if APK_ENTRY.match(e)})


def check(blueprint, target_files, require_overrides=False):
    names = read_overrides(blueprint)
    if require_overrides and not names:
        print(f"FAIL: no active overrides found in {blueprint}", file=sys.stderr)
        return 1
    entries = zipfile.ZipFile(target_files).namelist()
    survivors = []
    for name in names:
        hits = packaged(name, entries)
        if hits:
            apks = [e for e in hits if e.endswith(".apk")]
            # no APK = only dangling JNI-lib symlinks left in the staging dir (see
            # build-rung.sh scrub)
            survivors.append((name, apks[0] if apks else f"{hits[-1]}  (no APK: stale staging leftover)"))
    apps = remaining_apps(entries)
    print(f"{len(names)} active overrides; {len(apps)} APKs remain in the image:")
    for app in apps:
        print("   ", app)
    if survivors:
        print("FAIL: overridden modules still packaged:")
        for name, entry in survivors:
            print(f"    {name}: {entry}")
        return 1
    print("OK: no overridden module is packaged")
    return 0


USAGE = ("usage: vaultgate.py overrides list ANDROID_BP\n"
         "       vaultgate.py overrides check ANDROID_BP TARGET_FILES [--require-overrides]")


def main(argv):
    try:
        if len(argv) == 2 and argv[0] == "list":
            for name in read_overrides(argv[1]):
                print(name)
            return 0
        if argv[:1] == ["check"] and len(argv) in (3, 4) \
                and argv[3:] in ([], ["--require-overrides"]):
            return check(argv[1], argv[2], require_overrides=len(argv) == 4)
    except OverridesError as error:
        print(f"{argv[1]}: {error}", file=sys.stderr)
        return 2
    print(USAGE, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
