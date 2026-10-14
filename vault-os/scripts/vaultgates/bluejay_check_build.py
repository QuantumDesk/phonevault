"""Artifact gate for one bluejay rung (dev-ladder-bluejay/check-build.sh).

  vaultgate.py bluejay-check-build RUNG_DIR TARGET_FILES VENDOR_BOOT_CMDLINE

Sections (each only when the rung dir carries the input), exit 1 when any fails:
  kernel     PHONEVAULT_KMODS_REMOVED: no such .ko packaged, no load list names one,
             every modules.dep resolves;
  cmdline    PHONEVAULT_KERNEL_CMDLINE is in the vendor_boot command line;
  overrides  every Android.bp override is absent (app, overlay, RRO, vendor binary, VINTF
             fragment, permissions XML); writes apks-<rung>.txt next to TARGET_FILES;
  expect     rung-RUNG/expect-build.txt absent/present/grep/nogrep checks.
"""

import os
import re
import sys
import zipfile

from vaultgates.overrides import packaged, read_overrides, remaining_apps


def mk_list(path, var):
    """Values of VAR := / += in a makefile, continuation lines joined, comments dropped."""
    if not os.path.exists(path):
        return []
    with open(path) as handle:
        text = handle.read().replace('\\\n', ' ')
    vals = []
    for line in text.split('\n'):
        line = line.split('#', 1)[0]
        m = re.match(rf'\s*{re.escape(var)}\s*(:=|\+=|=)\s*(.*)$', line)
        if m:
            if m.group(1) != '+=':
                vals = []
            vals += m.group(2).split()
    return vals


def main(argv):
    rung_dir, tf, cmdline = argv[0], argv[1], argv[2]
    z = zipfile.ZipFile(tf)
    names = z.namelist()
    nameset = set(names)
    failed = False

    def section(title, problems):
        nonlocal failed
        if problems:
            failed = True
            print(f'FAIL {title}:')
            for p in problems:
                print('    ' + p)
        else:
            print(f'OK   {title}')

    # 1. kernel modules
    bcv = os.path.join(rung_dir, 'BoardConfigVault.mk')
    removed = mk_list(bcv, 'PHONEVAULT_KMODS_REMOVED')
    if removed:
        probs = []
        rm = set(removed)
        for n in names:
            if os.path.basename(n) in rm:
                probs.append(f'removed module still packaged: {n}')
        for n in names:
            b = os.path.basename(n)
            if b in ('modules.load', 'modules.load.recovery', 'modules.dep'):
                content = z.read(n).decode(errors='replace')
                d = os.path.dirname(n)
                for line in content.splitlines():
                    if not line.strip():
                        continue
                    if b == 'modules.dep':
                        mod, _, deps = line.partition(':')
                        for dep in [mod] + deps.split():
                            if os.path.basename(dep) in rm:
                                probs.append(f'{n}: {line.strip()[:120]}')
                            elif f'{d}/{os.path.basename(dep)}' not in nameset:
                                probs.append(f'{n}: dependency not packaged: {dep}')
                    elif os.path.basename(line.strip()) in rm:
                        probs.append(f'{n} still lists {line.strip()}')
        kos = sum(1 for n in names if n.endswith('.ko'))
        section(f'kernel: {len(removed)} modules removed, {kos} .ko entries remain, load lists and modules.dep consistent', probs)

    # 2. kernel command line
    want = mk_list(bcv, 'PHONEVAULT_KERNEL_CMDLINE')
    if want:
        have = cmdline.split()
        section(f'cmdline: vendor_boot has {" ".join(want)}',
                [f'missing {w} (vendor_boot cmdline: {cmdline or "unreadable"})' for w in want if w not in have])

    # 3. overrides
    ovr = read_overrides(os.path.join(rung_dir, 'Android.bp'))
    probs = []
    for mod in ovr:
        hits = packaged(mod, names, native=True)
        if hits:
            probs.append(f'{mod}: {hits[0]}')
    apps = remaining_apps(names)
    section(f'overrides: {len(ovr)} modules absent ({len(apps)} APKs remain)', probs)
    with open(os.path.join(os.path.dirname(tf), f'apks-{os.path.basename(rung_dir)}.txt'), 'w') as f:
        f.write('\n'.join(apps) + '\n')

    # 4. expectations
    exp = os.path.join(rung_dir, 'expect-build.txt')
    if os.path.exists(exp):
        probs, n = [], 0
        with open(exp) as handle:
            expectations = handle.readlines()
        for raw in expectations:
            line = raw.rstrip('\n')
            if not line.strip() or line.lstrip().startswith('#'):
                continue
            n += 1
            fields = line.split(None, 2)
            op, path = fields[0], fields[1]
            if op == 'absent':
                if path in nameset:
                    probs.append(f'present but must be absent: {path}')
            elif op == 'present':
                if path not in nameset:
                    probs.append(f'missing: {path}')
            elif op in ('grep', 'nogrep'):
                if path not in nameset:
                    probs.append(f'{op}: no such file {path}')
                    continue
                content = z.read(path).decode(errors='replace')
                found = re.search(fields[2], content, re.M) is not None
                if op == 'grep' and not found:
                    probs.append(f'{path} lacks /{fields[2]}/')
                if op == 'nogrep' and found:
                    probs.append(f'{path} matches /{fields[2]}/')
            else:
                probs.append(f'bad line: {line}')
        section(f'expect-build.txt: {n} checks', probs)

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
