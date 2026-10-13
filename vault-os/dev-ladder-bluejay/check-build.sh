#!/usr/bin/env bash
# Artifact gate for one bluejay rung (b2+): proves on the built target files and images that the
# rung did what its files say, before anything goes near the phone. build-rung.sh runs it; it can
# also be run by hand on the build box:
#   check-build.sh RUNG TARGET_FILES.zip OUT_DIR [TREE]
# Checks, each only when the rung dir carries the input:
#   1. kernel  PHONEVAULT_KMODS_REMOVED (BoardConfigVault.mk): no such .ko anywhere in the target
#              files (vendor_dlkm, vendor_boot ramdisk), no load list names one, and every
#              modules.dep in the target files resolves (no kept module depends on a removed one);
#   2. cmdline PHONEVAULT_KERNEL_CMDLINE is in vendor_boot.img's command line;
#   3. overrides every module in Android.bp `overrides` is absent: app/priv-app dir, overlay APK or
#              auto-generated RRO, vendor binary (bin/, bin/hw/), VINTF fragment, permissions XML
#              (an override is silently defeated when an installed module `required`s it);
#   4. expect  rung-RUNG/expect-build.txt, one check per line:
#                absent  PATH            PATH is not in the target files
#                present PATH            PATH is in the target files
#                grep    PATH  REGEX     PATH's content matches REGEX (Python re, MULTILINE)
#                nogrep  PATH  REGEX     PATH's content does not match REGEX
# Exit 1 on the first failed section, listing every failure in it.
set -euo pipefail
RUNG="${1:?rung}"
TF="${2:?target files zip}"
OUTD="${3:?out dir (images/)}"
TREE="${4:-/build/lineage-24}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
RUNG_DIR="${SCRIPT_DIR}/rung-${RUNG}"
[[ -d "${RUNG_DIR}" ]] || { echo "no such rung: ${RUNG_DIR}" >&2; exit 2; }
[[ -s "${TF}" ]] || { echo "target files not found: ${TF}" >&2; exit 2; }

CMDLINE=""
if [[ -s "${OUTD}/images/vendor_boot.img" ]]; then
  UB="$(mktemp -d)"
  "${TREE}/out/host/linux-x86/bin/unpack_bootimg" --boot_img "${OUTD}/images/vendor_boot.img" \
    --out "${UB}" > "${UB}/info.txt" 2>&1 || true
  CMDLINE="$(grep -i 'vendor command line args' "${UB}/info.txt" | head -1 | sed 's/^[^:]*: *//')"
  rm -rf "${UB}"
fi

python3 - "${RUNG_DIR}" "${TF}" "${CMDLINE}" <<'PY'
import os, re, sys, zipfile
rung_dir, tf, cmdline = sys.argv[1], sys.argv[2], sys.argv[3]
z = zipfile.ZipFile(tf)
names = z.namelist()
nameset = set(names)
failed = False

def section(title, problems):
    global failed
    if problems:
        failed = True
        print(f'FAIL {title}:')
        for p in problems:
            print('    ' + p)
    else:
        print(f'OK   {title}')

def mk_list(path, var):
    """Values of VAR := / += in a makefile, continuation lines joined, comments dropped."""
    if not os.path.exists(path):
        return []
    text = open(path).read().replace('\\\n', ' ')
    vals = []
    for line in text.split('\n'):
        line = line.split('#', 1)[0]
        m = re.match(rf'\s*{re.escape(var)}\s*(:=|\+=|=)\s*(.*)$', line)
        if m:
            if m.group(1) != '+=':
                vals = []
            vals += m.group(2).split()
    return vals

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
bp = os.path.join(rung_dir, 'Android.bp')
ovr, inside = [], False
for line in open(bp):
    s = line.strip()
    if s.startswith('//'):
        continue
    if re.match(r'overrides:\s*\[', s):
        inside = True; continue
    if inside and s.startswith(']'):
        inside = False; continue
    if inside:
        ovr += re.findall(r'"([^"]+)"', s)
parts = ('SYSTEM', 'SYSTEM_EXT', 'PRODUCT', 'VENDOR', 'ODM')
probs = []
for mod in ovr:
    app_pre = tuple(f'{p}/{d}/{mod}/' for p in parts for d in ('app', 'priv-app'))
    files = set()
    for p in parts:
        files |= {f'{p}/bin/{mod}', f'{p}/bin/hw/{mod}', f'{p}/etc/vintf/manifest/{mod}',
                  f'{p}/etc/permissions/{mod}', f'{p}/etc/permissions/{mod.replace(".prebuilt.xml", ".xml")}'}
    for e in names:
        hit = e.startswith(app_pre) or e in files
        if not hit and e.split('/')[0] in parts and '/overlay/' in e:
            base = e.rsplit('/', 1)[-1]
            hit = base == f'{mod}.apk' or base.startswith(f'{mod}__')
        if hit:
            probs.append(f'{mod}: {e}')
            break
apps = sorted({'/'.join(e.split('/')[:3]) for e in names
               if re.match(r'(SYSTEM|SYSTEM_EXT|PRODUCT|VENDOR)/(app|priv-app)/[^/]+/[^/]+\.apk$', e)})
section(f'overrides: {len(ovr)} modules absent ({len(apps)} APKs remain)', probs)
with open(os.path.join(os.path.dirname(tf), f'apks-{os.path.basename(rung_dir)}.txt'), 'w') as f:
    f.write('\n'.join(apps) + '\n')

# 4. expectations
exp = os.path.join(rung_dir, 'expect-build.txt')
if os.path.exists(exp):
    probs, n = [], 0
    for raw in open(exp):
        line = raw.rstrip('\n')
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        n += 1
        parts_ = line.split(None, 2)
        op, path = parts_[0], parts_[1]
        if op == 'absent':
            if path in nameset: probs.append(f'present but must be absent: {path}')
        elif op == 'present':
            if path not in nameset: probs.append(f'missing: {path}')
        elif op in ('grep', 'nogrep'):
            if path not in nameset:
                probs.append(f'{op}: no such file {path}'); continue
            content = z.read(path).decode(errors='replace')
            found = re.search(parts_[2], content, re.M) is not None
            if op == 'grep' and not found: probs.append(f'{path} lacks /{parts_[2]}/')
            if op == 'nogrep' and found: probs.append(f'{path} matches /{parts_[2]}/')
        else:
            probs.append(f'bad line: {line}')
    section(f'expect-build.txt: {n} checks', probs)

sys.exit(1 if failed else 0)
PY
