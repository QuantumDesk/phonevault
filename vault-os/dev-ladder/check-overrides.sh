#!/usr/bin/env bash
# Artifact gate for the app-strip rungs: every module named in the rung's active (uncommented)
# Android.bp `overrides` list must be absent from the built target-files, as an app
# (<PARTITION>/app|priv-app/<name>/) or an overlay (<PARTITION>/overlay/<name>.apk or
# overlay/<name>/, or the app's auto-generated RRO). Run on the build host after build-rung.sh, before sideloading:
#   check-overrides.sh RUNG|release [target_files.zip]   (default: newest in $LINEAGE_TREE/out)
# Exit 1 lists the survivors. An override can be silently defeated when another installed module
# names the target in `required` (Trebuchet survives its override that way), so this is the
# proof a rung did what its Android.bp says. Also prints the APKs that remain, for the README.
# Non-app modules (e.g. android.software.webview.prebuilt.xml) are not matched here; check those
# on the phone (`pm list features`).
set -euo pipefail
RUNG="${1:?rung}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# `release` checks the release overrides (vendor/phonevault/prebuilt/Android.bp); sign-release.sh
# runs it on the input target-files before anything is signed.
if [[ "${RUNG}" == release ]]; then
  BP="${ROOT}/vault-os/vendor/phonevault/prebuilt/Android.bp"
else
  BP="${ROOT}/vault-os/dev-ladder/rung-${RUNG}/Android.bp"
fi
[[ -f "${BP}" ]] || { echo "no Android.bp for rung ${RUNG}" >&2; exit 2; }
if [[ -n "${2:-}" ]]; then
  TF="$2"
else
  : "${LINEAGE_TREE:?pass the target_files.zip, or set LINEAGE_TREE to the crosshatch source tree}"
  TF="$(ls -t "${LINEAGE_TREE}"/out/target/product/crosshatch/obj/PACKAGING/target_files_intermediates/*target_files*.zip | head -1)"
fi
[[ -s "${TF}" ]] || { echo "target-files not found: ${TF}" >&2; exit 2; }
echo "rung ${RUNG}: ${TF}"
python3 - "${BP}" "${TF}" <<'EOF'
import re, sys, zipfile
bp, tf = sys.argv[1], sys.argv[2]
names, inside = [], False
for line in open(bp):
    s = line.strip()
    if s.startswith('//'):
        continue
    if re.match(r'overrides:\s*\[', s):
        inside = True
        continue
    if inside and s.startswith(']'):
        inside = False
        continue
    if inside:
        names += re.findall(r'"([^"]+)"', s)
entries = zipfile.ZipFile(tf).namelist()
parts = ('SYSTEM', 'SYSTEM_EXT', 'PRODUCT', 'VENDOR', 'ODM')
survivors = []
for n in names:
    # app dir; an overlay APK named <name>.apk anywhere under overlay/ (icon packs sit in
    # overlay/IconPackFooLauncher/IconPackFooLauncherOverlay.apk); the app's auto-generated RRO
    # (overlay/<name>__<product>__auto_generated_rro_*.apk)
    pre = tuple(f'{p}/{d}/{n}/' for p in parts for d in ('app', 'priv-app'))
    def is_hit(e):
        if e.startswith(pre):
            return True
        if e.split('/')[0] in parts and '/overlay/' in e:
            base = e.rsplit('/', 1)[-1]
            return base == f'{n}.apk' or base.startswith(f'{n}__')
        return False
    hit = [e for e in entries if is_hit(e)]
    if hit:
        apk = [e for e in hit if e.endswith('.apk')]
        # no APK = only dangling JNI-lib symlinks left in the staging dir (see build-rung.sh scrub)
        survivors.append((n, apk[0] if apk else f'{hit[-1]}  (no APK: stale staging leftover)'))
apps = sorted({'/'.join(e.split('/')[:3]) for e in entries
               if re.match(r'(SYSTEM|SYSTEM_EXT|PRODUCT|VENDOR)/(app|priv-app)/[^/]+/[^/]+\.apk$', e)})
print(f'{len(names)} active overrides; {len(apps)} APKs remain in the image:')
for a in apps:
    print('   ', a)
if survivors:
    print('FAIL: overridden modules still packaged:')
    for n, e in survivors:
        print(f'    {n}: {e}')
    sys.exit(1)
print('OK: no overridden module is packaged')
EOF
