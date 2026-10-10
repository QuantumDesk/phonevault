#!/usr/bin/env bash
# Sync the Pixel 6a (bluejay) sources: a SEPARATE LineageOS 24.0 tree plus the gs-6.1 kernel
# workspace. Never touches the crosshatch lineage-22.2 tree except to borrow its repo launcher.
# Runs as the tree owner (aipg). Typical start (as root, so the log can live in /root):
#   mkdir -p /root/lineage-24 /root/gs-6.1-kernel && chown aipg:aipg /root/lineage-24 /root/gs-6.1-kernel
#   install -m 0644 local_manifests-bluejay.xml /root/bluejay-local-manifest.xml
#   nohup su aipg -s /bin/bash -c 'bash /root/sync-bluejay.sh' > /root/bluejay-sync.log 2>&1 &
# Re-running resumes: repo init is skipped once done, repo sync is incremental.
set -uo pipefail
# repo wants an identity; give it one without editing anybody's ~/.gitconfig.
export GIT_CONFIG_COUNT=2
export GIT_CONFIG_KEY_0=user.name  GIT_CONFIG_VALUE_0="Phone Vault build"
export GIT_CONFIG_KEY_1=user.email GIT_CONFIG_VALUE_1="build@phonevault.invalid"
LAUNCHER="${PV_REPO_LAUNCHER:-/root/lineage-src/.repo/repo/repo}"
T="${PV_BLUEJAY_TREE:-/root/lineage-24}"
K="${PV_BLUEJAY_KERNEL:-/root/gs-6.1-kernel}"
LOCAL_MANIFEST="${PV_BLUEJAY_MANIFEST:-/root/bluejay-local-manifest.xml}"
stamp(){ echo "=== $(date '+%F %T') $*; disk: $(df -h / | awk 'NR==2{print $4" free"}')"; }

stamp "start (tree ${T}, kernel ${K})"
cd "${T}" || exit 2
if [[ ! -d .repo/manifests ]]; then
  "${LAUNCHER}" init -u https://github.com/LineageOS/android.git -b lineage-24.0 \
    --git-lfs --depth=1 --no-clone-bundle -g default,-darwin,-notdefault </dev/null \
    || { stamp "INIT FAILED"; exit 3; }
fi
mkdir -p .repo/local_manifests
install -m 0644 "${LOCAL_MANIFEST}" .repo/local_manifests/bluejay.xml
ok=0
for attempt in 1 2 3; do
  stamp "main sync attempt ${attempt}"
  if .repo/repo/repo sync -c --no-tags --no-clone-bundle --optimized-fetch -j8 </dev/null; then
    ok=1; break
  fi
  sleep 120
done
stamp "main sync ok=${ok}"
[[ ${ok} -eq 1 ]] || { stamp "MAIN SYNC FAILED"; exit 4; }

cd "${K}" || exit 5
if [[ ! -d .repo/manifests ]]; then
  "${LAUNCHER}" init -u https://github.com/LineageOS/android_kernel_google_gs-6.1_manifest.git \
    -b lineage-24.0 --depth=1 --no-clone-bundle </dev/null || { stamp "KERNEL INIT FAILED"; exit 6; }
fi
kok=0
for attempt in 1 2 3; do
  stamp "kernel sync attempt ${attempt}"
  if .repo/repo/repo sync -c --no-tags --no-clone-bundle -j8 </dev/null; then kok=1; break; fi
  sleep 120
done
stamp "kernel sync ok=${kok}"
du -sh "${T}" "${K}" 2>/dev/null
[[ ${kok} -eq 1 ]] || { stamp "KERNEL SYNC FAILED"; exit 7; }
stamp "ALL DONE"
