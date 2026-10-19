#!/usr/bin/env bash
# Resolve one bluejay beta configuration into a flat directory with a rung's layout
# (common.mk, BoardConfigVault.mk, Android.bp, config.xml, the four upstream diffs,
# expect-build.txt), so that sync-beta.sh, build-beta.sh and dev-ladder-bluejay/check-build.sh
# treat it exactly like a rung directory.
#   resolve-beta.sh BETA OUTDIR
#     BETA    a directory release-bluejay/BETA (beta1, beta1-novoice, ...)
#     OUTDIR  created/emptied; receives the resolved files plus RESOLVED.txt (the chain)
#
# A beta directory holds BASE ("rung RUNG" = dev-ladder-bluejay/rung-RUNG, or "beta NAME" =
# another release-bluejay/NAME, resolved first) and only the files it changes. Its files replace
# the base's, except expect-build.txt, which is appended (the base's expectations keep holding).
set -euo pipefail
BETA="${1:?usage: resolve-beta.sh BETA OUTDIR}"
OUTDIR="${2:?usage: resolve-beta.sh BETA OUTDIR}"
OVERLAY="$(cd "$(dirname "$0")/.." && pwd)"
FILES=(common.mk BoardConfigVault.mk Android.bp config.xml expect-build.txt
       device-google-bluejay.diff device-google-gs101.diff vendor-google-bluejay.diff
       device-google-bluejay-kernels.diff)

resolve() {
  local dir="$1" depth="$2" kind name base f
  (( depth < 8 )) || { echo "BASE chain too deep at ${dir}" >&2; exit 2; }
  [[ -s "${dir}/BASE" ]] || { echo "no BASE in ${dir}" >&2; exit 2; }
  read -r kind name < "${dir}/BASE"
  case "${kind}" in
    rung)
      base="${OVERLAY}/dev-ladder-bluejay/rung-${name}"
      [[ -d "${base}" ]] || { echo "BASE names a missing rung: ${base}" >&2; exit 2; }
      for f in "${FILES[@]}"; do
        [[ -f "${base}/${f}" ]] && install -m 0644 "${base}/${f}" "${OUTDIR}/${f}"
      done
      echo "rung ${name} (dev-ladder-bluejay/rung-${name})" >> "${OUTDIR}/RESOLVED.txt"
      ;;
    beta)
      base="${OVERLAY}/release-bluejay/${name}"
      [[ -d "${base}" ]] || { echo "BASE names a missing beta: ${base}" >&2; exit 2; }
      resolve "${base}" $((depth + 1))
      ;;
    *) echo "bad BASE in ${dir}: ${kind} ${name}" >&2; exit 2 ;;
  esac
  for f in "${dir}"/*; do
    f="$(basename "${f}")"
    case "${f}" in
      BASE|README.md) ;;
      expect-build.txt)
        { echo; echo "# ---- appended from release-bluejay/$(basename "${dir}")/expect-build.txt"
          cat "${dir}/${f}"; } >> "${OUTDIR}/expect-build.txt" ;;
      *)
        printf '%s\n' "${FILES[@]}" | grep -Fqx "${f}" \
          || { echo "unexpected file in ${dir}: ${f}" >&2; exit 2; }
        install -m 0644 "${dir}/${f}" "${OUTDIR}/${f}" ;;
    esac
  done
  echo "beta $(basename "${dir}") (release-bluejay/$(basename "${dir}"))" >> "${OUTDIR}/RESOLVED.txt"
}

BETA_DIR="${OVERLAY}/release-bluejay/${BETA}"
[[ -d "${BETA_DIR}" ]] || { echo "no such beta: ${BETA_DIR}" >&2; exit 2; }
mkdir -p "${OUTDIR}"
find "${OUTDIR}" -mindepth 1 -maxdepth 1 -type f -delete
resolve "${BETA_DIR}" 0
for f in common.mk BoardConfigVault.mk Android.bp; do
  [[ -s "${OUTDIR}/${f}" ]] || { echo "resolved ${BETA} lacks ${f}" >&2; exit 2; }
done
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
( cd "${OUTDIR}" && sha256 $(ls | grep -v '^RESOLVED.txt$' | sort) >> RESOLVED.txt )
echo "resolved ${BETA} -> ${OUTDIR}: $(grep -E '^(rung|beta) ' "${OUTDIR}/RESOLVED.txt" | tr '\n' ' ')"
