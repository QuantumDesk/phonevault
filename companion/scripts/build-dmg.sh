#!/usr/bin/env bash
# Build the Phone Vault Companion DMG for macOS, unsigned by default, signed and notarized when
# the Apple Developer ID variables below are set. Nothing is uploaded or published.
#
#   companion/scripts/build-dmg.sh                 # unsigned DMG (testers: right-click -> Open)
#   OUT_DIR=~/pv-dist companion/scripts/build-dmg.sh   # also copy the DMG + its .sha256 there
#   UNIVERSAL=1 companion/scripts/build-dmg.sh     # arm64 + x86_64 (needs both rustup targets)
#
# Toolchain: Node 22 (default ~/.nvm/versions/node/v22.23.2/bin, override with NODE_BIN), Rust from
# rust-toolchain.toml, Xcode command-line tools. CARGO_TARGET_DIR is honoured (point it at a scratch
# directory to keep build output out of the checkout). libusb is linked statically by rusb, so the
# app needs nothing from Homebrew at run time (checked below with otool).
#
# Signing and notarization (only once an Apple Developer ID exists; leave unset until then).
# Tauri reads these itself during `tauri build`:
#   APPLE_SIGNING_IDENTITY  "Developer ID Application: <Name> (<TEAMID>)"   (in the login keychain)
#   either an App Store Connect API key (preferred for automation):
#     APPLE_API_ISSUER      issuer UUID
#     APPLE_API_KEY         key ID
#     APPLE_API_KEY_PATH    path to AuthKey_<KEYID>.p8 (never committed)
#   or an Apple ID with an app-specific password:
#     APPLE_ID              developer Apple ID e-mail
#     APPLE_PASSWORD        app-specific password (not the account password)
#     APPLE_TEAM_ID         10-character team ID
# With APPLE_SIGNING_IDENTITY and one of the credential sets, Tauri signs with the hardened runtime,
# submits to Apple's notary service, waits, and staples the ticket. The script then checks the
# result with spctl/stapler. See release/beta/COMPANION_DISTRIBUTION.md.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"          # companion/
NODE_BIN="${NODE_BIN:-${HOME}/.nvm/versions/node/v22.23.2/bin}"
die() { echo "build-dmg: $*" >&2; exit 1; }

[[ -x "${NODE_BIN}/node" ]] || die "no node at ${NODE_BIN}/node (set NODE_BIN to a Node 22 bin directory)"
export PATH="${NODE_BIN}:${PATH}"
node_major="$(node -p 'process.versions.node.split(".")[0]')"
[[ "${node_major}" == 22 ]] || die "Node 22 required, found $(node --version)"
command -v cargo >/dev/null || die "no cargo in PATH (install Rust via rustup)"
[[ "$(uname -s)" == Darwin ]] || die "a DMG can only be built on macOS"

signed=0
if [[ -n "${APPLE_SIGNING_IDENTITY:-}" ]]; then
  signed=1
  if [[ -z "${APPLE_API_KEY:-}" && -z "${APPLE_ID:-}" ]]; then
    die "APPLE_SIGNING_IDENTITY is set but no notarization credentials (APPLE_API_* or APPLE_ID/APPLE_PASSWORD/APPLE_TEAM_ID)"
  fi
  security find-identity -v -p codesigning | grep -qF "${APPLE_SIGNING_IDENTITY}" \
    || die "signing identity not in the keychain: ${APPLE_SIGNING_IDENTITY}"
  echo "== signing as ${APPLE_SIGNING_IDENTITY}, notarizing"
else
  echo "== no APPLE_SIGNING_IDENTITY: building an UNSIGNED DMG (not notarized)"
fi

cd "${here}"
version="$(node -p 'require("./src-tauri/tauri.conf.json").version')"
echo "== Phone Vault Companion ${version}, node $(node --version), $(cargo --version)"

# The bundle embeds the printable backup cards; build fails later without them.
for f in a4-compact25 a4-standard29 letter-compact25 letter-standard29; do
  [[ -s "../tools/backup-card/out/phone-vault-backup-card-${f}.pdf" ]] \
    || die "missing tools/backup-card/out/phone-vault-backup-card-${f}.pdf (see tools/backup-card)"
done

npm ci --no-audit --no-fund

target_args=()
if [[ "${UNIVERSAL:-0}" == 1 ]]; then target_args=(--target universal-apple-darwin); fi
npx tauri build --bundles dmg "${target_args[@]}"

target_root="${CARGO_TARGET_DIR:-${here}/src-tauri/target}"
if [[ "${UNIVERSAL:-0}" == 1 ]]; then bundle_dir="${target_root}/universal-apple-darwin/release/bundle"
else bundle_dir="${target_root}/release/bundle"; fi
shopt -s nullglob
dmgs=("${bundle_dir}"/dmg/*.dmg)
[[ ${#dmgs[@]} == 1 ]] || die "expected one DMG under ${bundle_dir}/dmg, found ${#dmgs[@]}"
dmg="${dmgs[0]}"
[[ -n "${dmg}" && -s "${dmg}" ]] || die "no DMG under ${bundle_dir}/dmg"

echo "== checks"
hdiutil verify "${dmg}" >/dev/null && echo "hdiutil verify: ok"
# Look inside the DMG itself (the intermediate .app is not kept when only the dmg bundle is built).
mnt="$(mktemp -d)"
trap 'hdiutil detach -quiet "${mnt}" 2>/dev/null || true; rmdir "${mnt}" 2>/dev/null || true' EXIT
hdiutil attach -quiet -nobrowse -readonly -mountpoint "${mnt}" "${dmg}"
apps=("${mnt}"/*.app)
[[ ${#apps[@]} == 1 && -d "${apps[0]}" ]] || die "expected one .app inside the DMG"
app="${apps[0]}"
bin="${app}/Contents/MacOS/$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "${app}/Contents/Info.plist")"
[[ -x "${bin}" ]] || die "no executable at ${bin}"
echo "app: $(basename "${app}"), version $(/usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' "${app}/Contents/Info.plist"), archs $(lipo -archs "${bin}")"
if otool -L "${bin}" | grep -E '/opt/homebrew|/usr/local'; then
  die "the companion links a Homebrew library; it would not start on a Mac without it"
fi
echo "linked libraries: system only"
if [[ "${signed}" == 1 ]]; then
  codesign --verify --deep --strict --verbose=2 "${app}"
  xcrun stapler validate "${dmg}"
  spctl -a -vvv -t open --context context:primary-signature "${dmg}"
else
  codesign -dv "${app}" 2>&1 | grep -E '^(Signature|TeamIdentifier)' || true
  echo "unsigned: Gatekeeper will block a double-click; testers use right-click -> Open (or System Settings -> Privacy & Security -> Open Anyway)"
fi
hdiutil detach -quiet "${mnt}"; rmdir "${mnt}"; trap - EXIT

sum="$(shasum -a 256 "${dmg}" | awk '{print $1}')"
echo "== ${dmg}"
echo "sha256 ${sum}"
if [[ -n "${OUT_DIR:-}" ]]; then
  mkdir -p "${OUT_DIR}"
  cp "${dmg}" "${OUT_DIR}/"
  (cd "${OUT_DIR}" && shasum -a 256 "$(basename "${dmg}")" > "$(basename "${dmg}").sha256")
  echo "copied to ${OUT_DIR}"
fi
