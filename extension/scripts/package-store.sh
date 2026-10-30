#!/usr/bin/env bash
# Package the Phone Vault browser extension for the Chrome Web Store and Firefox Add-ons (AMO).
# Builds from source with build.mjs, checks that the manifests and code stay minimal, and writes
# the two store zips, a zip for unpacked installs, and SHA256SUMS. Nothing is uploaded.
#
#   extension/scripts/package-store.sh              # -> extension/dist/store/ (gitignored)
#   OUT_DIR=/some/scratch extension/scripts/package-store.sh
#
# Store differences from the unpacked build (dist/chrome, dist/firefox):
#  - Chrome Web Store: the manifest "key" is removed (the store refuses uploads that carry one and
#    signs with its own key). The store-assigned ID therefore differs from the unpacked ID
#    fbomijndbpoddicmbngledanaafapmlk. The companion's native host admits only pinned IDs
#    (companion/src-tauri/src/bridge, CHROME_EXTENSION_ID), so the store ID must be pinned there
#    before the store build can reach the companion (release/beta/STORE_LISTING.md).
#  - Firefox: browser_specific_settings.gecko.data_collection_permissions = {"required": ["none"]},
#    the data-collection declaration AMO requires for new add-ons.
set -euo pipefail

ext="$(cd "$(dirname "$0")/.." && pwd)"          # extension/
OUT_DIR="${OUT_DIR:-${ext}/dist/store}"
die() { echo "package-store: $*" >&2; exit 1; }
command -v node >/dev/null || die "node not found"
command -v zip >/dev/null || die "zip not found"

node "${ext}/build.mjs"
version="$(node -p "require('${ext}/package.json').version")"

stage="$(mktemp -d)"
trap 'rm -rf "${stage}"' EXIT
mkdir -p "${OUT_DIR}"

for target in chrome firefox; do
  src="${ext}/dist/${target}"
  dst="${stage}/${target}"
  cp -R "${src}" "${dst}"
  find "${dst}" -name '.DS_Store' -delete

  # Store-specific manifest edits, then the minimality checks on the result.
  node - "${dst}/manifest.json" "${target}" <<'JS'
const fs = require("fs");
const [file, target] = process.argv.slice(2);
const m = JSON.parse(fs.readFileSync(file, "utf8"));
const fail = (msg) => { console.error(`package-store (${target}): ${msg}`); process.exit(1); };

if (target === "chrome") delete m.key;
if (target === "firefox") {
  m.browser_specific_settings.gecko.data_collection_permissions = { required: ["none"] };
}

const allowedKeys = new Set(["manifest_version", "name", "version", "description", "icons", "action",
  "permissions", "content_scripts", "background", "minimum_chrome_version", "browser_specific_settings"]);
for (const k of Object.keys(m)) if (!allowedKeys.has(k)) fail(`unexpected manifest key "${k}"`);
if (m.manifest_version !== 3) fail("not MV3");
const perms = JSON.stringify([...(m.permissions ?? [])].sort());
if (perms !== JSON.stringify(["activeTab", "nativeMessaging"])) fail(`permissions changed: ${perms}`);
for (const k of ["host_permissions", "optional_permissions", "optional_host_permissions",
  "web_accessible_resources", "externally_connectable", "content_security_policy", "update_url"]) {
  if (k in m) fail(`"${k}" present`);
}
const okMatches = JSON.stringify(["https://*/*", "http://localhost/*", "http://127.0.0.1/*", "http://[::1]/*"]);
for (const cs of m.content_scripts) {
  if (JSON.stringify(cs.matches) !== okMatches) fail(`content script matches changed: ${JSON.stringify(cs.matches)}`);
  if (cs.all_frames !== false) fail("content script runs in all frames");
}
if (target === "chrome" && "key" in m) fail("key still present");
fs.writeFileSync(file, JSON.stringify(m, null, 2) + "\n");
console.log(`${target}: manifest ok (permissions ${perms})`);
JS

  # No remote code: no network fetches, no dynamic code, no remote script tags.
  if grep -nE '\beval\s*\(|new Function\s*\(|importScripts\s*\(|\bfetch\s*\(|XMLHttpRequest|WebSocket\s*\(|import\s*\(' "${dst}"/*.js; then
    die "${target}: dynamic code or network access found (see above)"
  fi
  if grep -niE '<script[^>]+src=["'"'"']?(https?:)?//' "${dst}"/*.html; then
    die "${target}: remote script in HTML"
  fi
  # Only what build.mjs produces.
  extra="$(cd "${dst}" && find . -type f | sed 's|^\./||' | grep -vE '^(manifest\.json|background\.js|content\.js|inpage\.js|popup\.(html|js|css)|icons/icon-(16|32|48|128)\.png)$' || true)"
  [[ -z "${extra}" ]] || die "${target}: unexpected files: ${extra}"

  zipname="phone-vault-extension-${version}-${target}.zip"
  rm -f "${OUT_DIR}/${zipname}"
  find "${dst}" -exec touch -h -t 202601010000 {} +   # fixed mtimes: same sources, same zip hash
  # -X: no extra file attributes; files at the zip root, sorted for a stable listing.
  (cd "${dst}" && find . -type f | sed 's|^\./||' | LC_ALL=C sort | TZ=UTC zip -X -q "${OUT_DIR}/${zipname}" -@)
  unzip -l "${OUT_DIR}/${zipname}" | tail -n +1
done

# For testers who load the extension unpacked until the store listing exists: the Chrome build
# WITH its manifest key, so the ID stays fbomijndbpoddicmbngledanaafapmlk and the companion admits it.
# Not for store upload.
unpacked="phone-vault-extension-${version}-chromium-unpacked.zip"
rm -f "${OUT_DIR}/${unpacked}"
find "${ext}/dist/chrome" -exec touch -h -t 202601010000 {} +
(cd "${ext}/dist/chrome" && find . -type f ! -name '.DS_Store' | sed 's|^\./||' | LC_ALL=C sort | TZ=UTC zip -X -q "${OUT_DIR}/${unpacked}" -@)
node -e 'const m=JSON.parse(require("child_process").execFileSync("unzip",["-p",process.argv[1],"manifest.json"]));if(!m.key)process.exit(1)' "${OUT_DIR}/${unpacked}" \
  || die "unpacked zip lost its manifest key"

(cd "${OUT_DIR}" && shasum -a 256 "phone-vault-extension-${version}-chrome.zip" "phone-vault-extension-${version}-firefox.zip" "${unpacked}" > SHA256SUMS)
echo "== ${OUT_DIR}"
cat "${OUT_DIR}/SHA256SUMS"
