// Headless end-to-end test of the browser extension against the REAL bridge code.
//
//   page (test/page.html on 127.0.0.1) ─ EIP-6963 / EIP-1193 ─ inpage.js ─ content.js ─ background.js
//     ─ native messaging ─ bridge_e2e (as native host: bridge::native_host_main)
//     ─ Unix socket ─ bridge_e2e (as companion: bridge::Bridge with a scripted "user")
//
// The scripted user approves connections and network switches and REJECTS every signing request:
// nothing is signed and no phone is involved. Everything runs in a temporary Chrome profile and a
// temporary directory; the real Chrome profile and the real companion socket are not touched.
//
// Needs Chrome for Testing or Chromium (branded Chrome ignores --load-extension since 137):
// CHROME_PATH=..., or the newest one puppeteer cached in ~/.cache/puppeteer.
//
//   node build.mjs && node test/e2e.mjs        (or: npm test)

import { spawn, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, readdirSync, rmSync, copyFileSync, chmodSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir, homedir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, "..", "..");
const extDir = join(here, "..", "dist", "chrome");
const outDir = process.env.SCREENSHOT_DIR ?? join(here, "output");
const EXT_ID = "fbomijndbpoddicmbngledanaafapmlk";
const ADDRESS = "0x7A3B9C1d2e4F5061728394a5b6c7d8E9F0a1b2C3"; // bridge_e2e TEST_ADDRESS, checksummed
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (ok, what, detail) => { console.log(`${ok ? "ok  " : "FAIL"} ${what}${ok || detail === undefined ? "" : ` — got ${JSON.stringify(detail)}`}`); if (!ok) failures++; };

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;
  const base = join(homedir(), ".cache", "puppeteer", "chrome");
  if (existsSync(base)) {
    const builds = readdirSync(base).filter((d) => d.startsWith("mac")).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
    for (const b of builds.reverse()) {
      for (const arch of ["chrome-mac-arm64", "chrome-mac-x64"]) {
        const p = join(base, b, arch, "Google Chrome for Testing.app", "Contents", "MacOS", "Google Chrome for Testing");
        if (existsSync(p)) return p;
      }
    }
  }
  for (const p of ["/Applications/Chromium.app/Contents/MacOS/Chromium"]) if (existsSync(p)) return p;
  throw new Error("No Chrome for Testing / Chromium found. Set CHROME_PATH (branded Chrome cannot load unpacked extensions from the command line).");
}

// ------------------------------------------------------------------ minimal CDP client
class Cdp {
  constructor(url) { this.ws = new WebSocket(url); this.id = 0; this.waiting = new Map(); this.ws.onmessage = (e) => { const m = JSON.parse(e.data); const w = this.waiting.get(m.id); if (w) { this.waiting.delete(m.id); m.error ? w.reject(new Error(m.error.message)) : w.resolve(m.result); } }; }
  open() { return new Promise((res, rej) => { this.ws.onopen = res; this.ws.onerror = rej; }); }
  send(method, params = {}, sessionId) { const id = ++this.id; this.ws.send(JSON.stringify({ id, method, params, sessionId })); return new Promise((resolve, reject) => this.waiting.set(id, { resolve, reject })); }
}

async function main() {
  const work = mkdtempSync(join(tmpdir(), "pv-e2e-"));
  const profile = join(work, "profile");
  const socket = join(work, "b.sock");
  if (socket.length > 100) throw new Error(`socket path too long: ${socket}`);
  mkdirSync(join(profile, "NativeMessagingHosts"), { recursive: true });
  mkdirSync(outDir, { recursive: true });

  console.log("building the bridge harness (cargo build --example bridge_e2e)…");
  execFileSync("cargo", ["build", "--quiet", "--example", "bridge_e2e", "--manifest-path", join(root, "companion", "src-tauri", "Cargo.toml")], { stdio: "inherit" });
  // Run it from the temp dir: macOS privacy protection (TCC) blocks a browser-started process from
  // reading a binary under ~/Documents, and the host must be the same file as the "companion".
  const harness = join(work, "bridge_e2e");
  copyFileSync(join(root, "companion", "src-tauri", "target", "debug", "examples", "bridge_e2e"), harness);
  chmodSync(harness, 0o755);
  // Host manifest in the TEMPORARY profile only (Chrome reads <user-data-dir>/NativeMessagingHosts).
  writeFileSync(join(profile, "NativeMessagingHosts", "dev.phonevault.json"), JSON.stringify({
    name: "dev.phonevault", description: "Phone Vault test host", path: harness, type: "stdio", allowed_origins: [`chrome-extension://${EXT_ID}/`],
  }));

  const env = { ...process.env, PHONEVAULT_BRIDGE_SOCKET: socket };
  const companion = spawn(harness, ["serve"], { env, stdio: ["ignore", "pipe", "inherit"] });
  const decisions = [];
  let ready;
  const readyP = new Promise((r) => (ready = r));
  let buf = "";
  companion.stdout.on("data", (d) => { buf += d; let i; while ((i = buf.indexOf("\n")) >= 0) { const line = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1); if (line.ready) ready(); if (line.pending) decisions.push(line.pending); } });
  await readyP;

  const page = readFileSync(join(here, "page.html"));
  const server = createServer((_, res) => { res.writeHead(200, { "content-type": "text/html; charset=utf-8" }); res.end(page); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const origin = `http://127.0.0.1:${server.address().port}`;

  const chrome = spawn(findChrome(), [
    "--headless=new", `--user-data-dir=${profile}`, "--remote-debugging-port=0", "--no-first-run", "--no-default-browser-check",
    `--load-extension=${extDir}`, `--disable-extensions-except=${extDir}`, "--disable-features=DisableLoadExtensionCommandLineSwitch",
    "--window-size=900,1100", "about:blank",
  ], { env, stdio: "ignore" });

  const cleanup = () => { try { chrome.kill(); } catch {} try { companion.kill(); } catch {} server.close(); };
  try {
    let portFile = join(profile, "DevToolsActivePort");
    for (let i = 0; i < 100 && !existsSync(portFile); i++) await sleep(100);
    const [port, path] = readFileSync(portFile, "utf8").trim().split("\n");
    const cdp = new Cdp(`ws://127.0.0.1:${port}${path}`);
    await cdp.open();
    await sleep(800); // let the extension's worker start
    const { targetId } = await cdp.send("Target.createTarget", { url: `${origin}/` });
    const { sessionId } = await cdp.send("Target.attachToTarget", { targetId, flatten: true });
    const evaluate = async (expr) => (await cdp.send("Runtime.evaluate", { expression: expr, awaitPromise: true, returnByValue: true }, sessionId)).result.value;
    await cdp.send("Emulation.setDeviceMetricsOverride", { width: 760, height: 1000, deviceScaleFactor: 2, mobile: false }, sessionId);

    // 1. EIP-6963 announcement
    let providers = [];
    for (let i = 0; i < 50 && !providers.length; i++) { await sleep(100); providers = await evaluate(`window.__providers.map(p => p.info)`); }
    const pv = providers.filter((p) => p.rdns === "dev.phonevault");
    check(pv.length === 1, "announces exactly one EIP-6963 provider with rdns dev.phonevault", providers);
    check(pv[0]?.name === "Phone Vault", "provider name is Phone Vault", pv[0]?.name);
    check(/^data:image\/svg\+xml;base64,/.test(pv[0]?.icon ?? ""), "icon is an SVG data URI", pv[0]?.icon?.slice(0, 30));
    check(/^[0-9a-f-]{36}$/.test(pv[0]?.uuid ?? ""), "uuid is a v4 UUID", pv[0]?.uuid);
    check(await evaluate(`window.dispatchEvent(new Event("eip6963:requestProvider")), window.__providers.length === 1`), "re-announce on request keeps one entry (same uuid)");
    check(await evaluate(`window.ethereum?.isPhoneVault === true`), "window.ethereum set (no other wallet present)");

    const swState = async () => {
      const { targetInfos } = await cdp.send("Target.getTargets");
      const sw = targetInfos.find((t) => t.type === "service_worker" && t.url.includes(EXT_ID));
      if (!sw) return "no service worker";
      const { sessionId: s2 } = await cdp.send("Target.attachToTarget", { targetId: sw.targetId, flatten: true });
      return (await cdp.send("Runtime.evaluate", { expression: `({ nativeState, nativeMessage, pending: pending.size, ports: ports.size })`, returnByValue: true }, s2)).result.value;
    };
    if (process.env.E2E_DEBUG) { await evaluate(`window.__providers[0].provider.request({method:"eth_chainId"}).catch(()=>0), 1`); await sleep(1500); console.log("worker:", await swState()); }

    // 2. Before connecting: chain visible, accounts empty, signing refused
    check((await evaluate(`call("eth_chainId", [])`)).result === "0x2105", "eth_chainId before connect = Base");
    check(JSON.stringify((await evaluate(`call("eth_accounts", [])`)).result) === "[]", "eth_accounts before connect = []");
    check((await evaluate(`call("personal_sign", ["0x68656c6c6f", "${ADDRESS}"])`)).error?.code === 4100, "personal_sign before connect → 4100");
    check((await evaluate(`call("eth_getBalance", ["${ADDRESS}", "latest"])`)).error?.code === 4100, "read-only call before connect → 4100");

    // 3. Connect (the scripted user approves Base + Ethereum)
    const conn = await evaluate(`call("eth_requestAccounts", [])`);
    check(JSON.stringify(conn.result) === JSON.stringify([ADDRESS]), "eth_requestAccounts → paired address after approval", conn);
    await sleep(200);
    const events = await evaluate(`window.__events`);
    check(events.some((e) => e.name === "accountsChanged" && e.data[0] === ADDRESS), "accountsChanged event delivered", events);
    check((await evaluate(`call("eth_chainId", [])`)).result === "0x2105", "active network after connect = Base");

    // 4. Network switches: approved network is immediate, a new one goes to the user
    check((await evaluate(`call("wallet_switchEthereumChain", [{ chainId: "0x1" }])`)).result === null, "switch to an approved network");
    check((await evaluate(`call("wallet_switchEthereumChain", [{ chainId: "0xa" }])`)).result === null, "switch to a new allowed network (user approves)");
    check((await evaluate(`call("wallet_switchEthereumChain", [{ chainId: "0x38" }])`)).error?.code === 4902, "switch to a chain the phone has no profile for → 4902");
    await sleep(200);
    check((await evaluate(`window.__events.filter(e => e.name === "chainChanged").map(e => e.data).join()`)) === "0x1,0xa", "chainChanged events 0x1 then 0xa");

    // 5. Signing reaches the user's queue (and is rejected there); bad params never do
    check((await evaluate(`call("personal_sign", ["0x68656c6c6f", "${ADDRESS}"])`)).error?.code === 4001, "personal_sign → queued for the user → rejected (4001)");
    check((await evaluate(`call("eth_sendTransaction", [{ from: "${ADDRESS}", to: "0x1111111111111111111111111111111111111111", value: "0x1" }])`)).error?.code === 4001, "eth_sendTransaction → queued → rejected (4001)");
    check((await evaluate(`call("eth_sendTransaction", [{ from: "0x1111111111111111111111111111111111111111", to: "0x1111111111111111111111111111111111111111" }])`)).error?.code === 4100, "eth_sendTransaction from another account → 4100 (never queued)");
    check((await evaluate(`call("eth_sign", ["${ADDRESS}", "0x${"ab".repeat(32)}"])`)).error?.code === 4200, "eth_sign → 4200");
    check((await evaluate(`call("eth_signTransaction", [{}])`)).error?.code === 4200, "eth_signTransaction → 4200");
    check((await evaluate(`call("eth_blockNumber", [])`)).error?.code === 4901, "read-only call goes to the node path (no node in the harness → 4901)");
    check((await evaluate(`call("eth_call", [{ to: "0x1111111111111111111111111111111111111111", data: "0x" + "00".repeat(300000) }, "latest"])`)).error?.code === -32602, "oversized request refused in the page (-32602)");

    // 6. A page cannot claim another origin
    await evaluate(`window.postMessage({ target: "phonevault:page->cs", id: 9999, method: "personal_sign", params: ["0x01", "${ADDRESS}"], origin: "https://app.uniswap.org" }, location.origin), new Promise(r => setTimeout(r, 400))`);
    const seen = [...new Set(decisions.map((d) => d.origin))];
    check(seen.length === 1 && seen[0] === origin, `every queued request carried the browser-reported origin ${origin}`, seen);
    check(decisions.some((d) => d.method === "personal_sign") && decisions.some((d) => d.method === "eth_sendTransaction") && !decisions.some((d) => d.method === "eth_sign"), "only reviewable requests reached the queue", decisions.map((d) => d.method));

    await evaluate(`new Promise(r => setTimeout(r, 300))`);
    const shot = await cdp.send("Page.captureScreenshot", { format: "png", captureBeyondViewport: true }, sessionId);
    writeFileSync(join(outDir, "extension-test-dapp.png"), Buffer.from(shot.data, "base64"));
    console.log(`screenshot: ${join(outDir, "extension-test-dapp.png")}`);

    // 7. The site disconnects itself
    check((await evaluate(`call("wallet_revokePermissions", [{ eth_accounts: {} }])`)).result === null, "wallet_revokePermissions");
    check(JSON.stringify((await evaluate(`call("eth_accounts", [])`)).result) === "[]", "eth_accounts after revoke = []");
  } finally {
    cleanup();
    await sleep(300);
    rmSync(work, { recursive: true, force: true });
  }
  console.log(failures ? `\n${failures} check(s) FAILED` : "\nall checks passed");
  process.exit(failures ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
