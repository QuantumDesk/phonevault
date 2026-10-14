// Browser extension, companion side. The Phone Vault extension is one more dApp transport next to
// WalletConnect: this module presents it to walletconnect.ts as a `Backend`, so a site's requests
// get the same cards and go through the same verified commands (wc_prepare → sign_start →
// broadcast_verified, sign_message / sign_typed_data). The rules live in Rust (bridge.rs, reusing
// wc.rs); this file only shows and forwards.
//
// Trust boundaries:
//  * The site's origin is the one the BROWSER reported (bridge.rs checks its form); it is shown
//    as-is. The site never supplies the account: Rust answers with the paired address.
//  * A request reaches this queue only after Rust's checks (connected site, wc.rs parameters).
//  * What goes back is limited by Rust to a verified hash, a verified signature, or null.

import { call, registerPreview, onEvent } from "./api";
import { NETWORKS, netName } from "./networks";
import { h, icon, copy, toast } from "./ui";
import type { Backend, Events, ProposalIn, RequestIn, SessionIn, VerifyIn } from "./wc-backend";

const EXT_PREFIX = "ext:";
export const isExtTopic = (topic: string) => topic.startsWith(EXT_PREFIX);
const originOf = (topic: string) => topic.slice(EXT_PREFIX.length);

interface PendingOut { id: number; kind: "connect" | "request"; origin: string; host: string; local: boolean; method: string; params: unknown; chain_id: number; created: number }
interface SiteOut { origin: string; host: string; local: boolean; chains: number[]; active: number; connected_at: number; address: string; current_pairing: boolean }
interface HostState { browser: string; path: string; browser_found: boolean; state: "installed" | "outdated" | "missing" | "foreign" }
export interface BridgeStatus { listening: boolean; error: string | null; socket: string; extension_id: string; firefox_id: string; connections: number; hosts: HostState[]; sites: SiteOut[]; exe: string; exe_error: string | null }

const SUPPORTED = ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "eth_chainId", "eth_accounts", "eth_requestAccounts", "wallet_switchEthereumChain"];
const ALL_CHAINS = NETWORKS.map((n) => n.id); // the phone's reviewed networks, app default first
const BRIDGE_POLL_MS = 2000;
const NODES_PUSH_MS = 10_000;

// ------------------------------------------------------------------ Rust calls (bridge_*: the preview mock below)

registerPreview((cmd) => cmd.startsWith("bridge_"), async () => previewInvoke);

// ------------------------------------------------------------------ state shared with Settings

let status: BridgeStatus | null = null;
let pending: PendingOut[] = [];
let onChange: () => void = () => {};
let busy: string | null = null;
let message: { text: string; tone: "ok" | "bad" } | null = null;

const verifyOf = (p: { origin: string; local: boolean }): VerifyIn => ({ validation: "VALID", origin: p.origin, isScam: false, source: "browser", local: p.local });

function sessionOf(s: SiteOut): SessionIn {
  return {
    topic: EXT_PREFIX + s.origin,
    meta: { name: s.host, url: s.origin, icons: [], description: "Connected through the Phone Vault browser extension." },
    namespaces: { eip155: { chains: s.chains.map((c) => `eip155:${c}`), accounts: s.chains.map((c) => `eip155:${c}:${s.address}`), methods: SUPPORTED, events: ["chainChanged", "accountsChanged"] } },
    expiry: 0,
  };
}

function proposalOf(p: PendingOut): ProposalIn {
  return {
    id: p.id,
    meta: { name: p.host, url: p.origin, icons: [], description: `${p.host} wants to connect through your browser. The site address is the one your browser reported, not one the site chose.` },
    required: {},
    optional: { eip155: { chains: ALL_CHAINS.map((c) => `eip155:${c}`), methods: SUPPORTED, events: ["chainChanged", "accountsChanged"] } },
    verify: verifyOf(p),
    expiry: 0,
  };
}

/** The extension as a WalletConnect-shaped backend. */
export function createExtBackend(ev: Events, rpcFor: (chainId: number) => string): Backend & { hasProposal(id: number): boolean } {
  let shownProposal: number | null = null;
  let snap = "";

  async function refresh() {
    try {
      const [st, pend] = await Promise.all([call<BridgeStatus>("bridge_status"), call<PendingOut[]>("bridge_pending")]);
      status = st; pending = pend;
    } catch { return; }
    // One connection card at a time; the next one appears when it is answered.
    const connects = pending.filter((p) => p.kind === "connect");
    if (shownProposal !== null && !connects.some((p) => p.id === shownProposal)) { ev.proposalExpired(shownProposal); shownProposal = null; }
    if (shownProposal === null && connects.length) { shownProposal = connects[0].id; ev.proposal(proposalOf(connects[0])); }
    const s = JSON.stringify([status?.sites, status?.hosts, status?.listening, status?.connections, pending.map((p) => p.id)]);
    if (s !== snap) { snap = s; ev.changed(); onChange(); }
  }

  const pushNodes = () => {
    const nodes: Record<string, string> = {};
    for (const n of NETWORKS) nodes[String(n.id)] = rpcFor(n.id);
    call("bridge_set_nodes", { nodes }).catch(() => {});
  };

  onEvent("bridge-changed", () => { void refresh(); }).catch(() => {});
  refresh(); pushNodes();
  window.setInterval(refresh, BRIDGE_POLL_MS);
  window.setInterval(pushNodes, NODES_PUSH_MS);
  refreshNow = refresh;

  const done = async () => { shownProposal = null; await refresh(); };
  return {
    hasProposal: (id) => pending.some((p) => p.id === id && p.kind === "connect"),
    pair: async () => { throw new Error("not a WalletConnect link"); },
    approve: async (id, namespaces) => {
      const chains = ((namespaces as { eip155?: { chains?: string[] } }).eip155?.chains ?? []).map((c) => Number(c.split(":")[1]));
      try { await call("bridge_approve_connect", { id, chains }); } finally { await done(); }
    },
    reject: async (id) => { try { await call("bridge_respond", { id, result: null, error: { code: 4001, message: "User rejected the request." } }); } finally { await done(); } },
    respond: async (_topic, id, result) => { await call("bridge_respond", { id, result, error: null }); await refresh(); },
    respondError: async (_topic, id, code, msg) => { await call("bridge_respond", { id, result: null, error: { code, message: msg } }); await refresh(); },
    update: async (topic, namespaces) => {
      const chains = ((namespaces as { eip155?: { chains?: string[] } }).eip155?.chains ?? []).map((c) => Number(c.split(":")[1]));
      await call("bridge_update_site", { origin: originOf(topic), chains, active: null }); await refresh();
    },
    emitChainChanged: async (topic, chainId) => { await call("bridge_update_site", { origin: originOf(topic), chains: null, active: chainId }); await refresh(); },
    disconnect: async (topic) => { await call("bridge_revoke", { origin: originOf(topic) }); await refresh(); },
    sessions: () => (status?.sites ?? []).map(sessionOf),
    requests: () => pending.filter((p) => p.kind === "request").map((p): RequestIn => ({ id: p.id, topic: EXT_PREFIX + p.origin, method: p.method, params: p.params, chainId: `eip155:${p.chain_id}`, verify: verifyOf(p), expiry: null })),
    isPending: (id) => pending.some((p) => p.id === id),
    online: () => false,
    relayError: () => null,
  };
}

let refreshNow: () => Promise<void> = async () => {};

/** WalletConnect (may be absent: no project ID) and the extension behind one Backend. Proposals
 *  and requests are routed by id / topic; the relay state is WalletConnect's. */
export function combine(wc: Backend | null, ext: Backend & { hasProposal(id: number): boolean }): Backend {
  const by = (topic: string) => (isExtTopic(topic) ? ext : wc ?? ext);
  return {
    pair: (uri) => (wc ? wc.pair(uri) : Promise.reject(new Error("WalletConnect is off"))),
    approve: (id, ns) => (ext.hasProposal(id) || !wc ? ext.approve(id, ns) : wc.approve(id, ns)),
    reject: (id) => (ext.hasProposal(id) || !wc ? ext.reject(id) : wc.reject(id)),
    respond: (t, id, r) => by(t).respond(t, id, r),
    respondError: (t, id, c, m) => by(t).respondError(t, id, c, m),
    update: (t, ns) => by(t).update(t, ns),
    emitChainChanged: (t, c) => by(t).emitChainChanged(t, c),
    disconnect: (t) => by(t).disconnect(t),
    sessions: () => [...(wc?.sessions() ?? []), ...ext.sessions()],
    requests: () => [...(wc?.requests() ?? []), ...ext.requests()],
    isPending: (id) => (wc?.isPending(id) ?? false) || ext.isPending(id),
    online: () => wc?.online() ?? false,
    relayError: () => wc?.relayError() ?? null,
  };
}

// ------------------------------------------------------------------ Settings → Browser extension

async function act(what: string, fn: () => Promise<unknown>, ok: string) {
  busy = what; message = null; onChange();
  try { await fn(); message = { text: ok, tone: "ok" }; }
  catch (e) { message = { text: typeof e === "string" ? e : (e as Error)?.message ?? String(e), tone: "bad" }; }
  busy = null;
  await refreshNow();
  onChange();
}

export function extSettingsSection(): HTMLElement {
  const st = status;
  const hosts = st?.hosts ?? [];
  const installed = hosts.filter((x) => x.state === "installed");
  const outdated = hosts.filter((x) => x.state === "outdated");
  const found = hosts.filter((x) => x.browser_found);
  const chip = !st ? ["none", "…"] : !st.listening ? ["danger", "Not available"]
    : st.connections ? ["accessory", "Extension connected"] : installed.length ? ["accessory", "Ready"] : ["none", "Not installed"];
  const sites = st?.sites ?? [];
  return h("section", { class: "set" },
    h("h4", null, "BROWSER EXTENSION"),
    h("div", { class: "set-row" }, h("span", null, "Status"), h("span", { class: `chip ${chip[0]}` }, h("i", { class: "dot" }), chip[1])),
    st?.error ? h("p", { class: "inline-error" }, icon("alert", 15), st.error) : null,
    h("p", { class: "muted small" }, "Lets sites in Chrome, Brave or Edge use Phone Vault directly (it appears in their wallet list). Every connection and every signature shows here first and is approved on your phone."),
    h("div", { class: "set-row" }, h("span", null, "Browser connection"),
      h("span", { class: "muted small" }, installed.length ? installed.map((x) => x.browser).join(", ") : outdated.length ? "Needs reinstall" : "Not installed")),
    outdated.length ? h("p", { class: "muted small" }, `${outdated.map((x) => x.browser).join(", ")}: installed for another copy of this app. Install again to point it here.`) : null,
    st?.exe_error ? h("p", { class: "inline-error" }, icon("alert", 15), st.exe_error) : null,
    h("div", { class: "row gap" },
      h("button", { disabled: !!busy || !!st?.exe_error, onclick: () => act("install", () => call("bridge_install"), "Installed. Reload the extension's tabs if they were open.") },
        busy === "install" ? [h("i", { class: "mini-spin" }), "Installing…"] : installed.length ? "Install again" : "Install browser connection"),
      installed.length || outdated.length ? h("button", { class: "ghost", disabled: !!busy, onclick: () => act("remove", () => call("bridge_uninstall"), "Removed.") }, "Remove") : null),
    message ? h("p", { class: `field-msg ${message.tone}` }, message.text) : null,
    !found.length && st ? h("p", { class: "muted small" }, "No Chrome, Brave, Edge, Chromium or Firefox profile found on this Mac.") : null,
    h("p", { class: "muted small" }, "Writes a small file in each browser's NativeMessagingHosts folder that lets only the Phone Vault extension (ID ",
      h("button", { class: "link mono", onclick: () => copy(st?.extension_id ?? "", "Extension ID") }, st?.extension_id ?? "…"),
      ") start this app's bridge. No network port is opened."),
    h("div", { class: "set-row" }, h("span", null, "Connected sites"), h("span", { class: "muted small" }, sites.length ? String(sites.length) : "")),
    sites.length ? h("ul", { class: "wc-sessions" }, sites.map((s) => h("li", null,
      h("span", { class: "wc-icon sm" }, icon("external", 14)),
      h("div", { class: "grow" },
        h("div", { class: "wc-dapp-name small" }, s.host, s.local ? h("span", { class: "tag" }, "local") : null),
        h("div", { class: "muted small" }, `${netName(s.active)} · ${s.chains.length} network${s.chains.length > 1 ? "s" : ""} approved`),
        s.current_pairing ? null : h("div", { class: "muted small" }, "Connected with a different paired phone: not active.")),
      h("button", { class: "danger-ghost chip-btn", onclick: () => act("revoke", () => call("bridge_revoke", { origin: s.origin }), `Disconnected ${s.host}.`).then(() => toast(`Disconnected ${s.host}`)) }, "Revoke"))))
      : h("p", { class: "muted small" }, "None. A site asks to connect from its own wallet button; you approve it here."),
  );
}

/** Settings re-render hook (main.ts redraws the drawer through the WalletConnect host). */
export function onExtChange(fn: () => void) { onChange = fn; }

// ------------------------------------------------------------------ preview (no Tauri)
// PREVIEW DATA ONLY: ?ext=connect | requests | sites | off. The real policy is bridge.rs.

const q = new URLSearchParams(typeof location !== "undefined" ? location.search : "");
const ADDR = "0x7A3B9C1d2e4F5061728394a5b6c7d8E9F0a1b2C3";
let mockSites: SiteOut[] = ["requests", "sites"].includes(q.get("ext") ?? "")
  ? [
      { origin: "https://app.uniswap.org", host: "app.uniswap.org", local: false, chains: [8453, 1], active: 8453, connected_at: 1760000000, address: ADDR, current_pairing: true },
      ...(q.get("ext") === "sites" ? [{ origin: "https://app.aave.com", host: "app.aave.com", local: false, chains: [1], active: 1, connected_at: 1760000000, address: ADDR, current_pairing: true }] : []),
    ]
  : [];
let mockPending: PendingOut[] = [];
let mockInstalled = q.get("ext") !== "off";
const t0 = Date.now();
if (q.get("ext") === "connect") mockPending.push({ id: 1, kind: "connect", origin: "https://app.uniswap.org", host: "app.uniswap.org", local: false, method: "eth_requestAccounts", params: [], chain_id: 8453, created: 0 });
if (q.get("ext") === "requests") {
  mockPending.push({ id: 2, kind: "request", origin: "https://app.uniswap.org", host: "app.uniswap.org", local: false, method: "eth_sendTransaction", chain_id: 8453, created: 0,
    params: [{ from: ADDR, to: "0x51Ea0B8F1a0c6f3f0c1b2E5a6d7c8b9a0e1F2d3C", value: "0x38d7ea4c68000" }] });
  mockPending.push({ id: 3, kind: "request", origin: "https://app.uniswap.org", host: "app.uniswap.org", local: false, method: "personal_sign", chain_id: 8453, created: 0,
    params: ["0x" + [...new TextEncoder().encode("Sign in to app.uniswap.org\nNonce: 8f3a1c2b")].map((b) => b.toString(16).padStart(2, "0")).join(""), ADDR] });
}

async function previewInvoke<T>(cmd: string, a: Record<string, unknown>): Promise<T> {
  await new Promise((r) => setTimeout(r, 120));
  const hosts: HostState[] = [
    { browser: "Google Chrome", path: "~/Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.phonevault.json", browser_found: true, state: mockInstalled ? "installed" : "missing" },
    { browser: "Brave", path: "", browser_found: true, state: mockInstalled ? "installed" : "missing" },
    { browser: "Microsoft Edge", path: "", browser_found: false, state: "missing" },
    { browser: "Chromium", path: "", browser_found: false, state: "missing" },
    { browser: "Firefox", path: "", browser_found: false, state: "missing" },
  ];
  switch (cmd) {
    case "bridge_status": return { listening: true, error: null, socket: "~/Library/Application Support/PhoneVault/bridge.sock", extension_id: "fbomijndbpoddicmbngledanaafapmlk", firefox_id: "browser-extension@phonevault.dev",
      connections: mockInstalled && Date.now() - t0 > 0 ? 1 : 0, hosts, sites: mockSites, exe: "/Applications/Phone Vault Companion.app/Contents/MacOS/companion", exe_error: null } as T;
    case "bridge_pending": return mockPending as T;
    case "bridge_set_nodes": return null as T;
    case "bridge_install": mockInstalled = true; return null as T;
    case "bridge_uninstall": mockInstalled = false; return null as T;
    case "bridge_revoke": mockSites = mockSites.filter((s) => s.origin !== a.origin); return null as T;
    case "bridge_approve_connect": {
      const p = mockPending.find((x) => x.id === a.id);
      const chains = a.chains as number[];
      if (p) mockSites.push({ origin: p.origin, host: p.host, local: p.local, chains, active: chains[0], connected_at: Date.now() / 1000, address: ADDR, current_pairing: true });
      mockPending = mockPending.filter((x) => x.id !== a.id);
      return null as T;
    }
    case "bridge_respond": mockPending = mockPending.filter((x) => x.id !== a.id); console.info("[preview ext] respond", a); return null as T;
    case "bridge_update_site": {
      mockSites = mockSites.map((s) => s.origin !== a.origin ? s : { ...s, chains: (a.chains as number[] | null) ?? s.chains, active: (a.active as number | null) ?? s.active });
      return null as T;
    }
  }
  throw new Error(`preview: no mock for ${cmd}`);
}
