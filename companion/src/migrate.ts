// "Move from another wallet": a read-only assistant for leaving Ledger, Trezor, MetaMask or any
// other wallet without bringing its recovery phrase here (src-tauri/src/migrate). The user pastes
// the old wallet's public addresses or xpubs; this shows what they hold on the user's own nodes,
// where each item goes on Phone Vault (verified on the phone first), and ticks items off on
// re-scan as the user sends them FROM THE OLD WALLET. Nothing here signs for the old wallet.

import { api, call, errText, registerPreview, type PreviewInvoke } from "./api";
import { NETWORKS, byId } from "./networks";
import { h, icon, short, grouped, fmtAmount, copy, ago, topbar, fmtInt } from "./ui";
import { qrSvg } from "./qr";
import { explainNode, explainPlain } from "./errors";
import { btcApi, fmtBtc, groupedBtc, type BtcNet } from "./bitcoin-core";
import type { View } from "./state";
import "./migrate.css";

registerPreview((cmd) => cmd.startsWith("migrate_"), async () => (await import("./migrate-mock")).migrateMock as PreviewInvoke);

// ------------------------------------------------------------------ types (migrate/*.rs)

export type BtcType = "native" | "taproot" | "nested" | "legacy";
export type MSource =
  | { kind: "evm"; id: string; address: string }
  | { kind: "xpub"; id: string; prefix: string; network: BtcNet; types: BtcType[]; note: string | null }
  | { kind: "btc_address"; id: string; network: BtcNet; btc_type: BtcType | null };
/** unknown: seen before, the node couldn't answer the re-check; pending: a Bitcoin spend waits for confirmation */
export type MStatus = "move" | "moved" | "gone" | "unknown" | "pending" | "empty";
export interface MItem { key: string; symbol: string; name: string; contract: string | null; decimals: number; raw: string; amount: string; destination_amount: string | null; status: MStatus }
export interface MNft { key: string; contract: string; token_id: string; name: string | null; symbol: string | null; status: MStatus; on_phone_vault: boolean }
export interface MApproval { key: string; kind: "token" | "collection"; contract: string; symbol: string | null; spender: string; amount: string; status: MStatus }
export interface MWindow { searched: boolean; from_block: number | null; to_block: number | null; error: string | null; capped: boolean }
export interface EvmReport {
  chain_id: number; network: string; address: string; destination: string; native: MItem; tokens: MItem[]; unreadable_tokens: string[];
  nfts: MNft[]; nft_window: MWindow; approvals: MApproval[]; approval_window: MWindow;
}
export interface TypeTotal { btc_type: BtcType; name: string; looks: string; confirmed_sats: number; unconfirmed_sats: number; used_addresses: number; checked_addresses: number; first_address: string }
export interface BtcReport { source: string; network: BtcNet; network_name: string; unit: string; server: string; types: TypeTotal[]; confirmed_sats: number; unconfirmed_sats: number; status: MStatus }
export interface MSession { sources: MSource[]; started_at: number; scanned_at: number; path: string }
export interface BtcDest { network: BtcNet; network_name: string; unit: string; id: string; label: string; kind_name: string; native_segwit: boolean; address: string; index: number; path: string; verified: boolean; balance_sats: number }
export interface Destinations { evm: { address: string; label: string } | null; btc: BtcDest[] }

const m = {
  check: (input: string) => call<MSource>("migrate_check", { input }),
  /** the whole list: a secret spread over several lines (a phrase one word per line) */
  checkText: (text: string) => call<void>("migrate_check_text", { text }),
  session: () => call<MSession | null>("migrate_session"),
  save: (sources: string[]) => call<MSession>("migrate_save", { sources }),
  forget: () => call<void>("migrate_forget"),
  destinations: () => call<Destinations>("migrate_destinations"),
  /** the node's eth_chainId is checked against chainId before anything is read or saved */
  scanEvm: (rpcUrl: string, chainId: number, address: string, deep: boolean) => call<EvmReport>("migrate_scan_evm", { rpcUrl, chainId, address, deep }),
  scanBtc: (source: string) => call<BtcReport>("migrate_scan_btc", { source }),
};

/** What the screen needs from the shell (main.ts). */
export interface MigrateHost {
  go(v: View): void;
  rpcFor(id: number): string;
  /** redraw the screen if it is showing */
  rerender(): void;
  /** why the phone can't take a request now (device check failed, …), or null */
  phoneBlocked(): string | null;
  /** another request is on the phone */
  phoneBusy(): boolean;
}

// ------------------------------------------------------------------ state

type Cell<T> = { report: T | null; error: string | null; busy: boolean };
type Verify = { s: "idle" } | { s: "asking" } | { s: "compare" } | { s: "ok" } | { s: "mismatch"; shown: string | null } | { s: "error"; message: string };

let host: MigrateHost;
const st = {
  loading: null as Promise<void> | null,
  loaded: false,
  loadError: null as string | null,
  session: null as MSession | null,
  editing: false,
  draft: "",
  saving: false,
  saveError: null as string | null,
  dest: null as Destinations | null,
  evm: new Map<string, Map<number, Cell<EvmReport>>>(),
  btc: new Map<string, Cell<BtcReport>>(),
  /** EVM address:chain pairs whose logs (NFTs, approvals) were searched this session */
  deepDone: new Set<string>(),
  scanning: false,
  verifyEvm: { s: "idle" } as Verify,
  verifyBtc: new Map<BtcNet, Verify>(),
  forgetArmed: false,
};

/** Redraw, unless the user is typing in the list (the screen would be rebuilt under them). */
function redraw() {
  const a = document.activeElement;
  if (st.editing && a instanceof HTMLTextAreaElement && a.closest(".mig")) return;
  host.rerender();
}

export function initMigrate(h0: MigrateHost) {
  host = h0;
  void load();
}

/** Open the assistant (Home, Settings, the end of the guided setup). */
export function openMigrate() {
  st.forgetArmed = false;
  host.go("migrate");
  void load().then(() => { if (st.session && !anyScan()) void scanAll(); });
}

function load(): Promise<void> {
  return (st.loading ??= (async () => {
    try { st.session = await m.session(); st.loadError = null; }
    catch (e) { st.loadError = errText(e); }
    st.loaded = true;
    void loadDestinations();
    redraw();
  })());
}

async function loadDestinations() {
  try { st.dest = await m.destinations(); } catch { /* shown as unavailable */ }
  redraw();
}

const anyScan = () => st.evm.size > 0 || st.btc.size > 0;
const evmSources = () => (st.session?.sources ?? []).filter((s): s is Extract<MSource, { kind: "evm" }> => s.kind === "evm");
const btcSources = () => (st.session?.sources ?? []).filter((s): s is Exclude<MSource, { kind: "evm" }> => s.kind !== "evm");

// ------------------------------------------------------------------ scanning

async function scanEvm(address: string, chainId: number, deepWanted: boolean) {
  let per = st.evm.get(address);
  if (!per) { per = new Map(); st.evm.set(address, per); }
  const cell = per.get(chainId) ?? { report: null, error: null, busy: false };
  per.set(chainId, cell);
  cell.busy = true; redraw();
  const k = `${address}:${chainId}`;
  const deep = deepWanted || !st.deepDone.has(k);
  try {
    const r = await m.scanEvm(host.rpcFor(chainId), chainId, address, deep);
    cell.report = r; cell.error = null;
    if (deep) st.deepDone.add(k);
  } catch (e) { cell.error = errText(e); }
  cell.busy = false; redraw();
}

async function scanBtc(id: string) {
  const cell = st.btc.get(id) ?? { report: null, error: null, busy: false };
  st.btc.set(id, cell);
  cell.busy = true; redraw();
  try { cell.report = await m.scanBtc(id); cell.error = null; }
  catch (e) { cell.error = errText(e); }
  cell.busy = false; redraw();
}

/** Scan everything; `deep` also searches the logs again for NFTs and approvals. */
async function scanAll(deep = false) {
  if (st.scanning || !st.session) return;
  st.scanning = true; redraw();
  const jobs: Promise<void>[] = [];
  for (const s of evmSources()) for (const n of NETWORKS) jobs.push(scanEvm(s.id, n.id, deep));
  for (const s of btcSources()) jobs.push(scanBtc(s.id));
  jobs.push(loadDestinations());
  await Promise.allSettled(jobs);
  try { st.session = await m.session() ?? st.session; } catch { /* keep */ }
  st.scanning = false; redraw();
}

async function save(lines: string[]) {
  st.saving = true; st.saveError = null; redraw();
  try {
    st.session = await m.save(lines);
    st.editing = false;
    // entries that went away lose their results
    const ids = new Set(st.session.sources.map((s) => s.id));
    for (const k of [...st.evm.keys()]) if (!ids.has(k)) st.evm.delete(k);
    for (const k of [...st.btc.keys()]) if (!ids.has(k)) st.btc.delete(k);
    st.saving = false;
    void scanAll();
  } catch (e) { st.saveError = errText(e); st.saving = false; }
  redraw();
}

async function forget() {
  try {
    await m.forget();
    st.session = null; st.evm.clear(); st.btc.clear(); st.deepDone.clear(); st.draft = ""; st.editing = false;
    st.verifyEvm = { s: "idle" }; st.verifyBtc.clear(); st.forgetArmed = false;
  } catch (e) { st.saveError = errText(e); }
  redraw();
}

// ------------------------------------------------------------------ counting (Home, progress)

/** unknown (couldn't check) and pending (unconfirmed) items are never counted as done. */
interface Tally { toMove: number; moved: number; unknown: number; pending: number; approvals: number; revoked: number }
function tally(): Tally {
  const t: Tally = { toMove: 0, moved: 0, unknown: 0, pending: 0, approvals: 0, revoked: 0 };
  const count = (s: MStatus) => {
    if (s === "move") t.toMove++; else if (s === "moved" || s === "gone") t.moved++;
    else if (s === "unknown") t.unknown++; else if (s === "pending") t.pending++;
  };
  for (const per of st.evm.values()) for (const c of per.values()) {
    const r = c.report; if (!r) continue;
    count(r.native.status); r.tokens.forEach((x) => count(x.status)); r.nfts.forEach((x) => count(x.status));
    for (const a of r.approvals) { if (a.status === "move") t.approvals++; else if (a.status === "moved") t.revoked++; else if (a.status === "unknown") t.unknown++; }
  }
  for (const c of st.btc.values()) if (c.report) count(c.report.status);
  return t;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** One line for what's left; "Everything found has moved" only when nothing is to do, unchecked or unconfirmed. */
function leftLine(t: Tally): string {
  const left = t.toMove + t.approvals;
  if (left) return `${plural(left, "item")} left to move or revoke${t.unknown ? ` · ${t.unknown} couldn't be checked` : ""}`;
  if (t.unknown) return `${plural(t.unknown, "item")} couldn't be checked: re-scan`;
  if (t.pending) return `Sending… waiting for ${t.pending === 1 ? "a confirmation" : "confirmations"}`;
  return "Everything found has moved";
}

/** Home: an empty wallet invites the assistant; a session in progress links back to it. */
export function migrateHomeCard(walletEmpty: boolean): HTMLElement | null {
  if (!st.loaded) return null;
  if (st.session) {
    const t = tally();
    return h("button", { class: "mig-home", onclick: () => openMigrate() },
      icon("down", 18),
      h("span", { class: "grow" }, h("strong", null, "Moving from another wallet"),
        h("span", { class: "muted small" }, anyScan() ? leftLine(t) : "Continue where you left off")),
      icon("back", 14));
  }
  if (!walletEmpty) return null;
  return h("section", { class: "callout accent mig-invite" },
    h("strong", null, "Moving from another wallet?"),
    h("span", null, "Bring what's in Ledger, Trezor, MetaMask or any other wallet over here, without typing its recovery phrase anywhere. Paste its public addresses; Phone Vault shows what to send and where."),
    h("div", { class: "row" }, h("button", { class: "primary", onclick: () => openMigrate() }, "Start moving")));
}

// ------------------------------------------------------------------ the screen

export function migrateView(): HTMLElement {
  if (!st.loaded) void load();
  const back = () => { st.forgetArmed = false; host.go("home"); };
  const body = !st.loaded ? h("div", { class: "boot" }, h("div", { class: "spinner" }))
    : st.loadError ? h("p", { class: "inline-error" }, icon("alert", 15), explainPlain(st.loadError))
    : !st.session || st.editing ? editView()
    : listView();
  return h("div", { class: "stack fade mig" }, topbar("Move from another wallet", back), body);
}

// ---- step 1: what the old wallet is

const HELP: [string, string][] = [
  ["Ledger Live", "open the account, click the wrench (Edit account), then Advanced: copy the public key (xpub)."],
  ["Trezor Suite", "open the account, then Details → Show public key (xpub)."],
  ["Sparrow", "Settings → Keystore: copy the public key (xpub, ypub or zpub)."],
  ["MetaMask and EVM wallets", "copy the account address (0x…). One address covers every network."],
];

function describe(s: MSource): string {
  if (s.kind === "evm") return "Ethereum and EVM networks";
  if (s.kind === "xpub") {
    const net = s.network === "bitcoin" ? "Bitcoin" : "Bitcoin test network";
    return s.types.length === 1 ? `${net} account (${s.prefix}, ${typeName(s.types[0])})` : `${net} account (${s.prefix}, every address type)`;
  }
  return `${s.network === "bitcoin" ? "Bitcoin" : "Bitcoin test"} address${s.btc_type ? ` (${typeName(s.btc_type)})` : ""}`;
}
const typeName = (t: BtcType) => ({ native: "Native SegWit", taproot: "Taproot", nested: "Nested SegWit", legacy: "Legacy" })[t];

function editView(): HTMLElement {
  const area = h("textarea", { rows: "5", spellcheck: "false", autocomplete: "off", autocapitalize: "off", "aria-label": "Old addresses and public keys, one per line",
    placeholder: "0x… an Ethereum / EVM account\nzpub…, ypub… or xpub… a Bitcoin account public key\nbc1…, 3… or 1… a single Bitcoin address" }) as HTMLTextAreaElement;
  area.value = st.draft || (st.session?.sources.map((s) => s.id).join("\n") ?? "");
  const checks = h("ul", { class: "mig-checks", "aria-live": "polite" });
  const submit = h("button", { class: "big primary", disabled: st.saving }, st.saving ? h("i", { class: "mini-spin" }) : icon("refresh", 18), st.saving ? "Saving…" : "Check what it holds") as HTMLButtonElement;
  let seq = 0;
  const lines = () => area.value.split("\n").map((l) => l.trim()).filter(Boolean);
  const validate = async () => {
    const my = ++seq;
    const ls = lines();
    // the whole text first: a recovery phrase pasted one word per line is no single bad line
    let whole: string | null = null;
    try { await m.checkText(area.value); } catch (e) { whole = errText(e); }
    if (my !== seq) return;
    if (whole) {
      checks.replaceChildren(h("li", { class: "bad" }, icon("x", 15), h("span", { class: "grow" }, h("span", { class: "mig-what" }, whole))));
      submit.disabled = true;
      return;
    }
    const rows = await Promise.all(ls.slice(0, 25).map(async (l) => {
      try { const s = await m.check(l); return { l, s, e: null as string | null }; }
      catch (e) { return { l, s: null, e: errText(e) }; }
    }));
    if (my !== seq) return;
    // a refused line may be a secret: it is named by its line number, never echoed
    checks.replaceChildren(...rows.map((r, i) => h("li", { class: r.e ? "bad" : "ok" },
      r.e ? icon("x", 15) : icon("check", 15),
      h("span", { class: "grow" }, h("span", { class: "mono" }, r.s ? short(r.s.kind === "evm" ? r.s.address : r.s.id) : `Line ${i + 1}`), " ", h("span", { class: "mig-what" }, r.s ? describe(r.s) : r.e),
        r.s?.kind === "xpub" && r.s.note ? h("span", { class: "muted small mig-note" }, r.s.note) : null))));
    submit.disabled = st.saving || !rows.length || rows.some((r) => r.e);
  };
  let timer = 0;
  area.addEventListener("input", () => { st.draft = area.value; clearTimeout(timer); timer = window.setTimeout(validate, 250); });
  submit.addEventListener("click", () => { const ls = lines(); if (ls.length) { st.draft = area.value; void save(ls); } });
  void validate();
  return h("div", { class: "stack" },
    h("section", { class: "card mig-card" },
      h("p", { class: "kicker" }, "Step 1 · The old wallet"),
      h("h3", null, "What's in your old wallet?"),
      h("p", { class: "muted" }, "Paste its public addresses or public keys, one per line. Phone Vault reads what they hold from your own nodes. You then send each item from the old wallet to Phone Vault, there, the way you always have."),
      h("label", { class: "field" }, h("span", { class: "field-label" }, "Public addresses and public keys (xpub / zpub)"), area),
      checks,
      st.saveError ? h("p", { class: "inline-error" }, icon("alert", 15), st.saveError) : null,
      h("div", { class: "actions" },
        submit,
        st.session ? h("button", { class: "big", onclick: () => { st.editing = false; st.draft = ""; st.saveError = null; redraw(); } }, "Cancel") : null),
      h("details", { class: "detail mig-help" }, h("summary", null, "Where do I find these?"),
        h("ul", { class: "mig-help-list" }, HELP.map(([who, how]) => h("li", null, h("strong", null, who), ": ", how)))),
    ),
    h("div", { class: "callout accent" },
      h("strong", { class: "ok-line" }, icon("shield", 15), "Never your recovery phrase"),
      h("span", null, "Only PUBLIC information goes here. Never paste a recovery phrase or a private key (xprv, zprv): they are refused and not kept. Public addresses and public keys (xpub, zpub) only show balances; they can't move anything."),
    ),
    h("p", { class: "muted small" }, "Saved on this Mac until you choose Forget (public data only). Bitcoin public keys are looked up on your Esplora server (Settings → Bitcoin), which learns their addresses; a public key (xpub) reveals every address and balance of that account, so share it only with software you trust."),
    phraseNote(),
  );
}

const phraseNote = () => h("p", { class: "muted small" }, "Restoring your old recovery phrase on Phone Vault is also possible, but then it lives on both devices.");

// ---- steps 2 to 4: where it goes, what to send, what to revoke

function listView(): HTMLElement {
  const t = tally();
  const total = t.toMove + t.moved + t.unknown + t.pending;
  const scannedAny = anyScan();
  const busy = st.scanning;
  return h("div", { class: "stack" },
    h("section", { class: "card mig-card mig-progress-card" },
      h("div", { class: "row between" },
        h("p", { class: "kicker" }, "Progress"),
        h("span", { class: "muted small" }, busy ? "Checking…" : st.session!.scanned_at ? `Checked ${ago(st.session!.scanned_at)}` : "")),
      h("h3", null, !scannedAny || (busy && !total) ? "Looking at the old wallet…" : total === 0 && !t.approvals ? "Nothing to move was found" : t.toMove === 0 ? leftLine(t) : `${t.moved} of ${total} moved`),
      total ? h("div", { class: "mig-bar", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": String(total), "aria-valuenow": String(t.moved) }, h("i", { style: `width:${Math.round((t.moved / total) * 100)}%` })) : null,
      t.approvals ? h("p", { class: "muted small" }, `${t.approvals} approval${t.approvals === 1 ? "" : "s"} still active on the old address${t.revoked ? ` · ${t.revoked} revoked` : ""}.`) : null,
      t.unknown ? h("p", { class: "muted small" }, `${plural(t.unknown, "item")} couldn't be checked (the node didn't answer). They aren't counted as moved: Re-scan, or use another node in Settings.`) : null,
      t.pending ? h("p", { class: "muted small" }, `${plural(t.pending, "Bitcoin transfer")} sent but not confirmed yet. It ticks off once it confirms; until then it could still be dropped or replaced.`) : null,
      h("div", { class: "row gap" },
        h("button", { class: "primary", disabled: busy, onclick: () => scanAll(false), title: "Read the balances again; items you moved tick off" }, busy ? h("i", { class: "mini-spin" }) : icon("refresh", 16), "Re-scan"),
        h("button", { disabled: busy, onclick: () => { st.editing = true; st.draft = ""; st.saveError = null; redraw(); } }, icon("pen", 15), "Edit list"),
        h("button", { class: "danger-ghost", onclick: (ev: Event) => {
          if (!st.forgetArmed) { st.forgetArmed = true; (ev.currentTarget as HTMLButtonElement).textContent = "Click again to forget"; return; }
          void forget();
        } }, "Forget")),
      evmSources().length ? h("button", { class: "link small mig-deep", disabled: busy, onclick: () => scanAll(true) }, "Search the recent blocks again for NFTs and approvals") : null,
    ),
    destinationSection(),
    h("h3", { class: "section-title" }, "2 · Send from the old wallet"),
    h("p", { class: "muted small mig-lead" }, "In the old wallet, send each item below to the Phone Vault address above, on the same network. Then Re-scan: moved items tick off."),
    ...evmSources().map(evmSourceCard),
    ...btcSources().map(btcSourceCard),
    approvalsSection(),
    h("div", { class: "callout" },
      h("strong", null, "Fees"),
      h("span", null, "Moving many small tokens may cost more in fees than they're worth. Send tokens first and the network's coin (ETH, POL) last: every token transfer needs it for gas."),
    ),
    phraseNote(),
    st.session ? h("p", { class: "muted small" }, "Saved in ", h("span", { class: "mono" }, st.session.path), " (addresses and public keys only).") : null,
  );
}

// ---- destinations

function verifyLine(v: Verify, ok: string): HTMLElement | null {
  if (v.s === "asking") return h("div", { class: "callout" }, h("strong", null, "Look at your phone"), h("span", null, "Unlock it if it asks. Compare every group of four characters with the address above."));
  if (v.s === "ok") return h("div", { class: "callout accent" }, h("strong", { class: "ok-line" }, icon("check", 15), "Verified on your phone"), h("span", null, ok));
  if (v.s === "error") return h("p", { class: "inline-error" }, icon("alert", 15), v.message);
  return null;
}

function phoneGate(): string | null {
  const blocked = host.phoneBlocked();
  if (blocked) return blocked;
  if (host.phoneBusy()) return "The phone is busy with another request. Finish it first, then verify.";
  return null;
}

async function verifyEvm(expected: string) {
  const gate = phoneGate();
  if (gate) { st.verifyEvm = { s: "error", message: gate }; redraw(); return; }
  st.verifyEvm = { s: "asking" }; redraw();
  try {
    const p = await api.readAddress();
    st.verifyEvm = p.address.toLowerCase() === expected.toLowerCase() ? { s: "compare" } : { s: "mismatch", shown: p.address };
  } catch (e) { st.verifyEvm = { s: "error", message: explainPlain(errText(e)) }; }
  redraw();
}

async function verifyBtc(d: BtcDest) {
  const gate = phoneGate();
  if (gate) { st.verifyBtc.set(d.network, { s: "error", message: gate }); redraw(); return; }
  st.verifyBtc.set(d.network, { s: "asking" }); redraw();
  try {
    const r = await btcApi.showAddress(d.id, 0, d.index);
    st.verifyBtc.set(d.network, r.matches ? { s: "ok" } : { s: "mismatch", shown: r.address });
    if (r.matches) await loadDestinations();
  } catch (e) { st.verifyBtc.set(d.network, { s: "error", message: explainPlain(errText(e), "btc") }); }
  redraw();
}

function mismatchCard(title: string, shown: string | null, body: string, again: () => void, reset: () => void): HTMLElement {
  return h("section", { class: "card danger-card mig-dest" },
    h("p", { class: "kicker danger" }, "Don't send here yet"),
    h("h3", null, title),
    h("p", null, body),
    shown ? h("p", { class: "muted small" }, "The phone said: ", h("span", { class: "mono break" }, shown)) : null,
    h("div", { class: "actions" }, h("button", { class: "primary", onclick: again }, icon("phone", 16), "Verify again"), h("button", { onclick: reset }, "Close")));
}

function destinationSection(): HTMLElement {
  const needEvm = evmSources().length > 0;
  const nets = [...new Set(btcSources().map((s) => s.network))];
  const cards: (HTMLElement | null)[] = [];
  const d = st.dest;
  if (needEvm) {
    const e = d?.evm;
    if (!e) cards.push(h("p", { class: "inline-error" }, icon("alert", 15), d ? "Pair your phone first (Settings → Phone)." : "Loading your Phone Vault address…"));
    else if (st.verifyEvm.s === "mismatch") {
      const shown = st.verifyEvm.shown;
      cards.push(mismatchCard(shown ? "Your phone is on another account" : "The addresses differ",
        shown,
        shown ? `The phone is using a different account than ${e.label}, which this Mac shows. Switch the phone to ${e.label} (or show the other account here), then verify again.`
          : "Your phone shows a different address than this Mac. Something between them may be changing data: use another cable and port, and don't send funds until they match.",
        () => verifyEvm(e.address), () => { st.verifyEvm = { s: "idle" }; redraw(); }));
    } else cards.push(destCard({
      kicker: "Ethereum and EVM networks", label: e.label, address: e.address, display: grouped(e.address), qr: e.address,
      verified: st.verifyEvm.s === "ok", v: st.verifyEvm, onVerify: () => verifyEvm(e.address),
      note: "The same address on Base, Ethereum, Optimism, Arbitrum and Polygon. In the old wallet, choose the network the item is on.",
      ok: "The phone holds the key for this address. Safe to send to.",
      compare: st.verifyEvm.s === "compare" ? h("div", { class: "callout" },
        h("strong", null, "Your phone is on this account"),
        h("span", null, "On the phone, open Wallet and compare its address with the one above, group by group."),
        h("div", { class: "row gap" },
          h("button", { class: "primary", onclick: () => { st.verifyEvm = { s: "ok" }; redraw(); } }, icon("check", 15), "It matches"),
          h("button", { onclick: () => { st.verifyEvm = { s: "mismatch", shown: null }; redraw(); } }, "It doesn't"))) : null,
    }));
  }
  for (const n of nets) {
    const b = d?.btc.find((x) => x.network === n);
    const v = st.verifyBtc.get(n) ?? { s: "idle" };
    const name = n === "bitcoin" ? "Bitcoin" : n === "testnet" ? "Bitcoin Testnet" : "Bitcoin Signet";
    if (!b) { cards.push(h("div", { class: "callout" }, h("strong", null, `No ${name} account on this Mac yet`), h("span", null, `Add one from your phone first: pick ${name} in the network menu on Home, then Add from phone. Then come back here.`))); continue; }
    if (v.s === "mismatch") {
      cards.push(mismatchCard("Your phone shows a different address", v.shown,
        "This Mac and your phone disagree about this account's next receive address, so it is hidden. Check the phone is on the same Bitcoin account, use another cable and port, and don't send until they match.",
        () => verifyBtc(b), () => { st.verifyBtc.set(n, { s: "idle" }); redraw(); }));
      continue;
    }
    cards.push(destCard({
      kicker: `${b.network_name} · ${b.kind_name}`, label: b.label, address: b.address, display: groupedBtc(b.address), qr: `bitcoin:${b.address.toUpperCase()}`,
      verified: b.verified || v.s === "ok", v, onVerify: () => verifyBtc(b),
      note: b.native_segwit ? `Address #${b.index + 1} of ${b.label}. Every old address type can send to it.`
        : `Your ${b.kind_name} account (no Native SegWit account is on this Mac). Every old address type can send to it.`,
      ok: `Derived on the phone from your key (${b.path}). Safe to send to.`,
      compare: null,
    }));
  }
  if (!cards.length) return h("span");
  const verifiedAll = (!needEvm || st.verifyEvm.s === "ok") && nets.every((n) => d?.btc.find((x) => x.network === n)?.verified || st.verifyBtc.get(n)?.s === "ok");
  return h("div", { class: "stack mig-dests" },
    h("h3", { class: "section-title" }, "1 · Verify where it goes"),
    verifiedAll ? null : h("p", { class: "muted small mig-lead" }, "Before the first transfer, check the address on your phone. Malware on a computer can swap an address on screen; your phone can't be fooled that way."),
    ...cards);
}

function destCard(o: { kicker: string; label: string; address: string; display: string; qr: string; verified: boolean; v: Verify; onVerify: () => void; note: string; ok: string; compare: HTMLElement | null }): HTMLElement {
  const asking = o.v.s === "asking";
  return h("section", { class: "card mig-dest" },
    h("div", { class: "row between" }, h("p", { class: "kicker" }, o.kicker), o.verified ? h("span", { class: "badge ok" }, icon("check", 12), "Verified") : h("span", { class: "badge" }, "Not verified yet")),
    h("div", { class: "mig-dest-body" },
      h("div", { class: "qr-tile mig-qr", html: qrSvg(o.qr, { dark: "#060608", light: "#ffffff", label: `QR code for ${o.address}` }) }),
      h("div", { class: "mig-dest-text" },
        h("p", { class: "mig-label" }, o.label),
        h("button", { class: "addr-full", onclick: () => copy(o.address), title: "Click to copy" }, h("span", { class: "mono" }, o.display), icon("copy", 16)),
        h("p", { class: "muted small" }, o.note),
        h("div", { class: "row gap" },
          h("button", { class: o.verified ? "" : "primary", disabled: asking, onclick: o.onVerify }, asking ? h("i", { class: "mini-spin" }) : icon("phone", 16), o.verified ? "Show on phone again" : "Verify on phone"),
          h("button", { class: o.verified ? "primary" : "", onclick: () => copy(o.address) }, icon("copy", 16), "Copy")))),
    o.compare ?? verifyLine(o.v, o.ok));
}

// ---- the checklist

const STATUS_TEXT: Record<MStatus, string> = { move: "To move", moved: "Moved", gone: "Left the old wallet", unknown: "Couldn't check", pending: "Sending… (unconfirmed)", empty: "" };
const UNKNOWN_SUB = "Couldn't check: the node didn't answer. Not counted as moved; Re-scan.";

function row(status: MStatus, title: Node | string, sub: Node | string | null, extra?: Node | null): HTMLElement {
  return h("li", { class: `mig-row ${status}` },
    h("span", { class: "mig-tick", "aria-label": STATUS_TEXT[status], title: STATUS_TEXT[status] }, status === "moved" ? icon("check", 14) : status === "gone" ? icon("up", 13) : status === "unknown" ? "?" : status === "pending" ? h("i", { class: "mini-spin" }) : null),
    h("span", { class: "grow" }, h("span", { class: "mig-title" }, title), sub ? h("span", { class: "muted small mig-sub" }, sub) : null),
    extra ?? null);
}

function destHas(amount: string | null, symbol: string): string | null {
  if (amount === null) return null;
  return amount === "0" ? null : `Phone Vault has ${fmtAmount(amount, 6)} ${symbol}`;
}

function evmSourceCard(s: Extract<MSource, { kind: "evm" }>): HTMLElement {
  const per = st.evm.get(s.id);
  const rows: HTMLElement[] = [];
  const nothing: string[] = [];
  const failed: HTMLElement[] = [];
  const windows: string[] = [];
  let checking = 0;
  for (const n of NETWORKS) {
    const c = per?.get(n.id);
    if (!c || (c.busy && !c.report)) { checking++; continue; }
    if (c.error && !c.report) { failed.push(h("p", { class: "inline-error" }, icon("alert", 15), `${n.name}: ${explainNode(c.error)}`)); continue; }
    const r = c.report!;
    const here: HTMLElement[] = [];
    if (r.native.status !== "empty") here.push(row(r.native.status, r.native.status === "move" ? `${fmtAmount(r.native.amount, 6)} ${r.native.symbol}` : r.native.symbol,
      r.native.status === "move" ? "Network coin: send it last" : destHas(r.native.destination_amount, r.native.symbol) ?? "No longer in the old wallet"));
    for (const t of r.tokens) here.push(row(t.status, t.status === "move" ? `${fmtAmount(t.amount, 6)} ${t.symbol}` : t.symbol, t.status === "move" ? t.name : t.status === "unknown" ? UNKNOWN_SUB : destHas(t.destination_amount, t.symbol) ?? "No longer in the old wallet"));
    for (const x of r.nfts) here.push(row(x.status, `${x.name ?? x.symbol ?? short(x.contract)} #${x.token_id.length > 12 ? x.token_id.slice(0, 10) + "…" : x.token_id}`,
      x.status === "move" ? `NFT · ${short(x.contract)}` : x.status === "unknown" ? UNKNOWN_SUB : x.on_phone_vault ? "Phone Vault holds it now" : "Sent somewhere other than Phone Vault"));
    if (r.unreadable_tokens.length) here.push(h("li", { class: "mig-note-row muted small" }, `Couldn't read ${r.unreadable_tokens.join(", ")} from this node.`));
    if (r.nft_window.capped) here.push(h("li", { class: "mig-note-row muted small" }, "This node returned more NFT transfers than are checked: only the newest 5,000 were kept."));
    if (r.nft_window.searched && r.nft_window.from_block !== null && r.nft_window.to_block !== null) windows.push(`${n.name} ${fmtInt(r.nft_window.to_block - r.nft_window.from_block + 1)}`);
    if (here.length) rows.push(h("li", { class: "mig-net" }, h("i", { class: `net-dot n${n.id}` }), n.name, c.busy ? h("i", { class: "mini-spin" }) : null), ...here);
    else if (!n.testnet) nothing.push(n.name);
  }
  return h("section", { class: "card mig-card" },
    h("div", { class: "row between" },
      h("p", { class: "kicker" }, "Old EVM account"),
      h("button", { class: "link mono small", title: `${s.address}\nClick to copy`, onclick: () => copy(s.address) }, short(s.address), icon("copy", 12))),
    rows.length ? h("ul", { class: "mig-list" }, rows) : null,
    checking ? h("p", { class: "muted small mig-checking" }, h("i", { class: "mini-spin" }), `Checking ${checking} network${checking === 1 ? "" : "s"}…`) : null,
    !rows.length && !checking && !failed.length ? h("p", { class: "empty" }, "Nothing found on the networks Phone Vault supports.") : null,
    failed,
    nothing.length && rows.length ? h("p", { class: "muted small" }, `Nothing on ${nothing.join(", ")}.`) : null,
    h("p", { class: "muted small" }, "Tokens: the built-in list only; other tokens aren't shown. NFTs: those that arrived within the recent blocks your nodes serve",
      windows.length ? ` (${windows.join(", ")} blocks)` : "", ", plus any found before. Older NFTs, and ERC-1155 items, may be missing: check the old wallet's NFT tab too."),
  );
}

function btcSourceCard(s: Exclude<MSource, { kind: "evm" }>): HTMLElement {
  const c = st.btc.get(s.id);
  const r = c?.report ?? null;
  const unit = r?.unit ?? (s.network === "bitcoin" ? "BTC" : "tBTC");
  const total = r ? r.confirmed_sats + r.unconfirmed_sats : 0;
  const sub = !r ? "" : r.status === "move" ? (r.unconfirmed_sats ? `${fmtBtc(r.unconfirmed_sats)} ${unit} unconfirmed · ` : "") + `send it all to your ${r.network_name} address above`
    : r.status === "pending" ? `Sending… (unconfirmed): ${fmtBtc(r.confirmed_sats)} ${unit} still confirmed at the old addresses. It ticks off once the transfer confirms.`
    : "No longer at the old wallet's addresses";
  return h("section", { class: "card mig-card" },
    h("div", { class: "row between" },
      h("p", { class: "kicker" }, s.kind === "xpub" ? `Old Bitcoin account · public key (${s.prefix})` : "Old Bitcoin address"),
      h("button", { class: "link mono small", title: `${s.id}\nClick to copy`, onclick: () => copy(s.id, s.kind === "xpub" ? "Public key" : "Address") }, short(s.id), icon("copy", 12))),
    !r && (!c || c.busy) ? h("p", { class: "muted small mig-checking" }, h("i", { class: "mini-spin" }), s.kind === "xpub" ? "Checking its addresses (gap limit 20)…" : "Checking the address…") : null,
    c?.error && !r ? h("p", { class: "inline-error" }, icon("alert", 15), explainNode(c.error)) : null,
    r ? (r.status === "empty" ? h("p", { class: "empty" }, s.kind === "xpub" ? "No bitcoin found on this public key's addresses." : "No bitcoin on this address.")
      : h("ul", { class: "mig-list" }, row(r.status, r.status === "move" ? `${fmtBtc(total)} ${unit}` : unit, sub,
        c?.busy ? h("i", { class: "mini-spin" }) : null))) : null,
    r && r.types.length ? h("ul", { class: "mig-types" }, r.types.map((t) => h("li", null,
      h("span", null, `${t.name} (${t.looks})`), h("span", { class: "mono" }, `${fmtBtc(t.confirmed_sats + t.unconfirmed_sats)} ${unit}`),
      h("span", { class: "muted small" }, `${t.used_addresses} used of ${t.checked_addresses} checked`)))) : null,
    s.kind === "xpub" && s.note ? h("p", { class: "muted small" }, s.note) : null,
    r ? h("p", { class: "muted small" }, `From ${r.server || "your Esplora server"}. In the old wallet, send the whole balance (often "Max" / "Send all") to one address; the old wallet picks the coins.`) : null,
  );
}

function approvalsSection(): HTMLElement | null {
  const items: { chain: string; a: MApproval }[] = [];
  const windows: string[] = [];
  let incomplete = false;
  for (const per of st.evm.values()) for (const [id, c] of per) {
    const r = c.report; if (!r) continue;
    for (const a of r.approvals) items.push({ chain: byId(id).name, a });
    const w = r.approval_window;
    if (w.searched && (w.error || w.capped)) incomplete = true;
    if (w.searched && w.from_block !== null && w.to_block !== null && r.approvals.length) windows.push(`${byId(id).name} ${fmtInt(w.to_block - w.from_block + 1)}`);
  }
  if (!evmSources().length) return null;
  return h("div", { class: "stack" },
    h("h3", { class: "section-title" }, "3 · Revoke approvals"),
    items.length ? h("section", { class: "card mig-card" },
      h("p", { class: "muted" }, "Revoke these before you retire the old wallet: each lets a contract move tokens or NFTs out of the old address, even after you stop using it. Revoke them from the old wallet (a revoke tool, or the app that asked for it)."),
      h("ul", { class: "mig-list" }, items.map(({ chain, a }) => row(a.status,
        a.kind === "token" ? `${a.amount === "unlimited" ? "Unlimited" : a.status === "unknown" ? "Approval" : `${fmtAmount(a.amount, 6)}`} ${a.symbol ?? short(a.contract)}` : `All ${a.symbol ?? "NFTs"} of ${short(a.contract)}`,
        `${a.status === "move" ? "Spender" : a.status === "unknown" ? "Couldn't check if it's still active (the node didn't answer) · spender" : "Revoked · was"} ${short(a.spender)} · ${chain}`,
        h("button", { class: "link mono small", title: `${a.spender}\nCopy spender`, onclick: () => copy(a.spender, "Spender") }, icon("copy", 12))))),
    ) : h("p", { class: "muted small" }, anyScan() ? "No active approvals found in the recent blocks searched." : "Approvals are listed here after the scan."),
    h("p", { class: "muted small" }, `Approvals are found in recent blocks only${windows.length ? ` (${windows.join(", ")} blocks)` : ""}${incomplete ? "; some nodes served fewer, or more than the 5,000 newest that are checked" : ""}. Older approvals aren't listed: check the old address in a revoke tool before you stop using it.`),
  );
}
