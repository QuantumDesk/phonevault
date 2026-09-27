/// <reference types="vite/client" />
// Phone Vault Companion UI. One main view (account, balances, Send, Receive, activity), a send
// stepper driven only by real command results and `send-progress` events, and a settings drawer.

import { api, onProgress, openExternal, appVersion, notify, errText, isTauri } from "./api";
import type { Status, Quote, Signed, SendError, HistoryEntry, FeeEstimate } from "./api";
import { NETWORKS, DEFAULT_CHAIN, byId, type Network } from "./networks";
import { h, icon, padlock, short, shortHash, grouped, fmtAmount, fmtUsd, ago, clock, copy } from "./ui";
import { qrSvg } from "./qr";
import { tokenSection, refreshTokenBalances, tokensOn, tokenAt, tokenBalanceOf, fmtExact, validTokenAmount, quoteAmount } from "./tokens";
import { mountWalletConnect, wcHomeSlot, wcSettingsSection, wcPhoneBusy } from "./walletconnect";

// ------------------------------------------------------------------ preferences (non-sensitive)

type Theme = "dark" | "light" | "system";
interface Prefs { chainId: number; rpc: Record<string, string>; notify: boolean; theme: Theme }
const PREFS_KEY = "phonevault.prefs.v1";
function loadPrefs(): Prefs {
  const d: Prefs = { chainId: DEFAULT_CHAIN, rpc: {}, notify: true, theme: "dark" };
  try {
    const p = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}");
    return { chainId: NETWORKS.some((n) => n.id === p.chainId) ? p.chainId : d.chainId, rpc: p.rpc && typeof p.rpc === "object" ? p.rpc : {}, notify: p.notify !== false, theme: ["dark", "light", "system"].includes(p.theme) ? p.theme : d.theme };
  } catch { return d; }
}
const prefs = loadPrefs();
function savePrefs() { try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* preferences are a convenience */ } }
const rpcFor = (id: number) => prefs.rpc[id] || byId(id).rpc;
const net = () => byId(prefs.chainId);
function applyTheme() {
  if (prefs.theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", prefs.theme);
}

// ------------------------------------------------------------------ live data

let status: Status | null = null;
let statusError: string | null = null;
interface Bal { eth: string; wei: bigint; at: number }
const balances = new Map<number, Bal>();
const balErrors = new Map<number, string>();
const prices: Record<string, number | null> = {};
let history: HistoryEntry[] = [];
const price = (n: Network) => prices[n.symbol] ?? null;

async function refreshStatus() {
  try {
    const s = await api.status();
    const pairedChanged = s.paired !== status?.paired;
    const phoneChanged = s.phone !== status?.phone;
    const appeared = (status?.phone ?? "none") === "none" && s.phone !== "none";
    status = s; statusError = null;
    if (s.phone === "none") identity = { s: "unknown" };
    else if (appeared) identifyPhone();
    renderHeader();
    if (pairedChanged) { balances.clear(); balErrors.clear(); if (s.paired) { refreshAllBalances(); } render(); }
    else if (phoneChanged && (view === "pair" || drawerOpen)) { render(); if (drawerOpen) renderDrawer(); }
  } catch (e) { statusError = errText(e); renderHeader(); }
}

async function refreshBalance(n: Network) {
  if (!status?.paired) return;
  try {
    const w = await api.wallet(rpcFor(n.id));
    if (w.chain_id !== n.id) throw `this node is on chain ${w.chain_id}, not ${n.name}. Check the node in Settings.`;
    const wei = BigInt(w.balance_wei);
    const prev = balances.get(n.id);
    balances.set(n.id, { eth: w.balance_eth, wei, at: Date.now() });
    balErrors.delete(n.id);
    if (prev && wei > prev.wei) await incoming(n, wei - prev.wei, w.balance_eth);
  } catch (e) { balErrors.set(n.id, errText(e)); }
  if (view === "home") renderSoon();
  if (view === "send" && flow.s === "form") updateFormBalance();
  // ERC-20 balances for the network in view (display only)
  if (n.id === prefs.chainId || (view === "send" && n.id === flowNet.id)) {
    void refreshTokenBalances(n.id, rpcFor(n.id)).then(() => {
      if (view === "home") renderSoon();
      if (view === "send" && flow.s === "form") updateFormBalance();
    });
  }
}
const refreshAllBalances = () => Promise.allSettled(NETWORKS.map(refreshBalance));

function weiToEth(wei: bigint): string {
  const whole = wei / 10n ** 18n; const frac = (wei % 10n ** 18n).toString().padStart(18, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : `${whole}`;
}
async function incoming(n: Network, delta: bigint, balanceEth: string) {
  try { history = await api.historyAddIncoming(n.id, delta.toString()); } catch { /* history is best effort */ }
  if (prefs.notify) await notify(`Received ${fmtAmount(weiToEth(delta), 8)} ${n.symbol} on ${n.name}. Balance ${fmtAmount(balanceEth, 8)} ${n.symbol}.`);
}

async function refreshPrices() {
  for (const sym of new Set(NETWORKS.map((n) => n.symbol))) {
    try { prices[sym] = await api.spotUsd(sym); } catch { prices[sym] = prices[sym] ?? null; }
  }
  if (view === "home") renderSoon();
}

async function refreshHistory() {
  try { history = await api.history(); } catch { /* keep what we have */ }
  if (view === "home") renderSoon();
}

/** Background receipt check for anything this companion sent that is still pending. */
async function pollPending() {
  const open = history.filter((e) => e.kind === "out" && e.status === "pending" && e.hash && Date.now() / 1000 - e.time < 86400 * 2);
  for (const e of open) {
    try {
      const rc = await api.receipt(rpcFor(e.chain_id), e.hash!);
      if (rc.mined) { history = await api.historyMark(e.hash!, rc.success ? "confirmed" : "failed", rc.block); refreshBalance(byId(e.chain_id)); }
    } catch { /* retry next round */ }
  }
  if (open.length && view === "home") renderSoon();
}

// ------------------------------------------------------------------ shell

type View = "home" | "send" | "receive" | "pair" | "tool";
let view: View = "home";
let drawerOpen = false;
const app = document.getElementById("app")!;
const header = h("header", { class: "top" });
const main = h("main", { id: "view" });
const scrim = h("div", { class: "scrim", onclick: () => closeDrawer() });
const drawer = h("aside", { class: "drawer", "aria-label": "Settings", "aria-hidden": "true" });
app.append(header, main, scrim, drawer);

function go(v: View) { view = v; main.scrollTop = 0; window.scrollTo(0, 0); render(); }

function renderHeader() {
  const phone = status?.phone ?? "none";
  let label = statusError ? "USB unavailable" : phone === "accessory" ? "Phone connected" : phone === "android" ? "Phone on USB" : "No phone";
  let title = statusError ?? (phone === "android" ? "The phone is on USB. It switches to vault mode when a request is sent." : phone === "none" ? "Plug the vault into this Mac with a USB cable." : "The vault is connected in accessory mode.");
  let cls: string = statusError ? "none" : phone;
  if (!statusError && phone !== "none") {
    if (identity.s === "checking") { label = "Checking phone…"; title = "Asking the phone which wallet it holds."; }
    else if (identity.s === "match") { label = "Your phone"; title = "The phone on USB holds the wallet this Mac is paired with."; cls = "accessory"; }
    else if (identity.s === "different") { label = "Different wallet"; title = "The phone on USB holds a different wallet. Click to review."; cls = "danger"; }
    else if (identity.s === "unreadable") { label = "Unlock your phone"; title = "The phone is asking to be unlocked. This updates by itself once you unlock it."; }
  }
  const retry = identity.s === "unreadable" ? () => identifyPhone()
    : identity.s === "different" ? () => { if (identity.s === "different") identity.dismissed = false; renderPhoneNotice(); } : undefined;
  header.replaceChildren(...[
    h("button", { class: "brand", onclick: () => go("home"), title: "Home" }, padlock(2), h("span", null, "PHONE VAULT")),
    retry ? h("button", { class: `chip ${cls}`, title, onclick: retry }, h("i", { class: "dot" }), label)
      : h("span", { class: `chip ${cls}`, title }, h("i", { class: "dot" }), label),
    h("button", { class: "icon-btn", onclick: () => openDrawer(), "aria-label": "Settings", title: "Settings" }, icon("gear", 20)),
  ].filter((x): x is HTMLElement => !!x));
}

let renderQueued = false;
function renderSoon() {
  if (renderQueued) return; renderQueued = true;
  requestAnimationFrame(() => {
    renderQueued = false;
    // don't yank a control out from under the user
    const a = document.activeElement;
    if (a && main.contains(a) && (a.tagName === "SELECT" || a.tagName === "INPUT")) { setTimeout(renderSoon, 1500); return; }
    render();
  });
}

function render() {
  if (!status) { main.replaceChildren(h("div", { class: "boot" }, h("div", { class: "spinner" }))); return; }
  if (!status.paired && view !== "tool") view = "pair";
  const el = view === "home" ? homeView() : view === "send" ? sendView() : view === "receive" ? receiveView() : view === "pair" ? pairView() : toolView();
  main.replaceChildren(el);
}

// ------------------------------------------------------------------ home

function networkSelect(onChange?: () => void, cls = "net-chip") {
  const sel = h("select", { class: "net-select", "aria-label": "Network" },
    NETWORKS.map((n) => h("option", { value: n.id, selected: n.id === prefs.chainId }, n.testnet ? `${n.name} (testnet)` : n.name)));
  sel.addEventListener("change", () => { prefs.chainId = Number(sel.value); savePrefs(); refreshBalance(net()); onChange ? onChange() : render(); });
  return h("label", { class: cls }, h("i", { class: `net-dot n${net().id}` }), h("span", null, net().name), icon("chevron", 14), sel);
}

function homeView() {
  const n = net();
  const b = balances.get(n.id);
  const err = balErrors.get(n.id);
  const addr = status!.paired_checksum!;
  const usd = b ? fmtUsd(b.eth, price(n)) : null;
  return h("div", { class: "stack fade" },
    h("section", { class: "card account" },
      h("div", { class: "row between" },
        h("p", { class: "kicker" }, "ACCOUNT 1"),
        networkSelect(),
      ),
      h("button", { class: "addr-btn", title: `${addr}\nClick to copy`, onclick: () => copy(addr) }, h("span", { class: "mono" }, short(addr)), icon("copy", 15)),
      h("div", { class: "balance" },
        b ? h("span", { class: "amount" }, fmtAmount(b.eth), h("span", { class: "unit" }, n.symbol)) : err ? null : h("span", { class: "amount skeleton" }, "0.0000"),
        usd ? h("span", { class: "fiat" }, usd) : null,
      ),
      err ? h("p", { class: "inline-error" }, icon("alert", 15), `Balance unavailable: ${err}`) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => startSend() }, icon("up", 20), "Send"),
        h("button", { class: "big", onclick: () => go("receive") }, icon("down", 20), "Receive"),
      ),
    ),
    wcHomeSlot(),
    h("section", { class: "section" },
      h("h3", { class: "section-title" }, "Balances"),
      h("ul", { class: "list nets" }, NETWORKS.map((x) => {
        const bx = balances.get(x.id); const ex = balErrors.get(x.id);
        const zero = bx && bx.wei === 0n;
        return h("li", null, h("button", { class: `net-row${x.id === n.id ? " on" : ""}${zero ? " zero" : ""}`, onclick: () => { prefs.chainId = x.id; savePrefs(); render(); refreshBalance(x); } },
          h("i", { class: `net-dot n${x.id}` }),
          h("span", { class: "grow" }, x.name, x.testnet ? h("span", { class: "tag" }, "testnet") : null),
          ex && !bx ? h("span", { class: "muted small", title: ex }, "unavailable") : h("span", { class: "mono num" }, bx ? `${fmtAmount(bx.eth, 5)} ${x.symbol}` : "…"),
          h("span", { class: "muted small fiat-col" }, bx && !x.testnet ? fmtUsd(bx.eth, price(x)) ?? "" : ""),
        ));
      })),
    ),
    tokenSection(n.id, n.name),
    h("section", { class: "section" },
      h("h3", { class: "section-title" }, "Activity"),
      history.length ? h("ul", { class: "list activity" }, history.slice(0, 30).map(activityRow))
        : h("p", { class: "empty" }, "Nothing yet. Transactions you send from this Mac, and funds that arrive while it is open, show up here."),
    ),
  );
}

function activityRow(e: HistoryEntry) {
  const n = byId(e.chain_id);
  const out = e.kind === "out";
  const url = e.hash ? `${n.explorer}/tx/${e.hash}` : `${n.explorer}/address/${status?.paired_checksum}`;
  const badge = e.status === "pending" ? h("span", { class: "badge pending" }, h("i", { class: "mini-spin" }), "Pending")
    : e.status === "failed" ? h("span", { class: "badge failed" }, "Failed")
    : e.status === "confirmed" ? h("span", { class: "badge ok" }, "Confirmed") : null;
  return h("li", null, h("button", { class: "act-row", onclick: () => openExternal(url), title: e.hash ? `${e.hash}\nOpen in explorer` : "Open the address in the explorer" },
    h("span", { class: `act-ic ${out ? "out" : "in"}` }, icon(out ? "up" : "down", 16)),
    h("span", { class: "grow" },
      h("span", { class: "act-title" }, `${out ? "Sent" : "Received"} ${e.token_symbol ? `${fmtExact(e.token_amount ?? "?")} ${e.token_symbol}` : `${fmtAmount(e.amount_eth)} ${n.symbol}`}`),
      h("span", { class: "act-sub" }, [out && e.counterparty ? `to ${short(e.counterparty)}` : null, n.name, ago(e.time)].filter(Boolean).join(" · ")),
    ),
    badge,
    h("span", { class: "muted ext" }, icon("external", 15)),
  ));
}

// ------------------------------------------------------------------ receive

function receiveView() {
  const n = net();
  const addr = status!.paired_checksum!;
  const qr = h("div", { class: "qr", html: qrSvg(addr, { dark: "#060608", light: "#ffffff", label: `QR code for ${addr}` }) });
  return h("div", { class: "stack fade" },
    topbar("Receive", () => go("home")),
    h("section", { class: "card receive" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, "YOUR ADDRESS"), networkSelect()),
      h("div", { class: "qr-tile" }, qr),
      h("button", { class: "addr-full", onclick: () => copy(addr), title: "Click to copy" }, h("span", { class: "mono" }, grouped(addr)), icon("copy", 16)),
      h("div", { class: "row center" }, h("button", { class: "primary", onclick: () => copy(addr) }, icon("copy", 16), "Copy address")),
    ),
    h("div", { class: `callout${n.testnet ? "" : " accent"}` },
      h("strong", null, n.testnet ? `Only send ${n.name} test ${n.symbol} to this address on ${n.name}.` : `Only send ${n.name === "Ethereum" ? "" : n.name + " "}${n.symbol} to this address on ${n.name}.`),
      h("span", null, `It is the same address on every network, so check the sender is using ${n.name}. Before sharing it for a large amount, compare it with the Wallet screen on your phone.`),
    ),
  );
}

function topbar(title: string, back: (() => void) | null, extra?: Node) {
  return h("div", { class: "topbar" },
    back ? h("button", { class: "icon-btn", onclick: back, "aria-label": "Back" }, icon("back", 20)) : h("span", { class: "icon-btn ghosted" }),
    h("h2", null, title),
    extra ?? h("span", { class: "icon-btn ghosted" }),
  );
}

// ------------------------------------------------------------------ pairing

type PairState = { s: "idle"; error?: string } | { s: "reading" } | { s: "compare"; address: string } | { s: "mismatch" };
let pair: PairState = { s: "idle" };

function pairView() {
  const paired = !!status?.paired;
  const phone = status?.phone ?? "none";
  const back = paired ? () => { pair = { s: "idle" }; go("home"); } : null;
  let body: Node;
  if (pair.s === "compare") {
    const address = pair.address;
    body = h("section", { class: "card" },
      h("p", { class: "kicker" }, "COMPARE"),
      h("h3", null, "Does this match your phone?"),
      h("p", { class: "muted" }, "On the phone, open Wallet. Compare every group of four characters below with the address it shows."),
      h("p", { class: "addr-compare mono" }, grouped(address)),
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: async () => {
          try { await api.confirmPairing(address); pair = { s: "idle" }; identity = { s: "match" }; await refreshStatus(); renderPhoneNotice(); go("home"); } catch (e) { pair = { s: "idle", error: errText(e) }; render(); }
        } }, icon("check", 18), "It matches"),
        h("button", { class: "big", onclick: () => { pair = { s: "mismatch" }; render(); } }, "It doesn't"),
      ),
    );
  } else if (pair.s === "mismatch") {
    body = h("section", { class: "card danger-card" },
      h("p", { class: "kicker danger" }, "NOT PAIRED"),
      h("h3", null, "Stop here"),
      h("p", null, "If the phone shows a different address, something between this Mac and the phone is changing data. Nothing was saved. Use another cable and port, and don't send funds until the addresses match."),
      h("div", { class: "actions" }, h("button", { onclick: () => { pair = { s: "idle" }; render(); } }, "Start over")),
    );
  } else {
    const reading = pair.s === "reading";
    body = h("section", { class: "card pair" },
      h("div", { class: "pair-hero" }, padlock(6)),
      h("h3", null, paired ? "Pair again" : "Pair your phone"),
      h("p", { class: "muted" }, "This Mac remembers your phone's address and checks every signature against it. It never sees a key."),
      h("ol", { class: "steps" },
        h("li", { class: phone !== "none" ? "done" : "" }, "Plug the vault into this Mac and unlock it."),
        h("li", null, "Read its address over USB."),
        h("li", null, "Compare it with the phone's screen, then pair."),
      ),
      pair.s === "idle" && pair.error ? h("p", { class: "inline-error" }, icon("alert", 15), explainPlain(pair.error)) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", disabled: reading, onclick: readAddress }, reading ? h("i", { class: "mini-spin" }) : icon("phone", 18), reading ? "Asking the phone…" : "Read address from phone"),
      ),
      reading ? h("p", { class: "muted small center" }, "Unlock the phone if it asks. This takes a few seconds.") : null,
    );
  }
  return h("div", { class: "stack fade" }, paired ? topbar("Pairing", back) : null, body);
}

// ------------------------------------------------------------------ phone identity
// When a phone appears, ask it which wallet it holds and compare with the pairing, so a reset,
// restored or swapped phone is noticed at once instead of at signing time. Pairing itself still
// ends with the person comparing the address against the phone's own screen.
type Identity = { s: "unknown" } | { s: "checking" } | { s: "match" }
  | { s: "different"; address: string; dismissed: boolean } | { s: "unreadable"; error: string };
let identity: Identity = { s: "unknown" };

let identifying = false;
/** Read fresh each time: status changes while a request is in flight. */
const phonePresent = (): boolean => (status?.phone ?? "none") !== "none";
async function identifyPhone() {
  if (identifying || pair.s === "reading" || !status || status.phone === "none") return;
  if (view === "send" && flow.s !== "form") { setTimeout(identifyPhone, 5000); return; } // never talk over a send
  if (wcPhoneBusy()) { setTimeout(identifyPhone, 5000); return; } // nor over a WalletConnect request
  identifying = true;
  // A locked phone holds the request on its lock screen and answers after unlock; keep the
  // "Unlock your phone" label steady while asking again rather than flickering to "Checking".
  if (identity.s !== "unreadable") { identity = { s: "checking" }; renderHeader(); }
  try {
    const address = await api.readAddress();
    if (!status?.paired) { identity = { s: "unknown" }; pair = { s: "compare", address }; go("pair"); }
    else if (address.toLowerCase() === status.paired.toLowerCase()) identity = { s: "match" };
    else identity = { s: "different", address, dismissed: false };
  } catch (e) { identity = { s: "unreadable", error: errText(e) }; }
  finally { identifying = false; }
  renderHeader(); renderPhoneNotice();
  if (identity.s === "unreadable" && phonePresent()) setTimeout(identifyPhone, 2000);
}

let noticeEl: HTMLElement | null = null;
function renderPhoneNotice() {
  noticeEl?.remove(); noticeEl = null;
  if (identity.s !== "different" || identity.dismissed || view === "pair") return;
  const found = identity.address;
  const close = () => { if (identity.s === "different") identity.dismissed = true; renderPhoneNotice(); };
  noticeEl = h("div", { class: "modal-scrim fade", onclick: (e: Event) => { if (e.target === noticeEl) close(); } },
    h("section", { class: "card modal", role: "dialog", "aria-modal": "true" },
      h("p", { class: "kicker" }, "NEW WALLET ON USB"),
      h("h3", null, "This phone holds a different wallet"),
      h("p", { class: "muted" }, "That happens after the phone was reset or restored, or when it is a different phone. Sending stays blocked until you pair it."),
      h("div", { class: "set-row" }, h("span", { class: "muted" }, "Paired with"), h("span", { class: "mono" }, short(status?.paired_checksum ?? ""))),
      h("div", { class: "set-row" }, h("span", { class: "muted" }, "Phone on USB"), h("span", { class: "mono" }, short(found))),
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => { noticeEl?.remove(); noticeEl = null; identity = { s: "unknown" }; pair = { s: "compare", address: found }; go("pair"); } }, icon("phone", 18), "Pair this phone"),
        h("button", { class: "big", onclick: close }, "Not now"),
      ),
    ));
  document.body.append(noticeEl);
}

async function readAddress() {
  pair = { s: "reading" }; render();
  try { const address = await api.readAddress(); pair = { s: "compare", address }; }
  catch (e) { pair = { s: "idle", error: errText(e) }; }
  if (view === "pair") render();
}

/** Plain wording for common transport errors (pairing and elsewhere). */
function explainPlain(m: string): string {
  if (/no Android device/i.test(m)) return "No phone found on USB. Plug it in and unlock it.";
  if (/held by another program|adb/i.test(m)) return "Another program holds the phone's USB connection, usually the adb server. Run `adb kill-server` and try again.";
  if (/did not answer|not reading/i.test(m)) return "The phone didn't answer. Wake and unlock it; if that fails, unplug and reconnect the cable.";
  if (/not ready/i.test(m)) return "The phone isn't ready: unlock it and finish the backup check first.";
  return m;
}

// ------------------------------------------------------------------ send flow
//
// Every state below is entered only from a real result: a command returning, a command failing,
// or a `send-progress` event carrying this attempt's ticket. "Review on your phone" requires the
// `delivered` event, i.e. the USB write to the phone completed.

type Flow =
  | { s: "form" }
  | { s: "quoting" }
  | { s: "review"; quote: Quote }
  | { s: "connecting"; quote: Quote; ticket: string; t0: number; cancelling?: boolean }
  | { s: "on_phone"; quote: Quote; ticket: string; t0: number; cancelling?: boolean }
  | { s: "verifying"; quote: Quote; ticket: string }
  | { s: "failed"; quote: Quote; err: SendError }
  | { s: "signed"; quote: Quote; signed: Signed }
  | { s: "broadcasting"; quote: Quote; signed: Signed }
  | { s: "broadcast_failed"; quote: Quote; signed: Signed; message: string }
  | { s: "submitted"; quote: Quote; hash: string; t0: number; slow: boolean; trouble: boolean }
  | { s: "done"; quote: Quote; hash: string; block: number; ok: boolean };

let flow: Flow = { s: "form" };
let flowNet: Network = net();
let activeTicket: string | null = null;
let formError: string | null = null;
/** asset: "" for the native coin, else a token contract from the built-in list on flowNet */
const draft = { to: "", amount: "", asset: "" };
const draftToken = () => (draft.asset ? tokenAt(flowNet.id, draft.asset) : undefined);
let fee: FeeEstimate | null = null;
let tick = 0;
const REVIEW_LIMIT_MS = 300_000;

function setFlow(f: Flow) {
  flow = f;
  clearInterval(tick);
  if (f.s === "on_phone" || f.s === "connecting" || f.s === "submitted") tick = window.setInterval(updateClock, 1000);
  if (view === "send") render();
}

function startSend() {
  if (identity.s === "different") { identity.dismissed = false; renderPhoneNotice(); return; }
  flow = { s: "form" }; formError = null; activeTicket = null; flowNet = net(); fee = null;
  if (draft.asset && !tokenAt(flowNet.id, draft.asset)) { draft.asset = ""; draft.amount = ""; }
  go("send");
  loadFee();
}

async function loadFee() {
  const n = flowNet;
  try { const f = await api.feeEstimate(rpcFor(n.id)); if (n === flowNet) { fee = f; updateFormExtras(); } } catch { fee = null; updateFormExtras(); }
}

const STEPS = ["Details", "Phone", "Broadcast", "Confirmed"];
function stepOf(f: Flow): number {
  switch (f.s) {
    case "form": case "quoting": case "review": return 0;
    case "connecting": case "on_phone": case "verifying": case "failed": return 1;
    case "signed": case "broadcasting": case "broadcast_failed": return 2;
    default: return 3;
  }
}
function stepper() {
  const at = stepOf(flow);
  const bad = flow.s === "failed" || flow.s === "broadcast_failed" || (flow.s === "done" && !flow.ok);
  return h("ol", { class: "stepper", "aria-label": "Progress" }, STEPS.map((label, i) =>
    h("li", { class: i < at || (i === at && flow.s === "done" && flow.ok) ? "done" : i === at ? (bad ? "now bad" : "now") : "" },
      h("span", { class: "bullet" }, i < at || (i === at && flow.s === "done" && flow.ok) ? icon("check", 12) : String(i + 1)), h("span", { class: "lbl" }, label))));
}

function sendView() {
  const busy = ["connecting", "on_phone", "verifying", "broadcasting", "submitted"].includes(flow.s);
  const back = busy ? null : () => { if (flow.s === "review") { setFlow({ s: "form" }); } else go("home"); };
  return h("div", { class: "stack fade" },
    topbar(`Send on ${flowNet.name}`, back),
    stepper(),
    h("div", { class: "flow-body", "aria-live": "polite" }, flowBody()),
  );
}

// refs into the form that update without re-rendering (keeps focus and caret)
let formRefs: { toMsg: HTMLElement; amtFiat: HTMLElement; feeLine: HTMLElement; avail: HTMLElement; go: HTMLButtonElement; toInput: HTMLInputElement; amtInput: HTMLInputElement; err: HTMLElement } | null = null;
let addrOk = false;
let addrSeq = 0;

function flowBody(): Node {
  const q = "quote" in flow ? flow.quote : null;
  const n = flowNet;
  const usd = (eth: string) => fmtUsd(eth, price(n));
  switch (flow.s) {
    case "form": case "quoting": {
      const quoting = flow.s === "quoting";
      const toInput = h("input", { id: "to", type: "text", placeholder: "0x…", spellcheck: "false", autocomplete: "off", value: draft.to, disabled: quoting });
      const amtInput = h("input", { id: "amount", type: "text", inputmode: "decimal", placeholder: "0.00", autocomplete: "off", value: draft.amount, disabled: quoting });
      const refs = {
        toInput, amtInput,
        toMsg: h("p", { class: "field-msg" }),
        amtFiat: h("p", { class: "field-msg" }),
        feeLine: h("div", { class: "fee-line" }),
        avail: h("span", { class: "muted small" }),
        go: h("button", { class: "big primary wide", disabled: true, type: "submit" }, quoting ? [h("i", { class: "mini-spin" }), "Getting a quote…"] : "Review"),
        err: h("div", null),
      };
      formRefs = refs;
      toInput.addEventListener("input", () => { draft.to = toInput.value; checkAddr(); });
      amtInput.addEventListener("input", () => { draft.amount = amtInput.value.replace(",", "."); updateFormExtras(); });
      const tok = draftToken();
      const max = h("button", { class: "chip-btn", type: "button", disabled: quoting, onclick: async () => {
        max.disabled = true;
        try {
          if (tok) {
            const b = tokenBalanceOf(n.id, tok.address);
            if (!b?.amount) throw `${tok.symbol} balance not loaded yet`;
            draft.amount = b.amount; amtInput.value = b.amount; formError = null;
          } else { const m = await api.maxSendable(rpcFor(n.id), addrOk ? draft.to.trim() : null); draft.amount = m.amount_eth; amtInput.value = m.amount_eth; formError = null; }
        }
        catch (e) { formError = errText(e); }
        max.disabled = false; updateFormExtras();
      } }, "Max");
      // asset: the native coin or a token from the built-in list (the same list the phone uses)
      const assetSel = h("select", { class: "net-select", "aria-label": "Asset", disabled: quoting },
        h("option", { value: "", selected: !tok }, `${n.symbol} (native)`),
        tokensOn(n.id).map((t) => h("option", { value: t.address, selected: tok?.address === t.address }, `${t.symbol} · ${t.name}`)));
      assetSel.addEventListener("change", () => { draft.asset = assetSel.value; draft.amount = ""; formError = null; setFlow({ s: "form" }); });
      const assetField = tokensOn(n.id).length ? h("label", { class: "field" }, h("span", { class: "field-label" }, "Asset"),
        h("span", { class: "net-chip asset-chip" }, h("span", null, tok ? `${tok.symbol} · ${tok.name}` : `${n.symbol} (native)`), icon("chevron", 14), assetSel)) : null;
      const form = h("form", { class: "card form", novalidate: true },
        h("div", { class: "from-line" }, h("span", { class: "muted small" }, "From Account 1 · ", h("span", { class: "mono" }, short(status!.paired_checksum!))), refs.avail),
        assetField,
        h("label", { class: "field" }, h("span", { class: "field-label" }, "To"), toInput, refs.toMsg),
        h("label", { class: "field" }, h("span", { class: "field-label" }, "Amount"),
          h("div", { class: "input-wrap" }, amtInput, h("span", { class: "suffix" }, tok ? tok.symbol : n.symbol), max), refs.amtFiat),
        refs.feeLine,
        refs.err,
        refs.go,
      );
      form.addEventListener("submit", (ev) => { ev.preventDefault(); getQuote(); });
      queueMicrotask(() => { checkAddr(); updateFormExtras(); updateFormBalance(); if (!quoting) (draft.to ? amtInput : toInput).focus(); });
      return form;
    }
    case "review": {
      const quote = flow.quote;
      return h("section", { class: "card" },
        h("p", { class: "kicker" }, "CHECK, THEN SEND TO YOUR PHONE"),
        quote.token ? h("div", { class: "hero-amount" }, h("span", { class: "amount" }, fmtExact(quote.token.amount), h("span", { class: "unit" }, quote.token.symbol)))
          : h("div", { class: "hero-amount" }, h("span", { class: "amount" }, fmtAmount(quote.amount_eth, 8), h("span", { class: "unit" }, n.symbol)), usd(quote.amount_eth) ? h("span", { class: "fiat" }, usd(quote.amount_eth)) : null),
        h("dl", { class: "facts" },
          quote.token ? fact("Token", h("span", null, `${quote.token.name} (${quote.token.symbol}) · `,
            h("span", { class: "mono", title: quote.token.contract }, short(tokenAt(n.id, quote.token.contract)?.address ?? quote.token.contract)))) : null,
          fact("To", h("span", { class: "mono break" }, grouped(checksumOf(quote.token ? quote.token.recipient : quote.to)))),
          fact("Network", quote.network),
          fact("Network fee", h("span", null, `at most ${fmtAmount(quote.max_fee_eth, 8)} ${n.symbol}`, usd(quote.max_fee_eth) ? h("span", { class: "muted" }, ` · ${usd(quote.max_fee_eth)}`) : null)),
          quote.token ? fact("Total at most", `${fmtExact(quote.token.amount)} ${quote.token.symbol} + ${fmtAmount(quote.max_fee_eth, 8)} ${n.symbol} fee`)
            : fact("Total at most", h("span", null, `${fmtAmount(quote.total_eth, 8)} ${n.symbol}`, usd(quote.total_eth) ? h("span", { class: "muted" }, ` · ${usd(quote.total_eth)}`) : null)),
          fact("Nonce", h("span", { class: "mono" }, String(parseInt(quote.nonce, 16)))),
        ),
        n.l2 ? h("p", { class: "note" }, `${n.name} also charges a small L1 data fee that neither this Mac nor the phone can bound in advance. It is usually a fraction of a cent.`) : null,
        quote.token ? h("p", { class: "note" }, `Your phone names the token from its own built-in list: it should read "Send ${fmtExact(quote.token.amount)} ${quote.token.symbol} to" this recipient. If it says "Unknown token contract", reject it there.`) : null,
        h("p", { class: "note" }, "Your phone shows these same details. Approve there only if they match. Nothing reaches the network until you press Broadcast afterwards."),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => sendToPhone(quote) }, icon("phone", 18), "Send to phone"),
          h("button", { class: "big", onclick: () => setFlow({ s: "form" }) }, "Edit"),
        ),
      );
    }
    case "connecting":
      return statusCard("connecting", "Reaching your phone…", "Opening the USB connection and switching the phone to vault mode. The request is not on the phone yet.",
        [clockLine(flow.t0, null)], [cancelBtn(flow.cancelling)]);
    case "on_phone":
      return h("section", { class: "card phone-wait" },
        h("div", { class: "phone-art" }, h("div", { class: "phone-screen" }, padlock(3))),
        h("h3", null, "Review on your phone"),
        h("p", { class: "muted" }, "The request is on your phone. Unlock it if needed, check the details, and tap Approve & sign."),
        h("ul", { class: "checklist" },
          h("li", null, h("span", { class: "muted" }, "Amount"), h("strong", null, quoteAmount(q!, `${fmtAmount(q!.amount_eth, 8)} ${n.symbol}`))),
          h("li", null, h("span", { class: "muted" }, "To"), h("strong", { class: "mono" }, short(checksumOf(q!.token ? q!.token.recipient : q!.to)))),
          q!.token ? h("li", null, h("span", { class: "muted" }, "Token contract"), h("strong", { class: "mono" }, short(tokenAt(n.id, q!.token.contract)?.address ?? q!.token.contract))) : null,
          h("li", null, h("span", { class: "muted" }, "Network"), h("strong", null, q!.network)),
        ),
        clockLine(flow.t0, REVIEW_LIMIT_MS),
        h("div", { class: "actions" }, cancelBtn(flow.cancelling)),
      );
    case "verifying":
      return statusCard("connecting", "Checking the signature…", "Decoding what the phone returned and comparing every field with what you entered.", [], []);
    case "failed": {
      const x = explain(flow.err);
      const quote = flow.quote;
      return h("section", { class: `card result ${x.danger ? "danger-card" : ""}` },
        h("div", { class: `result-ic ${x.danger ? "bad" : x.neutral ? "neutral" : "warn"}` }, icon(x.danger ? "alert" : "x", 28)),
        h("h3", null, x.title),
        h("p", null, x.body),
        flow.err.message && !x.hideDetail ? h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, flow.err.message)) : null,
        h("div", { class: "actions" },
          x.danger ? null : h("button", { class: "big primary", onclick: () => sendToPhone(quote) }, icon("refresh", 18), "Try again"),
          h("button", { class: "big", onclick: () => setFlow({ s: "form" }) }, "Edit"),
          x.danger ? h("button", { class: "big", onclick: () => go("home") }, "Close") : null,
        ),
      );
    }
    case "signed": case "broadcasting": case "broadcast_failed": {
      const signed = flow.signed; const quote = flow.quote;
      const sending = flow.s === "broadcasting";
      return h("section", { class: "card result" },
        h("div", { class: "result-ic ok" }, icon("check", 28)),
        h("h3", null, "Signed and verified"),
        h("ul", { class: "verified" },
          h("li", null, icon("check", 14), quote.token ? "Token contract, amount, recipient, fee and nonce match what you entered (decoded from the signed bytes)" : "Amount, recipient, fee and nonce match what you entered"),
          h("li", null, icon("check", 14), "Transaction hash recomputed on this Mac"),
          h("li", null, icon("check", 14), "Signed by your paired phone ", h("span", { class: "mono" }, short(signed.signer))),
        ),
        h("dl", { class: "facts" },
          fact("Send", quoteAmount(quote, `${fmtAmount(quote.amount_eth, 8)} ${n.symbol}${usd(quote.amount_eth) ? ` · ${usd(quote.amount_eth)}` : ""}`)),
          fact("To", h("span", { class: "mono" }, short(checksumOf(quote.token ? quote.token.recipient : quote.to)))),
          fact("Hash", h("button", { class: "link mono", onclick: () => copy(signed.hash, "Hash") }, shortHash(signed.hash))),
        ),
        flow.s === "broadcast_failed" ? h("div", { class: "inline-error block" }, icon("alert", 15), h("span", null, h("strong", null, "The node didn't accept it. "), explainBroadcast(flow.message), h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, flow.message)))) : null,
        h("p", { class: "note" }, `Not on the network yet. Broadcast sends it to ${n.name} through ${hostOf(rpcFor(n.id))}.`),
        h("div", { class: "actions" },
          h("button", { class: "big primary", disabled: sending, onclick: () => doBroadcast(quote, signed) }, sending ? [h("i", { class: "mini-spin" }), "Broadcasting…"] : [icon("up", 18), flow.s === "broadcast_failed" ? "Retry broadcast" : `Broadcast to ${n.name}`]),
          h("button", { class: "big", disabled: sending, onclick: () => { activeTicket = null; setFlow({ s: "form" }); } }, "Discard"),
        ),
      );
    }
    case "submitted": {
      const hash = flow.hash;
      return h("section", { class: "card result" },
        h("div", { class: "result-ic pending" }, h("i", { class: "spinner" })),
        h("h3", null, `Submitted to ${n.name}`),
        h("p", { class: "muted" }, flow.slow ? "Taking longer than usual. It stays valid; you can close this and it will update in Activity." : "Waiting for it to be included in a block…"),
        flow.trouble ? h("p", { class: "muted small" }, "The node isn't answering right now; still trying.") : null,
        clockLine(flow.t0, null),
        hashLinks(hash),
        h("div", { class: "actions" }, h("button", { class: "big", onclick: () => go("home") }, "Close")),
      );
    }
    case "done": {
      return h("section", { class: `card result ${flow.ok ? "" : "danger-card"}` },
        h("div", { class: `result-ic ${flow.ok ? "ok big" : "bad"}` }, icon(flow.ok ? "check" : "alert", 32)),
        h("h3", null, flow.ok ? "Confirmed" : "Included, but it failed"),
        h("p", { class: "muted" }, flow.ok ? `${quoteAmount(flow.quote, `${fmtAmount(flow.quote.amount_eth, 8)} ${n.symbol}`)} sent on ${n.name}, in block ${flow.block.toLocaleString("en-US")}.` : `The network ran it in block ${flow.block.toLocaleString("en-US")} and it reverted. The amount was not sent, but the fee was paid.`),
        hashLinks(flow.hash),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => go("home") }, "Done"),
          h("button", { class: "big", onclick: () => { draft.amount = ""; startSend(); } }, "Send another"),
        ),
      );
    }
  }
}

function fact(k: string, v: Node | string) { return h("div", { class: "fact" }, h("dt", null, k), h("dd", null, v)); }
let toChecksum: string | null = null;
function checksumOf(lower: string) { return toChecksum && toChecksum.toLowerCase() === lower ? toChecksum : lower; }
function hostOf(url: string) { try { return new URL(url).host; } catch { return url; } }
function hashLinks(hash: string) {
  const url = `${flowNet.explorer}/tx/${hash}`;
  return h("div", { class: "hash-box" },
    h("button", { class: "link mono", title: hash, onclick: () => copy(hash, "Hash") }, shortHash(hash), icon("copy", 14)),
    h("button", { class: "link", onclick: () => openExternal(url) }, `View on ${hostOf(flowNet.explorer)}`, icon("external", 14)),
  );
}
function statusCard(kind: string, title: string, body: string, extra: Node[], actions: Node[]) {
  return h("section", { class: `card result ${kind}` }, h("div", { class: "result-ic pending" }, h("i", { class: "spinner" })), h("h3", null, title), h("p", { class: "muted" }, body), extra, actions.length ? h("div", { class: "actions" }, actions) : null);
}
function clockLine(t0: number, limit: number | null) {
  return h("p", { class: "clock", "data-t0": t0, "data-limit": limit ?? "" }, clockText(t0, limit));
}
function clockText(t0: number, limit: number | null) {
  const el = Date.now() - t0;
  return limit ? `Waiting ${clock(el)} · gives up after ${clock(limit)}` : `${clock(el)} elapsed`;
}
function updateClock() {
  document.querySelectorAll<HTMLElement>(".clock").forEach((c) => { c.textContent = clockText(Number(c.dataset.t0), c.dataset.limit ? Number(c.dataset.limit) : null); });
}
function cancelBtn(cancelling?: boolean) {
  return h("button", { class: "big", disabled: !!cancelling, onclick: cancelSign }, cancelling ? "Cancelling…" : "Cancel");
}

async function checkAddr() {
  const r = formRefs; if (!r) return;
  const v = draft.to.trim();
  addrOk = false;
  if (!v) { r.toMsg.textContent = ""; r.toMsg.className = "field-msg"; updateFormExtras(); return; }
  const seq = ++addrSeq;
  try {
    const c = await api.checkAddress(v);
    if (seq !== addrSeq) return;
    addrOk = c.ok;
    toChecksum = c.checksum;
    if (!c.ok) { r.toMsg.textContent = v.length < 42 && /^0x[0-9a-fA-F]*$/.test(v) ? "" : c.error ?? "Not a valid address"; r.toMsg.className = "field-msg bad"; }
    else if (v.toLowerCase() === status?.paired?.toLowerCase()) { r.toMsg.textContent = "This is your own address."; r.toMsg.className = "field-msg warn"; }
    else if (v === v.toLowerCase() || v.slice(2) === v.slice(2).toUpperCase()) { r.toMsg.textContent = "Valid, but without a checksum: compare it carefully with the source."; r.toMsg.className = "field-msg warn"; }
    else { r.toMsg.replaceChildren(icon("check", 13), " Checksum OK"); r.toMsg.className = "field-msg ok"; }
  } catch { addrOk = false; }
  updateFormExtras();
}

function updateFormBalance() {
  const r = formRefs; if (!r) return;
  const tok = draftToken();
  if (tok) { const tb = tokenBalanceOf(flowNet.id, tok.address); r.avail.textContent = tb?.amount ? `Available ${fmtExact(tb.amount)} ${tok.symbol}` : ""; return; }
  const b = balances.get(flowNet.id);
  r.avail.textContent = b ? `Available ${fmtAmount(b.eth, 8)} ${flowNet.symbol}` : "";
}

function updateFormExtras() {
  const r = formRefs; if (!r || flow.s !== "form") return;
  const n = flowNet;
  const amt = draft.amount.trim();
  const tok = draftToken();
  const tv = tok ? validTokenAmount(amt, tok.decimals) : null;
  const amtValid = tv ? tv.ok : /^\d*\.?\d{0,18}$/.test(amt) && Number(amt) > 0;
  if (tv) r.amtFiat.textContent = tv.msg;
  else r.amtFiat.textContent = amtValid ? (fmtUsd(amt, price(n)) ? `≈ ${fmtUsd(amt, price(n))}` : "") : amt && !/^\d*\.?\d*$/.test(amt) ? "Use digits and one dot, like 0.05" : amt && /\.\d{19,}/.test(amt) ? "At most 18 decimals" : "";
  r.amtFiat.className = amt && !amtValid && (tv ? !!tv.msg : Number(amt) !== 0) ? "field-msg bad" : "field-msg";
  if (fee) {
    const tu = fmtUsd(fee.typical_fee_eth, price(n)); const mu = fmtUsd(fee.max_fee_eth, price(n));
    r.feeLine.replaceChildren(
      h("span", { class: "muted" }, "Network fee"),
      tok ? h("span", { class: "muted" }, "quoted on the next step") : h("span", null, `≈ ${fmtAmount(fee.typical_fee_eth, 8)} ${n.symbol}`, tu ? h("span", { class: "muted" }, ` · ${tu}`) : null),
      h("span", { class: "muted small full" }, tok ? `Paid in ${n.symbol}. A token transfer uses more gas than a plain transfer; the exact ceiling is quoted on the next step${n.l2 ? ", plus a small L1 data fee" : ""}.`
        : `At most ${fmtAmount(fee.max_fee_eth, 8)} ${n.symbol}${mu ? ` (${mu})` : ""} for a plain transfer${n.l2 ? ", plus a small L1 data fee" : ""}.`),
    );
  } else r.feeLine.replaceChildren(h("span", { class: "muted" }, "Network fee"), h("span", { class: "muted" }, "estimating…"));
  r.err.replaceChildren(formError ? h("p", { class: "inline-error" }, icon("alert", 15), formError) : "");
  r.go.disabled = !(addrOk && amtValid);
}

async function getQuote() {
  if (!addrOk) return;
  const n = flowNet;
  formError = null;
  setFlow({ s: "quoting" });
  try {
    const tok = draftToken();
    const quote = tok ? await api.tokenQuote(rpcFor(n.id), tok.address, draft.to.trim(), draft.amount.trim())
      : await api.quote(rpcFor(n.id), draft.to.trim(), draft.amount.trim());
    if (tok && (!quote.token || quote.token.contract.toLowerCase() !== tok.address.toLowerCase())) throw "the quote is not for the selected token";
    if (flow.s !== "quoting") return;
    if (parseInt(quote.chain_id, 16) !== n.id) throw `the node answered for chain ${parseInt(quote.chain_id, 16)}, not ${n.name}`;
    setFlow({ s: "review", quote });
  } catch (e) {
    formError = capitalize(errText(e));
    if (flow.s === "quoting") setFlow({ s: "form" });
  }
}
const capitalize = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

async function sendToPhone(quote: Quote) {
  const ticket = crypto.randomUUID();
  activeTicket = ticket;
  setFlow({ s: "connecting", quote, ticket, t0: Date.now() });
  // Last-resort UI watchdog: the Rust side already bounds each phase; this only guards the UI.
  const watchdog = window.setTimeout(() => {
    if (activeTicket === ticket && (flow.s === "connecting" || flow.s === "on_phone")) {
      api.signCancel().catch(() => {});
      setFlow({ s: "failed", quote, err: { kind: "timeout", message: "no result from the USB session", delivered: flow.s === "on_phone" } });
    }
  }, REVIEW_LIMIT_MS + 90_000);
  try {
    const signed = await api.signStart(ticket, quote);
    // A verified signature is always shown if this attempt is still the current one, even if
    // the UI had already given up waiting: losing it is how "signed but nothing shown" happens.
    if (activeTicket === ticket) setFlow({ s: "signed", quote, signed });
  } catch (e) {
    if (activeTicket !== ticket || flow.s === "signed") return;
    setFlow({ s: "failed", quote, err: asSendError(e) });
  } finally { clearTimeout(watchdog); }
}

function asSendError(e: unknown): SendError {
  if (e && typeof e === "object" && "kind" in e) return e as SendError;
  return { kind: "internal", message: errText(e), delivered: false };
}

async function cancelSign() {
  if (flow.s !== "connecting" && flow.s !== "on_phone") return;
  const ticket = flow.ticket;
  setFlow({ ...flow, cancelling: true });
  try { await api.signCancel(); } catch { /* the command result will say */ }
  // The Rust side answers within a few seconds; if it can't (e.g. mid USB switch), stop waiting.
  setTimeout(() => {
    if (activeTicket === ticket && (flow.s === "connecting" || flow.s === "on_phone")) setFlow({ s: "failed", quote: flow.quote, err: { kind: "cancelled", message: "cancelled on this Mac", delivered: flow.s === "on_phone" } });
  }, 8000);
}

onProgress((ticket, stage) => {
  if (ticket !== activeTicket) return;
  if (stage === "delivered" && flow.s === "connecting") setFlow({ s: "on_phone", quote: flow.quote, ticket, t0: Date.now(), cancelling: flow.cancelling });
  else if (stage === "verifying" && flow.s === "on_phone") setFlow({ s: "verifying", quote: flow.quote, ticket });
});

interface Explained { title: string; body: string; danger?: boolean; neutral?: boolean; hideDetail?: boolean }
function explain(err: SendError): Explained {
  const sent = err.delivered;
  switch (err.kind) {
    case "no_phone": return { title: "Phone not found", body: "No phone on USB. Plug the vault into this Mac and unlock it, then try again. Nothing was sent." };
    case "usb_busy": return { title: "USB is in use", body: "Another program holds the phone's USB connection, usually the Android adb server. Run `adb kill-server`, then try again. Nothing was sent." };
    case "connect": return { title: "Couldn't open the USB connection", body: "Unplug the cable and plug it back in, unlock the phone, and try again. Nothing was sent." };
    case "not_delivered": return { title: "The phone didn't take the request", body: "Nothing reached the phone. Wake and unlock it; if that doesn't help, unplug and reconnect the cable. Then try again." };
    case "timeout": return sent
      ? { title: "No answer from the phone", body: "The request reached the phone, but no answer came back within 5 minutes. If the phone still shows it, reject it there. Then try again." }
      : { title: "The phone didn't respond", body: "Nothing reached the phone. Wake and unlock it, reconnect the cable, and try again." };
    case "disconnected": return { title: "The USB connection dropped", body: sent ? "The link ended while waiting for the phone. Nothing was broadcast. If you approved on the phone, send it again: the phone signs the same transaction." : "The link ended before the request reached the phone. Reconnect and try again." };
    case "cancelled": return { title: "Cancelled", neutral: true, hideDetail: true, body: sent ? "Stopped waiting on this Mac. If the phone is still showing the request, tap Reject there." : "Stopped before anything reached the phone." };
    case "rejected": return { title: "Rejected on the phone", neutral: true, hideDetail: true, body: "You declined on the phone. No signature was created and nothing was broadcast." };
    case "phone_error": return { title: "The phone refused the request", body: explainPlain(err.message) };
    case "busy": return { title: "Still finishing the last request", body: "The previous request to the phone is still closing. Wait a few seconds and try again." };
    case "verify": return { title: "Signature failed verification", danger: true, body: "What came back does not match what you entered, or was not signed by your paired phone. It was thrown away and will not be broadcast. Stop and check the phone, the cable and this Mac before trying again." };
    case "protocol": return { title: "Unexpected reply from the phone", body: "The reply didn't follow the protocol, so it was discarded. Nothing was broadcast. Reconnect the cable and try again." };
    case "not_paired": return { title: "Not paired", body: "Pair this Mac with your phone first (Settings → Phone)." };
    default: return { title: "Something went wrong", body: "The request didn't complete. Nothing was broadcast. Try again." };
  }
}

function explainBroadcast(m: string): string {
  if (/insufficient funds/i.test(m)) return "The balance is too low for the amount plus fee. ";
  if (/nonce too low|already known/i.test(m)) return "It, or another transaction with the same nonce, is already on the network. Check Activity or the explorer. ";
  if (/underpriced|fee too low/i.test(m)) return "The fee is below what the network accepts right now. Discard and send again for a fresh quote. ";
  if (/unreachable|timed out|non-JSON/i.test(m)) return "The node couldn't be reached. Retry, or pick another node in Settings. ";
  return "";
}

async function doBroadcast(quote: Quote, signed: Signed) {
  setFlow({ s: "broadcasting", quote, signed });
  const n = flowNet;
  try {
    const hash = await api.broadcast(rpcFor(n.id), signed.hash);
    submitted(quote, hash);
  } catch (e) {
    const m = errText(e);
    if (/already known|known transaction/i.test(m)) { submitted(quote, signed.hash); return; }
    setFlow({ s: "broadcast_failed", quote, signed, message: m });
  }
}

async function submitted(quote: Quote, hash: string) {
  activeTicket = null;
  const t0 = Date.now();
  setFlow({ s: "submitted", quote, hash, t0, slow: false, trouble: false });
  refreshHistory();
  const n = flowNet;
  const every = n.l2 ? 2500 : 6000;
  for (let i = 0; ; i++) {
    await new Promise((r) => setTimeout(r, every));
    if (flow.s !== "submitted" || flow.hash !== hash) return; // the user moved on; pollPending finishes the job
    if (Date.now() - t0 > 30 * 60_000) return;
    try {
      const rc = await api.receipt(rpcFor(n.id), hash);
      if (flow.s !== "submitted" || flow.hash !== hash) return;
      if (rc.mined) {
        try { history = await api.historyMark(hash, rc.success ? "confirmed" : "failed", rc.block); } catch { /* best effort */ }
        setFlow({ s: "done", quote, hash, block: rc.block, ok: rc.success });
        refreshBalance(n);
        return;
      }
      const slow = Date.now() - t0 > 180_000;
      if (slow !== flow.slow || flow.trouble) setFlow({ ...flow, slow, trouble: false });
    } catch {
      if (flow.s === "submitted" && !flow.trouble && i > 1) setFlow({ ...flow, trouble: true });
    }
  }
}

// ------------------------------------------------------------------ optional tools (mount point)
//
// Message / EIP-712 signing lives in `signing.ts`, added separately. If that module exists it
// must export `mountSigning(container: HTMLElement)`; the build works without it.

type SigningModule = { mountSigning?: (el: HTMLElement) => unknown };
const signingLoader = import.meta.glob<SigningModule>("./signing.ts")["./signing.ts"] as (() => Promise<SigningModule>) | undefined;

function toolView() {
  const host = h("div", { class: "tool-host" }, h("div", { class: "boot" }, h("div", { class: "spinner" })));
  (async () => {
    try {
      const mod = signingLoader ? await signingLoader() : null;
      if (!mod?.mountSigning) throw "message signing is not included in this build";
      host.replaceChildren();
      mod.mountSigning(host);
    } catch (e) { host.replaceChildren(h("p", { class: "inline-error" }, icon("alert", 15), capitalize(errText(e)))); }
  })();
  return h("div", { class: "stack fade" }, topbar("Sign a message", () => go("home")), host);
}

// ------------------------------------------------------------------ settings drawer

function openDrawer() { drawerOpen = true; renderDrawer(); document.body.classList.add("drawer-open"); drawer.setAttribute("aria-hidden", "false"); (drawer.querySelector("button") as HTMLElement | null)?.focus(); }
function closeDrawer() { drawerOpen = false; document.body.classList.remove("drawer-open"); drawer.setAttribute("aria-hidden", "true"); }
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && drawerOpen) closeDrawer(); });

let version = "";
function renderDrawer() {
  const paired = status?.paired_checksum;
  const phone = status?.phone ?? "none";
  const n = net();
  const rpcInput = h("input", { type: "url", spellcheck: "false", value: rpcFor(n.id), placeholder: n.rpc });
  const rpcMsg = h("p", { class: "field-msg" });
  const saveRpc = () => {
    const v = rpcInput.value.trim();
    if (v && !v.startsWith("https://")) { rpcMsg.textContent = "Use an https:// URL."; rpcMsg.className = "field-msg bad"; return; }
    if (!v || v === n.rpc) delete prefs.rpc[n.id]; else prefs.rpc[n.id] = v;
    savePrefs(); balances.delete(n.id); refreshBalance(n);
    rpcMsg.textContent = "Saved."; rpcMsg.className = "field-msg ok";
  };
  const seg = (v: Theme, label: string) => h("button", { class: prefs.theme === v ? "on" : "", onclick: () => { prefs.theme = v; savePrefs(); applyTheme(); renderDrawer(); } }, label);
  drawer.replaceChildren(...[
    h("div", { class: "drawer-head" }, h("h2", null, "Settings"), h("button", { class: "icon-btn", onclick: closeDrawer, "aria-label": "Close settings" }, icon("close", 20))),
    h("section", { class: "set" },
      h("h4", null, "PHONE"),
      h("div", { class: "set-row" }, h("span", null, "USB"), h("span", { class: `chip ${phone}` }, h("i", { class: "dot" }), phone === "accessory" ? "Connected" : phone === "android" ? "On USB" : "Not connected")),
      h("div", { class: "set-row" }, h("span", null, "Paired address"), paired ? h("button", { class: "link mono", title: paired, onclick: () => copy(paired) }, short(paired), icon("copy", 14)) : h("span", { class: "muted" }, "Not paired")),
      h("div", { class: "row gap" },
        h("button", { onclick: () => { closeDrawer(); pair = { s: "idle" }; go("pair"); } }, paired ? "Pair again" : "Pair phone"),
        paired ? h("button", { class: "danger-ghost", onclick: async (ev: Event) => {
          const b = ev.currentTarget as HTMLButtonElement;
          if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again to forget"; return; }
          try { await api.forgetPairing(); closeDrawer(); await refreshStatus(); } catch (e) { b.textContent = errText(e); }
        } }, "Forget phone") : null,
      ),
      status?.pairing_path ? h("p", { class: "muted small" }, "Stored in ", h("span", { class: "mono" }, status.pairing_path)) : null,
    ),
    h("section", { class: "set" },
      h("h4", null, "NETWORK"),
      h("div", { class: "radio-list" }, NETWORKS.map((x) => h("button", { class: `radio${x.id === prefs.chainId ? " on" : ""}`, onclick: () => { prefs.chainId = x.id; savePrefs(); refreshBalance(x); renderDrawer(); if (view === "home" || view === "receive") render(); } },
        h("i", { class: `net-dot n${x.id}` }), h("span", { class: "grow" }, x.name), x.testnet ? h("span", { class: "tag" }, "testnet") : null, x.id === prefs.chainId ? icon("check", 16) : null))),
    ),
    h("section", { class: "set" },
      h("h4", null, `NODE FOR ${n.name.toUpperCase()}`),
      h("label", { class: "field" }, rpcInput, rpcMsg),
      h("div", { class: "row gap" },
        h("button", { onclick: saveRpc }, "Save"),
        h("button", { class: "ghost", onclick: () => { rpcInput.value = n.rpc; saveRpc(); } }, "Use default"),
      ),
      h("p", { class: "muted small" }, "The node supplies balance, nonce and fees, and relays what you broadcast. It can't change what the phone signs: every field is shown to you and on the phone first."),
    ),
    h("section", { class: "set" },
      h("h4", null, "NOTIFICATIONS"),
      h("label", { class: "toggle" }, h("span", null, "Tell me when funds arrive"),
        (() => { const t = h("input", { type: "checkbox", role: "switch", checked: prefs.notify }); t.addEventListener("change", () => { prefs.notify = t.checked; savePrefs(); if (t.checked) notify("Notifications are on."); }); return t; })(), h("i", { class: "knob" })),
      h("p", { class: "muted small" }, "Checks balances while this app is open."),
    ),
    h("section", { class: "set" },
      h("h4", null, "APPEARANCE"),
      h("div", { class: "segmented" }, seg("dark", "Dark"), seg("light", "Light"), seg("system", "System")),
    ),
    wcSettingsSection(),
    signingLoader ? h("section", { class: "set" },
      h("h4", null, "TOOLS"),
      h("button", { class: "radio", onclick: () => { closeDrawer(); go("tool"); } }, icon("pen", 16), h("span", { class: "grow" }, "Sign a message"), icon("back", 14)),
    ) : null,
    h("section", { class: "set about" },
      h("h4", null, "ABOUT"),
      h("div", { class: "set-row" }, h("span", null, "Phone Vault Companion"), h("span", { class: "mono muted" }, version || "…")),
      h("p", { class: "muted small" }, "This Mac never sees a key. It quotes, relays, verifies and broadcasts. The phone decides."),
      h("p", { class: "muted small" }, "Prices from Coinbase, for display only. No analytics, no accounts."),
    ),
  ].filter((x): x is HTMLElement => !!x));
}

// ------------------------------------------------------------------ boot

applyTheme();
if (!isTauri) document.body.append(h("span", { class: "preview-badge", title: "Running in a browser without Tauri: all data is fake" }, "PREVIEW DATA"));
renderHeader();
render();
appVersion().then((v) => { version = v; if (drawerOpen) renderDrawer(); }).catch(() => {});
mountWalletConnect({
  paired: () => status?.paired_checksum ?? null,
  rpcFor,
  phoneBlocked: () => identity.s === "different" ? "The phone on USB holds a different wallet. Pair it first (Settings → Phone)."
    : identifying ? "Checking which wallet the phone holds. Try again in a moment."
    : view === "send" && ["connecting", "on_phone", "verifying"].includes(flow.s) ? "The phone is busy with your Send. Finish it first." : null,
  changed: () => { if (view === "home") renderSoon(); if (drawerOpen && !drawer.contains(document.activeElement)) renderDrawer(); },
  sent: (chainId) => { refreshHistory(); refreshBalance(byId(chainId)); },
  openSettings: () => openDrawer(),
});
(async () => {
  await refreshStatus();
  render();
  refreshHistory().then(pollPending);
  refreshPrices();
  setInterval(refreshStatus, 3000);
  setInterval(() => { if (status?.paired) refreshBalance(net()); }, 15_000);
  setInterval(() => { if (status?.paired) refreshAllBalances(); }, 60_000);
  setInterval(refreshPrices, 60_000);
  setInterval(pollPending, 15_000);
  setInterval(() => { if (view === "home") renderSoon(); }, 60_000); // relative times
})();
