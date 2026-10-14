// Bitcoin: watch-only accounts whose keys stay on the phone (src-tauri/src/btc). This module owns
// the Bitcoin screens (home, receive + verify on phone, send stepper, pairing) and the Settings
// section; main.ts shows them when a Bitcoin network is selected. Every state of the send flow is
// entered only from a real command result or a `send-progress` event carrying this attempt's
// ticket, exactly like the EVM send.

import { call, onProgress, onEvent, openExternal, errText, REVIEW_LIMIT_MS } from "./api";
import type { SendError } from "./api";
import { h, icon, padlock, short, copy, ago, toast, usdFmt, capitalize, fact, statusCard } from "./ui";
import { stepper, clockLine, clockTicker, cancelButton } from "./send-flow";
import { qrSvg } from "./qr";
import { explainSendError, explainPlain, asSendError } from "./errors";
import "./bitcoin.css";

export type BtcNet = "bitcoin" | "testnet" | "signet";
export const BTC_NETS: { id: BtcNet; name: string; unit: string; test: boolean }[] = [
  { id: "bitcoin", name: "Bitcoin", unit: "BTC", test: false },
  { id: "testnet", name: "Bitcoin Testnet", unit: "tBTC", test: true },
  { id: "signet", name: "Bitcoin Signet", unit: "sBTC", test: true },
];
export const btcNet = (id: BtcNet) => BTC_NETS.find((n) => n.id === id) ?? BTC_NETS[0];

export interface BtcAccount { id: string; network: BtcNet; kind: "p2wpkh" | "p2tr"; kind_name: string; account: number; label: string; fingerprint: string; path: string; xpub: string; descriptor: string; active: boolean; unit: string; network_name: string }
interface Accounts { accounts: BtcAccount[]; servers: Record<string, string>; defaults: Record<string, string[]> }
interface Candidate { id: string; network: BtcNet; kind: string; account: number; fingerprint: string; path: string; xpub: string; descriptor: string; first_address: string; already_paired: boolean; label: string }
interface Shown { address: string; expected: string; matches: boolean }
export interface BtcHistory { txid: string; net_sats: number; fee_sats: number | null; status: "pending" | "confirmed" | "dropped"; confirmations: number; time: number; counterparty: string | null; explorer: string; can_bump: boolean; sent_here: boolean }
export interface BtcWallet { id: string; network: BtcNet; unit: string; confirmed_sats: number; unconfirmed_sats: number; receive_address: string; receive_index: number; receive_verified: boolean; history: BtcHistory[]; scanned_at: number; error: string | null; server: string; used_addresses: number }
interface AddrCheck { ok: boolean; error: string | null; own: boolean; kind: string | null }
interface Fees { fast: number; normal: number; slow: number; server: string }
export interface BtcQuote {
  quote_id: string; network: BtcNet; unit: string; recipient: string; amount_sats: number; fee_sats: number; vsize: number; rate: string; total_sats: number; change_sats: number;
  inputs: { outpoint: string; sats: number; address: string; confirmed: boolean }[]; outputs: { address: string; sats: number; change: boolean; path: string | null }[];
  replaces: string | null; own_recipient: boolean; unconfirmed_inputs: boolean; balance_sats: number; sequence: string;
}
interface Signed { txid: string; fee_sats: number; vsize: number; rate: string; amount_sats: number; recipient: string; explorer: string; checks: string[] }
interface TxState { confirmed: boolean; confirmations: number; height: number | null }
interface Export { descriptor: string; receive: string; change: string; fingerprint: string; path: string; xpub: string; text: string }

const btcApi = {
  accounts: () => call<Accounts>("btc_accounts"),
  readAccount: (network: BtcNet, kind: string, account: number) => call<Candidate>("btc_read_account", { network, kind, account }),
  showAddress: (id: string, change: number, index: number) => call<Shown>("btc_show_address", { id, change, index }),
  confirmAccount: (id: string, label: string | null) => call<BtcAccount>("btc_confirm_account", { id, label }),
  select: (id: string) => call<void>("btc_select", { id }),
  rename: (id: string, label: string) => call<void>("btc_rename", { id, label }),
  forget: (id: string) => call<void>("btc_forget", { id }),
  setServer: (network: BtcNet, url: string | null) => call<void>("btc_set_server", { network, url }),
  wallet: (id: string) => call<BtcWallet>("btc_wallet", { id }),
  refresh: (id: string, full: boolean) => call<BtcWallet>("btc_refresh", { id, full }),
  checkAddress: (id: string, address: string) => call<AddrCheck>("btc_check_address", { id, address }),
  fees: (id: string) => call<Fees>("btc_fees", { id }),
  quote: (id: string, to: string, amount: string | null, max: boolean, feeRate: string) => call<BtcQuote>("btc_quote", { id, to, amount, max, feeRate }),
  bumpQuote: (id: string, txid: string, feeRate: string) => call<BtcQuote>("btc_bump_quote", { id, txid, feeRate }),
  signStart: (ticket: string, quoteId: string) => call<Signed>("btc_sign_start", { ticket, quoteId }),
  signCancel: (ticket?: string) => call<void>("btc_sign_cancel", { ticket: ticket ?? null }),
  broadcast: (txid: string) => call<string>("btc_broadcast", { txid }),
  txStatus: (id: string, txid: string) => call<TxState>("btc_tx_status", { id, txid }),
  export: (id: string) => call<Export>("btc_export", { id }),
  saveExport: (id: string) => call<string>("btc_save_export", { id }),
};

export interface BtcHost {
  net(): BtcNet;
  showTestnets(): boolean;
  setShowTestnets(on: boolean): void;
  price(): number | null;
  /** redraw soon (background data; waits while the user is typing) */
  rerender(): void;
  /** redraw now (the user's own action or a flow step) */
  renderNow(): void;
  topbar(title: string, back: (() => void) | null): HTMLElement;
  networkSelect(): HTMLElement;
  /** why the phone can't take a request right now (device check failed, …), or null */
  phoneBlocked(): string | null;
  /** a request from another screen (EVM send, dApp) is on the phone */
  phoneBusy(): boolean;
}

// ------------------------------------------------------------------ formatting

/** Exact BTC from sats (string math, never floats for what is signed). */
export function fmtBtc(sats: number, trim = true): string {
  const neg = sats < 0; const s = Math.abs(Math.trunc(sats));
  const whole = Math.floor(s / 1e8); const frac = String(s % 1e8).padStart(8, "0");
  const f = trim ? frac.replace(/0+$/, "") : frac;
  return `${neg ? "−" : ""}${whole.toLocaleString("en-US")}${f ? "." + f : ""}`;
}
const fmtSats = (n: number) => `${Math.abs(n).toLocaleString("en-US")} sat`;
function usd(sats: number, price: number | null, test: boolean): string | null {
  if (price === null || test) return null;
  const v = (Math.abs(sats) / 1e8) * price;
  if (v > 0 && v < 0.01) return "< $0.01";
  return usdFmt.format(v);
}
/** bc1q xxxx xxxx … in groups of four, for comparing by eye. */
const groupedBtc = (a: string) => a.match(/.{1,4}/g)?.join(" ") ?? a;
/** "0.0005" BTC → sats, exactly; null when not a valid amount. */
function btcToSats(s: string): number | null {
  const m = /^(\d{0,8})(?:\.(\d{0,8}))?$/.exec(s.trim());
  if (!m || (!m[1] && !m[2])) return null;
  return Number(m[1] || "0") * 1e8 + Number((m[2] ?? "").padEnd(8, "0"));
}
const satsToBtcStr = (n: number) => `${Math.floor(n / 1e8)}.${String(n % 1e8).padStart(8, "0")}`.replace(/\.?0+$/, "") || "0";

// ------------------------------------------------------------------ state

let host: BtcHost;
let accounts: BtcAccount[] = [];
let servers: Record<string, string> = {};
let defaults: Record<string, string[]> = {};
let loaded = false;
const wallets = new Map<string, BtcWallet>();
const refreshing = new Set<string>();
type Sub = "home" | "receive" | "send" | "pair";
let sub: Sub = "home";

export const btcAccounts = () => accounts;
const accountsOn = (n: BtcNet) => accounts.filter((a) => a.network === n);
export const activeBtc = (n: BtcNet): BtcAccount | null => accountsOn(n).find((a) => a.active) ?? accountsOn(n)[0] ?? null;
export const btcWallet = (id: string) => wallets.get(id) ?? null;

export async function btcInit(h0: BtcHost) {
  host = h0;
  await reloadAccounts();
  void onEvent<{ id: string }>("btc-changed", (p) => { void loadWallet(p.id); });
  onProgress((ticket, stage) => {
    if (ticket !== activeTicket) return;
    if (stage === "waiting" && flow.s === "connecting") setFlow({ ...flow, waiting: true });
    else if (stage === "connecting" && flow.s === "connecting" && flow.waiting) setFlow({ ...flow, waiting: false, t0: Date.now() });
    else if (stage === "delivered" && flow.s === "connecting") setFlow({ s: "on_phone", q: flow.q, ticket, t0: Date.now(), cancelling: flow.cancelling });
    else if (stage === "verifying" && flow.s === "on_phone") setFlow({ s: "verifying", q: flow.q, ticket });
  });
}

export async function reloadAccounts() {
  try { const r = await btcApi.accounts(); accounts = r.accounts; servers = r.servers; defaults = r.defaults; loaded = true; }
  catch { /* keep the last list */ }
  for (const a of accounts) if (!wallets.has(a.id)) void loadWallet(a.id);
}

async function loadWallet(id: string) {
  try { wallets.set(id, await btcApi.wallet(id)); } catch { /* not paired any more */ }
  if (sub !== "send" || flow.s !== "form") host?.rerender();
}

/** Ask the server now (light scan; Rust does a full gap-limit scan at most every 30 min, or when `full`). */
export async function refreshBtc(id: string, full = false) {
  if (refreshing.has(id)) return;
  refreshing.add(id); host.rerender();
  try { wallets.set(id, await btcApi.refresh(id, full)); } catch (e) { const w = wallets.get(id); if (w) wallets.set(id, { ...w, error: errText(e) }); }
  finally { refreshing.delete(id); host.rerender(); }
}

/** Back to the Bitcoin home screen (the header's brand button). */
export function btcGoHome() { if (!busy()) { sub = "home"; } }
export const btcBusy = () => busy();
function go(s: Sub) { sub = s; window.scrollTo(0, 0); host.renderNow(); }

/** Total of the shown mainnet account (for the Balances list and the USD total). */
export function btcBalanceSats(n: BtcNet): number | null {
  const a = activeBtc(n); const w = a ? wallets.get(a.id) : null;
  return w ? w.confirmed_sats + w.unconfirmed_sats : null;
}

// ------------------------------------------------------------------ main entry

export function btcMain(): HTMLElement {
  const n = host.net();
  const a = activeBtc(n);
  if (sub === "pair") return pairView();
  if (!a) return emptyView();
  if (sub === "receive") return receiveView(a);
  if (sub === "send") return sendView(a);
  return homeView(a);
}

function emptyView() {
  const n = btcNet(host.net());
  return h("div", { class: "stack fade" },
    h("section", { class: "card account" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, "Bitcoin"), host.networkSelect()),
      h("div", { class: "pair-hero" }, padlock(5)),
      h("h3", null, n.test ? `Add a ${n.name} account` : "Add a Bitcoin account"),
      h("p", { class: "muted" }, "Your phone derives Bitcoin keys from the same 24 words and keeps them. This Mac stores only the account's public key (xpub), to show addresses, balance and history and to prepare transactions for the phone to sign."),
      h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => { pair = { s: "choose" }; go("pair"); } }, icon("phone", 18), "Add from phone")),
    ),
    !loaded ? h("p", { class: "muted small center" }, "Loading…") : null,
  );
}

// ------------------------------------------------------------------ home

function accountChip(a: BtcAccount) {
  const list = accountsOn(a.network);
  if (list.length < 2) return h("p", { class: "kicker" }, a.label);
  const sel = h("select", { class: "net-select", "aria-label": "Bitcoin account" }, list.map((x) => h("option", { value: x.id, selected: x.id === a.id }, `${x.label} · ${x.kind_name}`)));
  sel.addEventListener("change", async () => { try { await btcApi.select(sel.value); await reloadAccounts(); host.renderNow(); } catch (e) { toast(errText(e)); } });
  return h("label", { class: "net-chip acct-chip", title: "Bitcoin accounts paired with this Mac" }, h("span", { class: "kicker" }, a.label), icon("chevron", 14), sel);
}

function homeView(a: BtcAccount) {
  const n = btcNet(a.network);
  const w = wallets.get(a.id);
  if (!w && !refreshing.has(a.id)) void loadWallet(a.id);
  if (w && w.scanned_at === 0 && !refreshing.has(a.id) && !w.error) void refreshBtc(a.id);
  const total = w ? w.confirmed_sats + w.unconfirmed_sats : null;
  const fiat = total !== null ? usd(total, host.price(), n.test) : null;
  return h("div", { class: "stack fade" },
    h("section", { class: "card account" },
      h("div", { class: "row between" }, accountChip(a), host.networkSelect()),
      w ? h("button", { class: "addr-btn", title: `${w.receive_address}\nNext receive address. Click to copy`, onclick: () => copy(w.receive_address) }, h("span", { class: "mono" }, short(w.receive_address)), icon("copy", 15)) : null,
      h("div", { class: "balance" },
        total !== null ? h("span", { class: "amount" }, fmtBtc(total), h("span", { class: "unit" }, n.unit)) : h("span", { class: "amount skeleton" }, "0.0000"),
        fiat ? h("span", { class: "fiat" }, fiat) : null,
      ),
      w && w.unconfirmed_sats !== 0 ? h("p", { class: "muted small" }, `${w.unconfirmed_sats > 0 ? "+" : ""}${fmtBtc(w.unconfirmed_sats)} ${n.unit} unconfirmed · ${fmtBtc(w.confirmed_sats)} confirmed`) : null,
      w?.error ? h("p", { class: "inline-error" }, icon("alert", 15), `Server: ${w.error}`) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => startSend(a) }, icon("up", 20), "Send"),
        h("button", { class: "big", onclick: () => { recv = { s: "idle" }; go("receive"); } }, icon("down", 20), "Receive"),
      ),
    ),
    historySection(a, w ?? null),
  );
}

function historySection(a: BtcAccount, w: BtcWallet | null) {
  const n = btcNet(a.network);
  const spinning = refreshing.has(a.id);
  const head = h("div", { class: "total-line" },
    h("h3", { class: "section-title" }, "Activity"),
    h("button", { class: "chip-btn", disabled: spinning, onclick: () => refreshBtc(a.id, true), title: `Ask ${w?.server || "the server"} again (full address scan)` },
      spinning ? h("i", { class: "mini-spin" }) : icon("refresh", 13), w?.scanned_at ? `Updated ${ago(w.scanned_at)}` : "Refresh"));
  if (!w) return h("section", { class: "section" }, head, h("p", { class: "muted small" }, "Loading…"));
  const rows = w.history.slice(0, 60).map((e) => {
    const out = e.net_sats < 0;
    const self = out && e.counterparty === null;
    const title = `${out ? "Sent" : "Received"} ${fmtBtc(Math.abs(out && e.fee_sats ? e.net_sats + e.fee_sats : e.net_sats))} ${n.unit}`;
    const badge = e.status === "pending" ? h("span", { class: "badge pending" }, h("i", { class: "mini-spin" }), "Pending")
      : e.status === "dropped" ? h("span", { class: "badge dropped", title: "Replaced (RBF) or dropped from the mempool" }, "Replaced")
      : h("span", { class: "badge ok", title: `${e.confirmations} confirmation${e.confirmations === 1 ? "" : "s"}` }, e.confirmations >= 6 ? "Confirmed" : `${e.confirmations} conf.`);
    const subline = [e.counterparty ? `${out ? "to" : "from"} ${short(e.counterparty)}` : self ? "to yourself" : null, out && e.fee_sats ? `fee ${fmtSats(e.fee_sats)}` : null, ago(e.time)].filter(Boolean).join(" · ");
    const main = h("button", { class: "act-row", onclick: () => openExternal(e.explorer), title: `${e.txid}\nOpen on mempool.space` },
      h("span", { class: `act-ic ${out ? "out" : "in"}` }, icon(out ? "up" : "down", 16)),
      h("span", { class: "grow" }, h("span", { class: "act-title" }, title), h("span", { class: "act-sub" }, subline)),
      badge, h("span", { class: "muted ext" }, icon("external", 15)));
    if (!e.can_bump) return h("li", null, main);
    return h("li", { class: "act-stuck" }, main, h("div", { class: "act-actions" },
      h("span", { class: "muted small grow" }, "Waiting for a block. Pay a higher fee to speed it up (RBF); your phone reviews the replacement."),
      h("button", { class: "chip-btn", onclick: () => startBump(a, e) }, icon("up", 13), "Speed up")));
  });
  return h("section", { class: "section" }, head,
    rows.length ? h("ul", { class: "list activity" }, rows) : h("p", { class: "empty" }, w.scanned_at ? "No transactions yet. Payments to this account's addresses show up here." : "Looking up this account's addresses…"),
    h("p", { class: "muted small" }, `From ${w.server} (${w.used_addresses} used address${w.used_addresses === 1 ? "" : "es"}, gap limit 20). The server learns which addresses are yours; Settings → Bitcoin to use your own.`),
  );
}

// ------------------------------------------------------------------ receive + verify on phone

type Recv = { s: "idle" } | { s: "asking"; index: number } | { s: "match"; index: number } | { s: "mismatch"; index: number; shown: string } | { s: "error"; message: string };
let recv: Recv = { s: "idle" };

async function verifyOnPhone(a: BtcAccount, index: number) {
  const blocked = host.phoneBlocked();
  if (blocked) { recv = { s: "error", message: blocked }; host.renderNow(); return; }
  recv = { s: "asking", index }; host.renderNow();
  try {
    const r = await btcApi.showAddress(a.id, 0, index);
    recv = r.matches ? { s: "match", index } : { s: "mismatch", index, shown: r.address };
    if (r.matches) await loadWallet(a.id);
  } catch (e) { recv = { s: "error", message: explainPlain(errText(e), "btc") }; }
  host.renderNow();
}

function receiveView(a: BtcAccount) {
  const n = btcNet(a.network);
  const w = wallets.get(a.id);
  if (!w) return h("div", { class: "stack fade" }, host.topbar("Receive", () => go("home")), h("div", { class: "boot" }, h("div", { class: "spinner" })));
  const addr = w.receive_address;
  const idx = w.receive_index;
  const verified = w.receive_verified || (recv.s === "match" && recv.index === idx);
  const qr = h("div", { class: "qr", html: qrSvg(`bitcoin:${addr.toUpperCase()}`, { dark: "#060608", light: "#ffffff", label: `QR code for ${addr}` }) });
  const verifyBox =
    recv.s === "asking" && recv.index === idx ? h("div", { class: "callout" }, h("strong", null, "Look at your phone"), h("span", null, "It shows this address. Compare every group of four characters with the one above."))
    : recv.s === "mismatch" && recv.index === idx ? h("div", { class: "callout danger-card" }, h("strong", null, "The phone shows a different address. Don't use this one."),
        h("span", { class: "mono" }, groupedBtc(recv.shown)), h("span", null, "Something between this Mac and the phone changed data, or the account doesn't match. Use the address on the phone's screen only after you understand why."))
    : verified ? h("div", { class: "callout accent" }, h("strong", { class: "ok-line" }, icon("check", 15), "Your phone showed this same address"), h("span", null, `Derived on the phone from your key: m/${a.path.slice(2)}/0/${idx}. Safe to share.`))
    : recv.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), recv.message) : null;
  return h("div", { class: "stack fade" },
    host.topbar("Receive bitcoin", () => go("home")),
    h("section", { class: "card receive" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, `${a.label} · ${a.kind_name}`), host.networkSelect()),
      h("div", { class: "qr-tile" }, qr),
      h("button", { class: "addr-full", onclick: () => copy(addr), title: "Click to copy" }, h("span", { class: "mono" }, groupedBtc(addr)), icon("copy", 16)),
      h("p", { class: "muted small center" }, `Address #${idx + 1} on the receive chain · a new one after each payment`),
      h("div", { class: "row center gap" },
        h("button", { class: verified ? "" : "primary", disabled: recv.s === "asking", onclick: () => verifyOnPhone(a, idx) }, recv.s === "asking" ? h("i", { class: "mini-spin" }) : icon("phone", 16), verified ? "Show on phone again" : "Verify on phone"),
        h("button", { class: verified ? "primary" : "", onclick: () => copy(addr) }, icon("copy", 16), "Copy address"),
      ),
      verifyBox,
    ),
    verified ? null : h("div", { class: "callout accent" },
      h("strong", null, "Verify it on your phone before the first payment"),
      h("span", null, "This Mac computed the address from your account's public key. Malware on a computer can swap an address on screen; your phone can't be fooled that way. Tap Verify on phone and compare."),
    ),
    h("div", { class: "callout" },
      h("strong", null, n.test ? `Only ${n.name} coins.` : "Only bitcoin (BTC) on the Bitcoin network."),
      h("span", null, n.test ? "Test coins have no value." : "Not BTC on Ethereum, Base or another chain, and not Lightning: those are different networks and the coins would not arrive here."),
    ),
  );
}

// ------------------------------------------------------------------ pairing

type Pair = { s: "choose"; error?: string } | { s: "reading" } | { s: "compare"; c: Candidate; shown?: Shown; asking?: boolean; error?: string } | { s: "mismatch"; c: Candidate; shown: string };
let pair: Pair = { s: "choose" };
const pairDraft = { kind: "p2wpkh", account: 1 };

function pairView() {
  const n = btcNet(host.net());
  const back = () => { pair = { s: "choose" }; go("home"); };
  let body: Node;
  if (pair.s === "compare") {
    const p = pair;
    const c = p.c;
    const label = h("input", { type: "text", maxlength: "40", spellcheck: "false", value: c.label, "aria-label": "Name on this Mac" }) as HTMLInputElement;
    const ask = async () => {
      const blocked = host.phoneBlocked(); if (blocked) { pair = { ...p, error: blocked }; host.renderNow(); return; }
      pair = { ...p, asking: true, error: undefined }; host.renderNow();
      try {
        const r = await btcApi.showAddress(c.id, 0, 0);
        pair = r.matches ? { s: "compare", c, shown: r } : { s: "mismatch", c, shown: r.address };
      } catch (e) { pair = { s: "compare", c, error: explainPlain(errText(e), "btc") }; }
      host.renderNow();
    };
    body = h("section", { class: "card" },
      h("p", { class: "kicker" }, "Step 2 of 2 · Compare on the phone"),
      h("h3", null, `${c.kind === "p2tr" ? "Taproot" : "Native SegWit"} account ${c.account}`),
      h("dl", { class: "facts" },
        fact("Fingerprint", h("span", { class: "mono" }, c.fingerprint)),
        fact("Path", h("span", { class: "mono" }, c.path)),
        fact("xpub", h("span", { class: "mono", title: c.xpub }, `${c.xpub.slice(0, 12)}…${c.xpub.slice(-8)}`)),
      ),
      h("p", { class: "muted" }, "Its first receive address, computed on this Mac:"),
      h("p", { class: "addr-compare mono" }, groupedBtc(c.first_address)),
      p.shown?.matches ? h("div", { class: "callout accent" }, h("strong", null, "The phone shows the same address"), h("span", null, "Compare every group once more on the phone's screen, then pair."))
        : h("p", { class: "muted small" }, "Show it on the phone and compare every group of four characters. Pairing is only possible after the phone has shown it."),
      p.error ? h("p", { class: "inline-error" }, icon("alert", 15), p.error) : null,
      h("label", { class: "field" }, h("span", { class: "muted small" }, "Name on this Mac"), label),
      h("div", { class: "actions" },
        p.shown?.matches
          ? h("button", { class: "big primary", onclick: async () => {
              try { await btcApi.confirmAccount(c.id, label.value.trim() || null); await reloadAccounts(); pair = { s: "choose" }; recv = { s: "match", index: 0 }; go("home"); void refreshBtc(c.id, true); }
              catch (e) { pair = { ...p, error: errText(e) }; host.renderNow(); }
            } }, icon("check", 18), "It matches · pair")
          : h("button", { class: "big primary", disabled: !!p.asking, onclick: ask }, p.asking ? h("i", { class: "mini-spin" }) : icon("phone", 18), p.asking ? "Look at your phone…" : "Show on phone"),
        h("button", { class: "big", onclick: () => { pair = { s: "mismatch", c, shown: p.shown?.address ?? "" }; host.renderNow(); } }, "It doesn't match"),
      ),
    );
  } else if (pair.s === "mismatch") {
    body = h("section", { class: "card danger-card" },
      h("p", { class: "kicker danger" }, "Not paired"),
      h("h3", null, "Stop here"),
      h("p", null, "The phone and this Mac disagree about the account's first address, so this Mac would show addresses your phone doesn't control. Nothing was saved. Use another cable and port, and don't receive to this account until they match."),
      pair.shown ? h("p", { class: "mono small" }, `Phone: ${groupedBtc(pair.shown)}`) : null,
      h("div", { class: "actions" }, h("button", { onclick: () => { pair = { s: "choose" }; host.renderNow(); } }, "Start over")),
    );
  } else {
    const reading = pair.s === "reading";
    const kindSeg = (k: string, label: string, note: string) => h("button", { class: pairDraft.kind === k ? "on" : "", title: note, onclick: () => { pairDraft.kind = k; host.renderNow(); } }, label);
    const acct = h("select", { class: "net-select", "aria-label": "Account number" }, Array.from({ length: 20 }, (_, i) => h("option", { value: i + 1, selected: pairDraft.account === i + 1 }, `Account ${i + 1}`)));
    acct.addEventListener("change", () => { pairDraft.account = Number(acct.value); });
    const read = async () => {
      const blocked = host.phoneBlocked(); if (blocked) { pair = { s: "choose", error: blocked }; host.renderNow(); return; }
      if (host.phoneBusy()) { pair = { s: "choose", error: "The phone is answering another request. Finish it first." }; host.renderNow(); return; }
      pair = { s: "reading" }; host.renderNow();
      try { const c = await btcApi.readAccount(host.net(), pairDraft.kind, pairDraft.account); pair = { s: "compare", c }; }
      catch (e) { pair = { s: "choose", error: explainPlain(errText(e), "btc") }; }
      host.renderNow();
    };
    body = h("section", { class: "card pair" },
      h("p", { class: "kicker" }, `Step 1 of 2 · ${n.name}`),
      h("h3", null, "Add a Bitcoin account from your phone"),
      h("p", { class: "muted" }, "The phone shares the account's public key (xpub) once you approve it there. This Mac can then show balances and prepare transactions; only the phone can sign."),
      h("div", { class: "field" }, h("span", { class: "field-label" }, "Address type"),
        h("div", { class: "segmented two" }, kindSeg("p2wpkh", "Native SegWit (bc1q)", "BIP-84. Supported everywhere. Recommended."), kindSeg("p2tr", "Taproot (bc1p)", "BIP-86. Slightly cheaper to spend; a few services can't send to it yet."))),
      h("p", { class: "muted small" }, pairDraft.kind === "p2tr" ? "Taproot (BIP-86): a little cheaper to spend. A few older exchanges can't send to bc1p addresses yet." : "Native SegWit (BIP-84): works with every wallet and exchange. The default."),
      h("label", { class: "field" }, h("span", { class: "field-label" }, "Account"), h("span", { class: "net-chip asset-chip" }, h("span", null, `Account ${pairDraft.account}`), icon("chevron", 14), acct)),
      pair.s === "choose" && pair.error ? h("p", { class: "inline-error" }, icon("alert", 15), pair.error) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", disabled: reading, onclick: read }, reading ? h("i", { class: "mini-spin" }) : icon("phone", 18), reading ? "Approve on your phone…" : "Read from phone"),
      ),
      reading ? h("p", { class: "muted small center" }, "Unlock the phone; it asks you to approve sharing this account's public key.") : null,
    );
  }
  return h("div", { class: "stack fade" }, host.topbar("Add Bitcoin account", back), body);
}

// ------------------------------------------------------------------ send

type Flow =
  | { s: "form" } | { s: "quoting" } | { s: "review"; q: BtcQuote }
  | { s: "connecting"; q: BtcQuote; ticket: string; t0: number; waiting?: boolean; cancelling?: boolean }
  | { s: "on_phone"; q: BtcQuote; ticket: string; t0: number; cancelling?: boolean }
  | { s: "verifying"; q: BtcQuote; ticket: string }
  | { s: "failed"; q: BtcQuote; err: SendError }
  | { s: "signed"; q: BtcQuote; signed: Signed }
  | { s: "broadcasting"; q: BtcQuote; signed: Signed }
  | { s: "broadcast_failed"; q: BtcQuote; signed: Signed; message: string }
  | { s: "submitted"; q: BtcQuote; signed: Signed; t0: number; confs: number }
  | { s: "bumping"; txid: string } | { s: "bump_failed"; txid: string; message: string };
let flow: Flow = { s: "form" };
let activeTicket: string | null = null;

type Unit = "BTC" | "sats" | "USD";
const draft = { to: "", amount: "", unit: "BTC" as Unit, max: false, fee: "normal" as "slow" | "normal" | "fast" | "custom", custom: "", bumpOf: null as string | null };
let fees: Fees | null = null;
let formError: string | null = null;
let addr: AddrCheck | null = null;
let addrSeq = 0;
const tickFor = clockTicker();
const CONFIRMATION_POLL_MS = 15_000;

const busy = () => sub === "send" && !["form", "quoting", "review", "failed", "signed", "broadcast_failed", "bump_failed"].includes(flow.s);

function setFlow(f: Flow) {
  flow = f;
  tickFor(f.s);
  if (sub === "send") host.renderNow();
}

function startSend(a: BtcAccount) {
  const blocked = host.phoneBlocked();
  if (blocked) { toast(blocked); return; }
  flow = { s: "form" }; formError = null; activeTicket = null; addr = null; draft.bumpOf = null;
  go("send");
  void loadFees(a);
}

async function loadFees(a: BtcAccount) {
  try { fees = await btcApi.fees(a.id); } catch (e) { fees = null; formError = `Fee estimates unavailable (${errText(e)}). Enter a custom fee rate.`; draft.fee = "custom"; }
  if (sub === "send" && flow.s === "form") host.renderNow();
}

function rateOf(): string | null {
  if (draft.fee === "custom") return /^\d+(\.\d{1,3})?$/.test(draft.custom.trim()) ? draft.custom.trim() : null;
  return fees ? String(fees[draft.fee]) : null;
}

/** The amount field in BTC (exact), or null. */
function amountBtc(): string | null {
  const v = draft.amount.trim();
  if (draft.unit === "BTC") { const s = btcToSats(v); return s && s > 0 ? satsToBtcStr(s) : null; }
  if (draft.unit === "sats") return /^\d{1,16}$/.test(v) && Number(v) > 0 ? satsToBtcStr(Number(v)) : null;
  const p = host.price(); const usdV = Number(v);
  if (!p || !/^\d+(\.\d{0,2})?$/.test(v) || !(usdV > 0)) return null;
  return satsToBtcStr(Math.round((usdV / p) * 1e8));
}

function stepOf(f: Flow): number {
  switch (f.s) {
    case "form": case "quoting": case "review": case "bumping": case "bump_failed": return 0;
    case "connecting": case "on_phone": case "verifying": case "failed": return 1;
    case "signed": case "broadcasting": case "broadcast_failed": return 2;
    default: return 3;
  }
}

function sendView(a: BtcAccount) {
  const n = btcNet(a.network);
  const back = busy() ? null : () => { if (flow.s === "review" && !draft.bumpOf) setFlow({ s: "form" }); else { flow = { s: "form" }; go("home"); } };
  return h("div", { class: "stack fade" },
    host.topbar(draft.bumpOf ? "Speed up" : `Send ${n.unit === "BTC" ? "bitcoin" : n.unit}`, back),
    stepper(stepOf(flow), flow.s === "submitted" && flow.confs > 0, flow.s === "failed" || flow.s === "broadcast_failed"),
    h("div", { class: "flow-body", "aria-live": "polite" }, flowBody(a)),
  );
}

function flowBody(a: BtcAccount): Node {
  const n = btcNet(a.network);
  const $ = (sats: number) => usd(sats, host.price(), n.test);
  const w = wallets.get(a.id);
  switch (flow.s) {
    case "form": case "quoting": {
      const quoting = flow.s === "quoting";
      const toInput = h("input", { id: "btc-to", type: "text", placeholder: n.test ? "tb1…" : "bc1…", spellcheck: "false", autocomplete: "off", value: draft.to, disabled: quoting }) as HTMLInputElement;
      const amtInput = h("input", { id: "btc-amount", type: "text", inputmode: "decimal", placeholder: draft.unit === "sats" ? "50000" : draft.unit === "USD" ? "25.00" : "0.0005", autocomplete: "off", value: draft.max ? "" : draft.amount, disabled: quoting || draft.max }) as HTMLInputElement;
      const toMsg = h("p", { class: "field-msg" });
      const amtMsg = h("p", { class: "field-msg" });
      const goBtn = h("button", { class: "big primary wide", type: "submit", disabled: true }, quoting ? [h("i", { class: "mini-spin" }), "Building the transaction…"] : "Review");
      const sync = () => {
        const btc = amountBtc();
        if (draft.max) amtMsg.textContent = "Everything this account holds, minus the fee. No change output.";
        else if (btc) { const s = btcToSats(btc)!; amtMsg.textContent = [draft.unit !== "BTC" ? `${btc} ${n.unit}` : null, draft.unit !== "sats" ? fmtSats(s) : null, draft.unit !== "USD" ? $(s) : null].filter(Boolean).join(" · "); }
        else amtMsg.textContent = draft.amount ? (draft.unit === "USD" && !host.price() ? "No USD price right now" : "Not a valid amount") : "";
        amtMsg.className = `field-msg${draft.amount && !btc && !draft.max ? " bad" : ""}`;
        goBtn.disabled = quoting || !(addr?.ok && (draft.max || btc) && rateOf());
      };
      const check = async () => {
        const v = draft.to.trim(); addr = null;
        if (!v) { toMsg.textContent = ""; sync(); return; }
        const seq = ++addrSeq;
        try {
          const r = await btcApi.checkAddress(a.id, v);
          if (seq !== addrSeq) return;
          addr = r;
          if (!r.ok) { toMsg.textContent = v.length < 14 ? "" : r.error ?? "Not a valid address"; toMsg.className = "field-msg bad"; }
          else if (r.own) { toMsg.textContent = "This is one of your own addresses (this account). The coins would stay with you, minus the fee."; toMsg.className = "field-msg warn"; }
          else { toMsg.replaceChildren(icon("check", 13), ` Valid ${n.name} address${r.kind ? ` · ${r.kind}` : ""} · checksum OK`); toMsg.className = "field-msg ok"; }
        } catch { addr = null; }
        sync();
      };
      toInput.addEventListener("input", () => { draft.to = toInput.value; void check(); });
      amtInput.addEventListener("input", () => { draft.amount = amtInput.value.replace(",", "."); sync(); });
      const unitSeg = h("div", { class: "segmented unit-seg" }, (["BTC", "sats", "USD"] as Unit[]).map((u) => h("button", { type: "button", class: draft.unit === u ? "on" : "", disabled: n.test && u === "USD",
        onclick: () => { const btc = amountBtc(); draft.unit = u; if (btc) { const s = btcToSats(btc)!; draft.amount = u === "BTC" ? btc : u === "sats" ? String(s) : host.price() ? ((s / 1e8) * host.price()!).toFixed(2) : ""; } host.renderNow(); } }, u === "BTC" ? n.unit : u)));
      const maxBtn = h("button", { class: `chip-btn${draft.max ? " on" : ""}`, type: "button", disabled: quoting, onclick: () => { draft.max = !draft.max; host.renderNow(); } }, "Max");
      const feeBtn = (k: "slow" | "normal" | "fast", label: string, eta: string) => {
        const r = fees ? fees[k] : null;
        const vb = a.kind === "p2tr" ? 154 : 141;
        return h("button", { type: "button", class: `fee-opt${draft.fee === k ? " on" : ""}`, disabled: !fees, onclick: () => { draft.fee = k; host.renderNow(); } },
          h("strong", null, label), h("span", { class: "muted small" }, eta), h("span", { class: "mono small" }, r ? `${r} sat/vB` : "…"), h("span", { class: "muted small" }, r ? `≈ ${fmtSats(Math.ceil(r * vb))}${$(Math.ceil(r * vb)) ? ` · ${$(Math.ceil(r * vb))}` : ""}` : ""));
      };
      const custom = h("input", { type: "text", inputmode: "decimal", placeholder: "sat/vB", value: draft.custom, class: "fee-custom", "aria-label": "Custom fee rate in sat/vB" }) as HTMLInputElement;
      custom.addEventListener("input", () => { draft.custom = custom.value; draft.fee = "custom"; sync(); document.querySelectorAll(".fee-opt").forEach((b) => b.classList.toggle("on", (b as HTMLElement).dataset.k === "custom")); });
      const form = h("form", { class: "card form", novalidate: true },
        h("div", { class: "from-line" }, h("span", { class: "muted small" }, `From ${a.label} · ${a.kind_name}`), h("span", { class: "muted small" }, w ? `Available ${fmtBtc(w.confirmed_sats + w.unconfirmed_sats)} ${n.unit}` : "")),
        h("label", { class: "field" }, h("span", { class: "field-label" }, "To"), toInput, toMsg),
        h("div", { class: "field" }, h("span", { class: "field-label row between" }, "Amount", unitSeg),
          h("div", { class: "input-wrap" }, amtInput, h("span", { class: "suffix" }, draft.unit === "BTC" ? n.unit : draft.unit), maxBtn), amtMsg),
        h("div", { class: "field" }, h("span", { class: "field-label" }, "Fee"),
          h("div", { class: "fee-opts" }, feeBtn("slow", "Slow", "~1 day"), feeBtn("normal", "Normal", "~1 hour"), feeBtn("fast", "Fast", "next block"),
            h("label", { class: `fee-opt${draft.fee === "custom" ? " on" : ""}`, "data-k": "custom" }, h("strong", null, "Custom"), h("span", { class: "muted small" }, "sat/vB"), custom)),
          h("p", { class: "muted small" }, fees ? `Estimates from ${fees.server}. Replaceable (RBF): a stuck transaction can be sped up later.` : "Loading fee estimates…")),
        formError ? h("p", { class: "inline-error" }, icon("alert", 15), formError) : null,
        goBtn,
      );
      form.addEventListener("submit", (ev) => { ev.preventDefault(); void getQuote(a); });
      queueMicrotask(() => { void check(); sync(); if (!quoting) (draft.to ? amtInput : toInput).focus(); });
      return form;
    }
    case "bumping": return statusCard("Preparing the speed-up…", "Checking the transaction is still unconfirmed and building a replacement with a higher fee.", [], []);
    case "bump_failed": return h("section", { class: "card result" }, h("div", { class: "result-ic neutral" }, icon("x", 28)), h("h3", null, "Can't speed it up"), h("p", null, capitalize(flow.message) + "."),
      h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => { flow = { s: "form" }; go("home"); } }, "Back")));
    case "review": return review(a, flow.q);
    case "connecting":
      return statusCard(flow.waiting ? "Waiting for your phone…" : "Reaching your phone…", flow.waiting ? "Your phone is answering another request. Your transaction goes to it as soon as that one finishes. Nothing has been sent yet." : "Opening the USB connection. The request is not on the phone yet.",
        [clockLine(flow.t0, null)], [cancelButton(flow.cancelling, cancelSign)]);
    case "on_phone": {
      const q = flow.q;
      return h("section", { class: "card phone-wait" },
        h("div", { class: "phone-art" }, h("div", { class: "phone-screen" }, padlock(3))),
        h("h3", null, "Review on your phone"),
        h("p", { class: "muted" }, "Check the amount, the address and the fee there, then approve. The phone checks the change goes back to your own key."),
        h("ul", { class: "checklist" },
          h("li", null, h("span", { class: "muted" }, "Send"), h("strong", null, `${fmtBtc(q.amount_sats)} ${n.unit}`)),
          h("li", null, h("span", { class: "muted" }, "To"), h("strong", { class: "mono" }, short(q.recipient))),
          h("li", null, h("span", { class: "muted" }, "Fee"), h("strong", null, fmtSats(q.fee_sats))),
          q.change_sats ? h("li", null, h("span", { class: "muted" }, "Change (yours)"), h("strong", null, `${fmtBtc(q.change_sats)} ${n.unit}`)) : null,
        ),
        clockLine(flow.t0, REVIEW_LIMIT_MS),
        h("div", { class: "actions" }, cancelButton(flow.cancelling, cancelSign)),
      );
    }
    case "verifying": return statusCard("Checking the signatures…", "Comparing the signed transaction with what you reviewed and verifying every signature on this Mac.", [], []);
    case "failed": {
      const x = explainSendError(flow.err, { chain: "btc" });
      const q = flow.q;
      return h("section", { class: `card result ${x.danger ? "danger-card" : ""}` },
        h("div", { class: `result-ic ${x.danger ? "bad" : x.neutral ? "neutral" : "warn"}` }, icon(x.danger ? "alert" : "x", 28)),
        h("h3", null, x.title), h("p", null, x.body),
        flow.err.message && !x.hideDetail ? h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, flow.err.message)) : null,
        h("div", { class: "actions" },
          x.danger ? null : h("button", { class: "big primary", onclick: () => sendToPhone(q) }, icon("refresh", 18), "Try again"),
          h("button", { class: "big", onclick: () => { if (x.danger || draft.bumpOf) { flow = { s: "form" }; go("home"); } else setFlow({ s: "form" }); } }, x.danger || draft.bumpOf ? "Close" : "Edit"),
        ));
    }
    case "signed": case "broadcasting": case "broadcast_failed": {
      const s = flow.signed; const q = flow.q;
      const sending = flow.s === "broadcasting";
      return h("section", { class: "card result" },
        h("div", { class: "result-ic ok" }, icon("check", 28)),
        q.replaces ? h("p", { class: "kicker" }, `Replaces ${short(q.replaces)}`) : null,
        h("h3", null, "Signed and verified"),
        h("ul", { class: "verified" }, s.checks.map((c) => h("li", null, icon("check", 14), c))),
        h("dl", { class: "facts" },
          fact("Send", h("span", null, `${fmtBtc(s.amount_sats)} ${n.unit}`, $(s.amount_sats) ? h("span", { class: "muted" }, ` · ${$(s.amount_sats)}`) : null)),
          fact("To", h("span", { class: "mono" }, short(s.recipient))),
          fact("Fee", `${fmtSats(s.fee_sats)} · ${s.rate} sat/vB · ${s.vsize} vB`),
          fact("Transaction ID", h("button", { class: "link mono", onclick: () => copy(s.txid, "Transaction ID") }, short(s.txid))),
        ),
        flow.s === "broadcast_failed" ? h("div", { class: "inline-error block" }, icon("alert", 15), h("span", null, h("strong", null, "The server didn't accept it. "), explainBroadcast(flow.message), h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, flow.message)))) : null,
        h("p", { class: "note" }, `Not on the network yet. Broadcast sends it through ${w?.server ?? "your server"}.`),
        h("div", { class: "actions" },
          h("button", { class: "big primary", disabled: sending, onclick: () => doBroadcast(a, q, s) }, sending ? [h("i", { class: "mini-spin" }), "Broadcasting…"] : [icon("up", 18), flow.s === "broadcast_failed" ? "Retry broadcast" : `Broadcast to ${n.name}`]),
          h("button", { class: "big", disabled: sending, onclick: () => { activeTicket = null; flow = { s: "form" }; go("home"); } }, "Discard"),
        ));
    }
    case "submitted": {
      const s = flow.signed;
      const conf = flow.confs;
      return h("section", { class: "card result" },
        conf > 0 ? h("div", { class: "result-ic ok big" }, icon("check", 32)) : h("div", { class: "result-ic pending" }, h("i", { class: "spinner" })),
        h("h3", null, conf > 0 ? `Confirmed · ${conf} confirmation${conf === 1 ? "" : "s"}` : `Broadcast to ${n.name}`),
        h("p", { class: "muted" }, conf > 0 ? `${fmtBtc(s.amount_sats)} ${n.unit} sent. Most services wait for 1–6 confirmations.` : "Waiting for the first confirmation (about 10 minutes on average, longer at a low fee). You can close this; Activity keeps track."),
        conf > 0 ? null : clockLine(flow.t0, null),
        h("div", { class: "hash-box" },
          h("button", { class: "link mono", title: s.txid, onclick: () => copy(s.txid, "Transaction ID") }, short(s.txid), icon("copy", 14)),
          h("button", { class: "link", onclick: () => openExternal(s.explorer) }, "View on mempool.space", icon("external", 14))),
        h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => { flow = { s: "form" }; draft.amount = ""; draft.max = false; go("home"); } }, conf > 0 ? "Done" : "Close")),
      );
    }
  }
}

function review(a: BtcAccount, q: BtcQuote) {
  const n = btcNet(a.network);
  const $ = (sats: number) => usd(sats, host.price(), n.test);
  const change = q.outputs.find((o) => o.change);
  const big = q.fee_sats > q.amount_sats * 0.1 && q.fee_sats > 5_000;
  return h("section", { class: "card" },
    h("p", { class: "kicker" }, q.replaces ? `Replacement for ${short(q.replaces)} · higher fee` : "Check, then send to your phone"),
    h("div", { class: "hero-amount" }, h("span", { class: "amount" }, fmtBtc(q.amount_sats), h("span", { class: "unit" }, n.unit)), $(q.amount_sats) ? h("span", { class: "fiat" }, $(q.amount_sats)) : null),
    h("dl", { class: "facts" },
      fact("To", h("span", { class: "mono break" }, groupedBtc(q.recipient))),
      fact("Network", n.name),
      fact("Fee", h("span", null, `${fmtSats(q.fee_sats)} · ${q.rate} sat/vB`, $(q.fee_sats) ? h("span", { class: "muted" }, ` · ${$(q.fee_sats)}`) : null)),
      fact("Total", h("span", null, `${fmtBtc(q.total_sats)} ${n.unit}`, $(q.total_sats) ? h("span", { class: "muted" }, ` · ${$(q.total_sats)}`) : null)),
      change ? fact("Change", h("span", null, `${fmtBtc(change.sats)} ${n.unit} back to you `, h("span", { class: "mono muted", title: change.address }, `${short(change.address)} · ${change.path}`))) : fact("Change", "none"),
      fact("Inputs", h("details", { class: "detail inline" }, h("summary", null, `${q.inputs.length} coin${q.inputs.length === 1 ? "" : "s"} · ${fmtBtc(q.balance_sats)} ${n.unit}`),
        h("ul", { class: "plain-list" }, q.inputs.map((i) => h("li", { class: "mono small" }, `${short(i.outpoint.split(":")[0])}:${i.outpoint.split(":")[1]} · ${fmtBtc(i.sats)}${i.confirmed ? "" : " · unconfirmed"}`))))),
      fact("Size", `${q.vsize} vB · nSequence ${q.sequence}`),
    ),
    q.own_recipient ? h("p", { class: "inline-error" }, icon("alert", 15), "The recipient is one of your own addresses: this only moves coins inside your wallet and pays a fee.") : null,
    q.unconfirmed_inputs ? h("p", { class: "note" }, "This spends coins that are not confirmed yet. If the transaction that created them is replaced, this one becomes invalid.") : null,
    big ? h("p", { class: "inline-error" }, icon("alert", 15), `The fee is more than 10% of the amount. Check the fee rate (${q.rate} sat/vB).`) : null,
    h("p", { class: "note" }, "Your phone shows the address, amount, fee and change, and checks the change belongs to your key. Approve there only if they match. After signing, this Mac re-checks every signature and the exact amounts before anything can be broadcast."),
    h("div", { class: "actions" },
      h("button", { class: "big primary", onclick: () => sendToPhone(q) }, icon("phone", 18), "Send to phone"),
      h("button", { class: "big", onclick: () => { if (q.replaces) { flow = { s: "form" }; go("home"); } else setFlow({ s: "form" }); } }, q.replaces ? "Not now" : "Edit"),
    ),
  );
}

async function getQuote(a: BtcAccount) {
  const rate = rateOf(); const amount = draft.max ? null : amountBtc();
  if (!addr?.ok || !rate || (!draft.max && !amount)) return;
  formError = null;
  setFlow({ s: "quoting" });
  try {
    const q = await btcApi.quote(a.id, draft.to.trim(), amount, draft.max, rate);
    if (flow.s !== "quoting") return;
    setFlow({ s: "review", q });
  } catch (e) { formError = capitalize(errText(e)); if (flow.s === "quoting") setFlow({ s: "form" }); }
}

async function startBump(a: BtcAccount, e: BtcHistory) {
  const blocked = host.phoneBlocked(); if (blocked) { toast(blocked); return; }
  draft.bumpOf = e.txid; activeTicket = null;
  flow = { s: "bumping", txid: e.txid }; go("send");
  try {
    let f = fees; try { f = await btcApi.fees(a.id); fees = f; } catch { /* use the last */ }
    const rate = Math.max(f?.fast ?? 2, 1.1);
    const q = await btcApi.bumpQuote(a.id, e.txid, rate.toFixed(1));
    if (flow.s !== "bumping") return;
    setFlow({ s: "review", q });
  } catch (err) { if (flow.s === "bumping") setFlow({ s: "bump_failed", txid: e.txid, message: errText(err) }); }
}

async function sendToPhone(q: BtcQuote) {
  if (host.phoneBusy()) { toast("The phone is answering another request. Finish it first."); return; }
  const ticket = crypto.randomUUID();
  activeTicket = ticket;
  setFlow({ s: "connecting", q, ticket, t0: Date.now() });
  try {
    const signed = await btcApi.signStart(ticket, q.quote_id);
    if (activeTicket === ticket) setFlow({ s: "signed", q, signed });
  } catch (e) {
    if (activeTicket !== ticket) return;
    setFlow({ s: "failed", q, err: asSendError(e) });
  }
}

async function cancelSign() {
  if (flow.s !== "connecting" && flow.s !== "on_phone") return;
  const t = flow.ticket; setFlow({ ...flow, cancelling: true });
  try { await btcApi.signCancel(t); } catch { /* the command result says */ }
}

async function doBroadcast(a: BtcAccount, q: BtcQuote, s: Signed) {
  setFlow({ s: "broadcasting", q, signed: s });
  try {
    await btcApi.broadcast(s.txid);
    activeTicket = null;
    const t0 = Date.now();
    setFlow({ s: "submitted", q, signed: s, t0, confs: 0 });
    void loadWallet(a.id);
    for (;;) {
      await new Promise((r) => setTimeout(r, CONFIRMATION_POLL_MS));
      if (flow.s !== "submitted" || flow.signed.txid !== s.txid) return;
      try {
        const st = await btcApi.txStatus(a.id, s.txid);
        if (flow.s !== "submitted" || flow.signed.txid !== s.txid) return;
        if (st.confirmed) { setFlow({ ...flow, confs: st.confirmations }); void refreshBtc(a.id); return; }
      } catch { /* try again */ }
      if (Date.now() - t0 > 3 * 3600_000) return;
    }
  } catch (e) { setFlow({ s: "broadcast_failed", q, signed: s, message: errText(e) }); }
}

function explainBroadcast(m: string): string {
  if (/insufficient fee|min relay fee|mempool min fee/i.test(m)) return "The fee is below what the network accepts right now. Discard and send again with a higher fee. ";
  if (/missingorspent|bad-txns-inputs-missingorspent|conflict/i.test(m)) return "Its coins were already spent by another transaction. Refresh and check Activity. ";
  if (/unreachable|timed out/i.test(m)) return "The server couldn't be reached. Retry, or set another server in Settings → Bitcoin. ";
  return "";
}

// ------------------------------------------------------------------ settings

let exporting: { a: BtcAccount; e: Export | null; error?: string } | null = null;

function exportModal(): HTMLElement | null {
  if (!exporting) return null;
  const x = exporting;
  const close = () => { exporting = null; document.getElementById("btc-export")?.remove(); };
  const body = x.e
    ? h("div", { class: "stack" },
        h("p", { class: "muted small" }, "In Sparrow: File → New Wallet → name it → Import External → Output Descriptor, then paste this. Sparrow shows the same addresses and balance, and can make PSBTs for your phone to sign. It holds no private key."),
        h("pre", { class: "descriptor mono" }, x.e.descriptor),
        h("dl", { class: "facts" }, fact("Fingerprint", h("span", { class: "mono" }, x.e.fingerprint)), fact("Path", h("span", { class: "mono" }, x.e.path)), fact("xpub", h("span", { class: "mono break small" }, x.e.xpub))),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => copy(x.e!.descriptor, "Descriptor") }, icon("copy", 16), "Copy descriptor"),
          h("button", { class: "big", onclick: async () => { try { const p = await btcApi.saveExport(x.a.id); toast(`Saved to ${p.replace(/^.*\/Downloads\//, "Downloads/")}`); } catch (e) { toast(errText(e)); } } }, "Save .txt"),
        ),
        h("p", { class: "muted small" }, "Anyone with this text can see every address, balance and transaction of this account (not spend). Share it only with software you trust."))
    : x.error ? h("p", { class: "inline-error" }, x.error) : h("div", { class: "boot" }, h("div", { class: "spinner" }));
  return h("div", { id: "btc-export", class: "modal-scrim fade", onclick: (e: Event) => { if ((e.target as HTMLElement).id === "btc-export") close(); } },
    h("section", { class: "card modal", role: "dialog", "aria-modal": "true" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, `Export to Sparrow · ${x.a.label}`), h("button", { class: "icon-btn", onclick: close, "aria-label": "Close" }, icon("close", 18))),
      body));
}

async function openExport(a: BtcAccount) {
  exporting = { a, e: null };
  const show = () => { document.getElementById("btc-export")?.remove(); const m = exportModal(); if (m) document.body.append(m); };
  show();
  try { const e = await btcApi.export(a.id); if (exporting?.a.id === a.id) { exporting.e = e; show(); } }
  catch (e) { if (exporting) { exporting.error = errText(e); show(); } }
}

export function btcSettingsSection(rerenderDrawer: () => void): HTMLElement {
  const n = host.net();
  const rows = accounts.filter((a) => host.showTestnets() || a.network === "bitcoin").map((a) => {
    const name = h("input", { type: "text", class: "acct-name", value: a.label, maxlength: "40", spellcheck: "false", "aria-label": `Name for ${a.id}` }) as HTMLInputElement;
    name.addEventListener("change", async () => { const v = name.value.trim(); if (!v) { name.value = a.label; return; } try { await btcApi.rename(a.id, v); await reloadAccounts(); host.renderNow(); } catch { name.value = a.label; } });
    return h("div", { class: "acct-row" },
      h("div", { class: "grow" }, name,
        h("span", { class: "muted small mono" }, `${a.kind_name} · ${a.path} · ${a.fingerprint}`),
        a.network !== "bitcoin" ? h("span", { class: "tag" }, a.network) : null),
      h("button", { onclick: () => openExport(a), title: "Watch-only descriptor for Sparrow and other wallets" }, "Export to Sparrow"),
      h("button", { class: "danger-ghost", title: "Unpair this account from this Mac (the phone keeps its keys)", onclick: async (ev: Event) => {
        const b = ev.currentTarget as HTMLButtonElement;
        if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again"; return; }
        try { await btcApi.forget(a.id); wallets.delete(a.id); await reloadAccounts(); rerenderDrawer(); host.renderNow(); } catch (e) { b.textContent = errText(e); }
      } }, "Forget"),
    );
  });
  const def = defaults[n]?.[0] ?? "";
  const server = h("input", { type: "url", spellcheck: "false", value: servers[n] ?? "", placeholder: def }) as HTMLInputElement;
  const msg = h("p", { class: "field-msg" });
  const save = async (v: string | null) => {
    try { await btcApi.setServer(n, v); await reloadAccounts(); msg.textContent = v ? "Saved. Only this server is used now." : "Using the default servers."; msg.className = "field-msg ok"; const a = activeBtc(n); if (a) void refreshBtc(a.id, true); }
    catch (e) { msg.textContent = errText(e); msg.className = "field-msg bad"; }
  };
  const testToggle = h("input", { type: "checkbox", role: "switch", checked: host.showTestnets() }) as HTMLInputElement;
  testToggle.addEventListener("change", () => { host.setShowTestnets(testToggle.checked); rerenderDrawer(); });
  return h("section", { class: "set", id: "btc-section" },
    h("h4", null, "BITCOIN"),
    rows.length ? h("div", { class: "acct-list" }, h("p", { class: "muted small" }, "Watch-only accounts: this Mac holds public keys only."), ...rows)
      : h("p", { class: "muted small" }, "No Bitcoin account yet. Pick Bitcoin in the network menu to add one from your phone."),
    h("h4", { class: "sub" }, `SERVER FOR ${btcNet(n).name.toUpperCase()}`),
    h("label", { class: "field" }, server, msg),
    h("div", { class: "row gap" },
      h("button", { onclick: () => { const v = server.value.trim(); void save(v || null); } }, "Save"),
      h("button", { class: "ghost", onclick: () => { server.value = ""; void save(null); } }, "Use default"),
    ),
    h("p", { class: "muted small" }, `Default: ${(defaults[n] ?? []).map((u) => u.replace(/^https:\/\//, "")).join(", then ")}. Any Esplora API works (mempool, electrs/esplora), including one on your own node (http:// is allowed on this Mac and the local network only).`),
    h("div", { class: "callout" },
      h("strong", null, "Privacy"),
      h("span", null, "To show your balance, this Mac asks the server about each of your addresses (about 40 at first, then a few every couple of minutes). The server can link them to each other and to your IP address. It can't move your coins or change what the phone signs: amounts are checked against the transactions themselves, and the phone shows what it signs. For privacy, run your own node (Umbrel, Start9, a Raspberry Pi with mempool or electrs) and enter its address here."),
    ),
    h("label", { class: "toggle" }, h("span", null, "Developer: show Testnet and Signet"), testToggle, h("i", { class: "knob" })),
  );
}
