// Bitcoin: watch-only accounts whose keys stay on the phone (src-tauri/src/btc). This module owns
// the Bitcoin screens (home, receive + verify on phone, pairing) and the Settings section; main.ts
// shows them when a Bitcoin network is selected. The send stepper is in bitcoin-send.ts; commands,
// types, formatting and the shared state are in bitcoin-core.ts.

import { onEvent, openExternal, errText } from "./api";
import { h, icon, padlock, short, copy, ago, toast, fact } from "./ui";
import { qrSvg } from "./qr";
import { explainPlain } from "./errors";
import { btcState, btcApi, wallets, go, btcNet, fmtBtc, fmtSats, usd, groupedBtc } from "./bitcoin-core";
import type { BtcHost, BtcNet, BtcAccount, BtcWallet, Candidate, Shown, Export } from "./bitcoin-core";
import { initBtcSend, btcSendFormOpen, btcSendBusy, startSend, startBump, sendView } from "./bitcoin-send";
import "./bitcoin.css";

export { BTC_NETS, btcNet, fmtBtc } from "./bitcoin-core";
export type { BtcNet, BtcHost, BtcAccount, BtcWallet, BtcHistory, BtcQuote } from "./bitcoin-core";

// ------------------------------------------------------------------ state

let accounts: BtcAccount[] = [];
let servers: Record<string, string> = {};
let defaults: Record<string, string[]> = {};
let loaded = false;
const refreshing = new Set<string>();

export const btcAccounts = () => accounts;
const accountsOn = (n: BtcNet) => accounts.filter((a) => a.network === n);
export const activeBtc = (n: BtcNet): BtcAccount | null => accountsOn(n).find((a) => a.active) ?? accountsOn(n)[0] ?? null;
export const btcWallet = (id: string) => wallets.get(id) ?? null;

export async function btcInit(h0: BtcHost) {
  btcState.host = h0;
  await reloadAccounts();
  void onEvent<{ id: string }>("btc-changed", (p) => { void loadWallet(p.id); });
  initBtcSend({ loadWallet, refreshBtc });
}

export async function reloadAccounts() {
  try { const r = await btcApi.accounts(); accounts = r.accounts; servers = r.servers; defaults = r.defaults; loaded = true; }
  catch { /* keep the last list */ }
  for (const a of accounts) if (!wallets.has(a.id)) void loadWallet(a.id);
}

async function loadWallet(id: string) {
  try { wallets.set(id, await btcApi.wallet(id)); } catch { /* not paired any more */ }
  if (!btcSendFormOpen()) btcState.host?.rerender();
}

/** Ask the server now (light scan; Rust does a full gap-limit scan at most every 30 min, or when `full`). */
export async function refreshBtc(id: string, full = false) {
  if (refreshing.has(id)) return;
  refreshing.add(id); btcState.host.rerender();
  try { wallets.set(id, await btcApi.refresh(id, full)); } catch (e) { const w = wallets.get(id); if (w) wallets.set(id, { ...w, error: errText(e) }); }
  finally { refreshing.delete(id); btcState.host.rerender(); }
}

/** Back to the Bitcoin home screen (the header's brand button). */
export function btcGoHome() { if (!btcSendBusy()) { btcState.sub = "home"; } }
export const btcBusy = () => btcSendBusy();
/** The Bitcoin Receive screen is the one shown (for the network picker on it). */
export const btcOnReceive = () => btcState.sub === "receive";
/** Open the Bitcoin Receive screen (picked from another network's Receive screen). */
export function btcOpenReceive() { if (!btcSendBusy()) { recv = { s: "idle" }; btcState.sub = "receive"; } }

/** Total of the shown mainnet account (for the Balances list and the USD total). */
export function btcBalanceSats(n: BtcNet): number | null {
  const a = activeBtc(n); const w = a ? wallets.get(a.id) : null;
  return w ? w.confirmed_sats + w.unconfirmed_sats : null;
}

// ------------------------------------------------------------------ main entry

export function btcMain(): HTMLElement {
  const n = btcState.host.net();
  const a = activeBtc(n);
  if (btcState.sub === "pair") return pairView();
  if (!a) return emptyView();
  if (btcState.sub === "receive") return receiveView(a);
  if (btcState.sub === "send") return sendView(a);
  return homeView(a);
}

function emptyView() {
  const n = btcNet(btcState.host.net());
  return h("div", { class: "stack fade" },
    h("section", { class: "card account" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, "Bitcoin"), btcState.host.networkSelect()),
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
  sel.addEventListener("change", async () => { try { await btcApi.select(sel.value); await reloadAccounts(); btcState.host.renderNow(); } catch (e) { toast(errText(e)); } });
  return h("label", { class: "net-chip acct-chip", title: "Bitcoin accounts paired with this Mac" }, h("span", { class: "kicker" }, a.label), icon("chevron", 14), sel);
}

function homeView(a: BtcAccount) {
  const n = btcNet(a.network);
  const w = wallets.get(a.id);
  if (!w && !refreshing.has(a.id)) void loadWallet(a.id);
  if (w && w.scanned_at === 0 && !refreshing.has(a.id) && !w.error) void refreshBtc(a.id);
  const total = w ? w.confirmed_sats + w.unconfirmed_sats : null;
  const fiat = total !== null ? usd(total, btcState.host.price(), n.test) : null;
  return h("div", { class: "stack fade" },
    h("section", { class: "card account" },
      h("div", { class: "row between" }, accountChip(a), btcState.host.networkSelect()),
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

type Recv = { s: "idle" } | { s: "asking"; index: number; after?: string } | { s: "match"; index: number } | { s: "mismatch"; index: number; shown: string } | { s: "error"; message: string };
let recv: Recv = { s: "idle" };

async function verifyOnPhone(a: BtcAccount, index: number) {
  const blocked = btcState.host.phoneBlocked();
  if (blocked) { recv = { s: "error", message: blocked }; btcState.host.renderNow(); return; }
  recv = { s: "asking", index, after: recv.s === "mismatch" && recv.index === index ? recv.shown : undefined }; btcState.host.renderNow();
  try {
    const r = await btcApi.showAddress(a.id, 0, index);
    recv = r.matches ? { s: "match", index } : { s: "mismatch", index, shown: r.address };
    if (r.matches) await loadWallet(a.id);
  } catch (e) { recv = { s: "error", message: explainPlain(errText(e), "btc") }; }
  btcState.host.renderNow();
}

function receiveView(a: BtcAccount) {
  const n = btcNet(a.network);
  const w = wallets.get(a.id);
  if (!w) return h("div", { class: "stack fade" }, btcState.host.topbar("Receive", () => go("home")), h("div", { class: "boot" }, h("div", { class: "spinner" })));
  const addr = w.receive_address;
  const idx = w.receive_index;
  const verified = w.receive_verified || (recv.s === "match" && recv.index === idx);
  // The phone showed another address: nothing here may be shared (no QR, no Copy), only what to do next.
  const mismatch = recv.s === "mismatch" && recv.index === idx ? recv.shown : recv.s === "asking" && recv.index === idx ? recv.after : undefined;
  if (mismatch) {
    const shown = mismatch;
    const asking = recv.s === "asking";
    return h("div", { class: "stack fade" },
      btcState.host.topbar("Receive bitcoin", () => go("home")),
      h("section", { class: "card danger-card" },
        h("div", { class: "row between" }, h("p", { class: "kicker danger" }, "Don't use this address"), btcState.host.networkSelect()),
        h("h3", null, "Your phone shows a different address"),
        h("p", null, "This Mac and your phone disagree about this account's next receive address, so the address this Mac computed is hidden. Don't share or pay to either one until they match."),
        h("dl", { class: "facts" }, fact("Phone showed", h("span", { class: "mono break" }, groupedBtc(shown)))),
        h("ol", { class: "steps" },
          h("li", null, "Check the phone is on the same Bitcoin account (and passphrase wallet, if you use one) as this Mac shows."),
          h("li", null, "Use another USB cable and port, then verify again."),
          h("li", null, "Still different? Something between this Mac and the phone is changing data. Stop and don't receive to this account here; use the address on the phone's screen only once you know why.")),
        h("div", { class: "actions" },
          h("button", { class: "big primary", disabled: asking, onclick: () => verifyOnPhone(a, idx) }, asking ? h("i", { class: "mini-spin" }) : icon("phone", 18), asking ? "Look at your phone…" : "Verify on phone again"),
          h("button", { class: "big", onclick: () => { recv = { s: "idle" }; go("home"); } }, "Close")),
      ),
    );
  }
  const qr = h("div", { class: "qr", html: qrSvg(`bitcoin:${addr.toUpperCase()}`, { dark: "#060608", light: "#ffffff", label: `QR code for ${addr}` }) });
  const verifyBox =
    recv.s === "asking" && recv.index === idx ? h("div", { class: "callout" }, h("strong", null, "Look at your phone"), h("span", null, "It shows this address. Compare every group of four characters with the one above."))
    : verified ? h("div", { class: "callout accent" }, h("strong", { class: "ok-line" }, icon("check", 15), "Your phone showed this same address"), h("span", null, `Derived on the phone from your key: m/${a.path.slice(2)}/0/${idx}. Safe to share.`))
    : recv.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), recv.message) : null;
  return h("div", { class: "stack fade" },
    btcState.host.topbar("Receive bitcoin", () => go("home")),
    h("section", { class: "card receive" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, `${a.label} · ${a.kind_name}`), btcState.host.networkSelect()),
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
  const n = btcNet(btcState.host.net());
  const back = () => { pair = { s: "choose" }; go("home"); };
  let body: Node;
  if (pair.s === "compare") {
    const p = pair;
    const c = p.c;
    const label = h("input", { type: "text", maxlength: "40", spellcheck: "false", value: c.label, "aria-label": "Name on this Mac" }) as HTMLInputElement;
    const ask = async () => {
      const blocked = btcState.host.phoneBlocked(); if (blocked) { pair = { ...p, error: blocked }; btcState.host.renderNow(); return; }
      pair = { ...p, asking: true, error: undefined }; btcState.host.renderNow();
      try {
        const r = await btcApi.showAddress(c.id, 0, 0);
        pair = r.matches ? { s: "compare", c, shown: r } : { s: "mismatch", c, shown: r.address };
      } catch (e) { pair = { s: "compare", c, error: explainPlain(errText(e), "btc") }; }
      btcState.host.renderNow();
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
              catch (e) { pair = { ...p, error: errText(e) }; btcState.host.renderNow(); }
            } }, icon("check", 18), "It matches · pair")
          : h("button", { class: "big primary", disabled: !!p.asking, onclick: ask }, p.asking ? h("i", { class: "mini-spin" }) : icon("phone", 18), p.asking ? "Look at your phone…" : "Show on phone"),
        h("button", { class: "big", onclick: () => { pair = { s: "mismatch", c, shown: p.shown?.address ?? "" }; btcState.host.renderNow(); } }, "It doesn't match"),
      ),
    );
  } else if (pair.s === "mismatch") {
    body = h("section", { class: "card danger-card" },
      h("p", { class: "kicker danger" }, "Not paired"),
      h("h3", null, "Stop here"),
      h("p", null, "The phone and this Mac disagree about the account's first address, so this Mac would show addresses your phone doesn't control. Nothing was saved. Use another cable and port, and don't receive to this account until they match."),
      pair.shown ? h("p", { class: "mono small" }, `Phone: ${groupedBtc(pair.shown)}`) : null,
      h("div", { class: "actions" }, h("button", { onclick: () => { pair = { s: "choose" }; btcState.host.renderNow(); } }, "Start over")),
    );
  } else {
    const reading = pair.s === "reading";
    const kindSeg = (k: string, label: string, note: string) => h("button", { class: pairDraft.kind === k ? "on" : "", title: note, onclick: () => { pairDraft.kind = k; btcState.host.renderNow(); } }, label);
    const acct = h("select", { class: "net-select", "aria-label": "Account number" }, Array.from({ length: 20 }, (_, i) => h("option", { value: i + 1, selected: pairDraft.account === i + 1 }, `Account ${i + 1}`)));
    acct.addEventListener("change", () => { pairDraft.account = Number(acct.value); });
    const read = async () => {
      const blocked = btcState.host.phoneBlocked(); if (blocked) { pair = { s: "choose", error: blocked }; btcState.host.renderNow(); return; }
      if (btcState.host.phoneBusy()) { pair = { s: "choose", error: "The phone is answering another request. Finish it first." }; btcState.host.renderNow(); return; }
      pair = { s: "reading" }; btcState.host.renderNow();
      try { const c = await btcApi.readAccount(btcState.host.net(), pairDraft.kind, pairDraft.account); pair = { s: "compare", c }; }
      catch (e) { pair = { s: "choose", error: explainPlain(errText(e), "btc") }; }
      btcState.host.renderNow();
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
  return h("div", { class: "stack fade" }, btcState.host.topbar("Add Bitcoin account", back), body);
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
  const n = btcState.host.net();
  const rows = accounts.filter((a) => btcState.host.showTestnets() || a.network === "bitcoin").map((a) => {
    const name = h("input", { type: "text", class: "acct-name", value: a.label, maxlength: "40", spellcheck: "false", "aria-label": `Name for ${a.id}` }) as HTMLInputElement;
    name.addEventListener("change", async () => { const v = name.value.trim(); if (!v) { name.value = a.label; return; } try { await btcApi.rename(a.id, v); await reloadAccounts(); btcState.host.renderNow(); } catch { name.value = a.label; } });
    return h("div", { class: "acct-row" },
      h("div", { class: "grow" }, name,
        h("span", { class: "muted small mono" }, `${a.kind_name} · ${a.path} · ${a.fingerprint}`),
        a.network !== "bitcoin" ? h("span", { class: "tag" }, a.network) : null),
      h("button", { onclick: () => openExport(a), title: "Watch-only descriptor for Sparrow and other wallets" }, "Export to Sparrow"),
      h("button", { class: "danger-ghost", title: "Unpair this account from this Mac (the phone keeps its keys)", onclick: async (ev: Event) => {
        const b = ev.currentTarget as HTMLButtonElement;
        if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again"; return; }
        try { await btcApi.forget(a.id); wallets.delete(a.id); await reloadAccounts(); rerenderDrawer(); btcState.host.renderNow(); } catch (e) { b.textContent = errText(e); }
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
  const testToggle = h("input", { type: "checkbox", role: "switch", checked: btcState.host.showTestnets() }) as HTMLInputElement;
  testToggle.addEventListener("change", () => { btcState.host.setShowTestnets(testToggle.checked); rerenderDrawer(); });
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
