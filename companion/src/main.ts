/// <reference types="vite/client" />
// Phone Vault Companion UI. One main view (account, balances, Send, Receive, activity), a send
// stepper driven only by real command results and `send-progress` events, and a settings drawer.
// This file is the composition root: the shell, home, receive, pairing and boot live here; the send
// flow (send.ts), phone identity + genuine check (identity.ts) and the settings drawer (settings.ts)
// get what they need from it through their *Host interfaces, and share state through state.ts.

import { api, onEvent, errText, isTauri } from "./api";
import type { WatchBalance, PairedAccount } from "./api";
import { badge as attBadge, verdictCard } from "./attestation";
import { NETWORKS, byId, type Network } from "./networks";
import { h, icon, padlock, short, grouped, fmtAmount, fmtUsd, copy, capitalize, topbar } from "./ui";
import { qrSvg } from "./qr";
import { tokenSection, refreshTokenBalances, resetTokenBalances, tokensOn, tokenBalancesFor, tokenUsd } from "./tokens";
import { wcPhoneBusy } from "./walletconnect";
import { mountWalletConnect, wcHomeSlot } from "./wc-view";
import { numberingHomeSlot, offerNumberingScan } from "./account-numbering";
import { activitySection, type ActivityHost } from "./activity";
import { nftSection, resetNfts, type NftHost } from "./nfts";
import { setupView, setupStart, setupNoticeFunds, type SetupHost } from "./onboarding";
import { explainPlain, explainNode } from "./errors";
import { setSimulationAccount } from "./simulation";
import { btcInit, btcMain, btcGoHome, btcOnReceive, btcOpenReceive, btcBusy, activeBtc, btcBalanceSats, refreshBtc, reloadAccounts, BTC_NETS, btcNet, fmtBtc, type BtcNet } from "./bitcoin";
import { state, prefs, savePrefs, rpcFor, net, applyTheme, pushWatchConfig, balances, balErrors, prices, price, activeLabel, pairedAccounts, type View, type HomeTab } from "./state";
import { initIdentity, identifyPhone, classifyPhone, renderPhoneNotice, readAddress, openDeviceSettings } from "./identity";
import { initSend, sendView, startSend, startSendTo, startReplacement, updateFormBalance, sendStage, sendNet } from "./send";
import { initSettings, drawer, openDrawer, closeDrawer, renderDrawer } from "./settings";
import "./extras.css";

// Poll intervals (ms). The preview has no background watcher, so it polls balances itself.
const STATUS_POLL_MS = 3000;
const PREVIEW_BALANCE_POLL_MS = 15_000;
const PREVIEW_ALL_BALANCES_POLL_MS = 60_000;
const PRICE_POLL_MS = 60_000;
const PENDING_POLL_MS = isTauri ? 60_000 : 15_000;
const RELATIVE_TIME_REFRESH_MS = 60_000;

// ------------------------------------------------------------------ live data

async function refreshStatus() {
  try {
    const s = await api.status();
    const pairedChanged = s.paired !== state.status?.paired;
    const phoneChanged = s.phone !== state.status?.phone;
    const appeared = (state.status?.phone ?? "none") === "none" && s.phone !== "none";
    state.status = s; state.statusError = null;
    setSimulationAccount(s.paired);
    if (s.phone === "none") { state.identity = { s: "unknown" }; state.phoneAddress = null; if (state.device.report || state.device.error) { state.device = { report: null, checking: false, error: null }; state.failDismissed = false; renderPhoneNotice(); } }
    else if (appeared) identifyPhone();
    renderHeader();
    if (pairedChanged) {
      // another account is shown (or pairing changed): everything per-account starts over
      balances.clear(); balErrors.clear(); resetTokenBalances(); resetNfts(); state.history = [];
      if (state.phoneAddress && state.identity.s !== "checking" && state.identity.s !== "unreadable") { state.identity = classifyPhone(state.phoneAddress); renderHeader(); renderPhoneNotice(); }
      if (s.paired) { refreshAllBalances(); void refreshHistory(); }
      render();
    }
    else if (phoneChanged && (state.view === "pair" || state.view === "setup" || state.drawerOpen)) { render(); if (state.drawerOpen) renderDrawer(); }
  } catch (e) { state.statusError = errText(e); renderHeader(); }
}

async function refreshBalance(n: Network) {
  if (!state.status?.paired) return;
  try {
    const w = await api.wallet(rpcFor(n.id));
    if (w.chain_id !== n.id) throw `this node is on chain ${w.chain_id}, not ${n.name}. Check the node in Settings.`;
    const wei = BigInt(w.balance_wei);
    const prev = balances.get(n.id);
    setBalance(n.id, wei, w.balance_eth, prev);
  } catch (e) { balErrors.set(n.id, errText(e)); }
  if (state.view === "home") renderSoon();
  if (state.view === "send" && sendStage() === "form") updateFormBalance();
  // ERC-20 balances for the network in view (display only)
  if (n.id === prefs.chainId || (state.view === "send" && n.id === sendNet().id)) {
    void refreshTokenBalances(n.id, rpcFor(n.id)).then(() => {
      if (state.view === "home") renderSoon();
      if (state.view === "send" && sendStage() === "form") updateFormBalance();
    });
  }
}
const refreshAllBalances = () => Promise.allSettled(NETWORKS.map(refreshBalance));

/** Balance increases, for the setup's "waiting for your test deposit" step. Recording incoming
 *  transfers and notifying is the background watcher's job (Rust), window open or not. */
const increaseListeners = new Set<(chainId: number, prevWei: bigint) => void>();
function setBalance(chainId: number, wei: bigint, eth: string, prev = balances.get(chainId)) {
  balances.set(chainId, { eth, wei, at: Date.now() });
  balErrors.delete(chainId);
  if (prev && wei > prev.wei) increaseListeners.forEach((l) => l(chainId, prev.wei));
}

async function refreshPrices() {
  try { const p = await api.prices(); prices.ETH = p.ETH ?? prices.ETH ?? null; prices.POL = p.POL ?? prices.POL ?? null; prices.BTC = p.BTC ?? prices.BTC ?? null; }
  catch { /* keep the last ones */ }
  if (state.view === "home") renderSoon();
}


async function refreshHistory() {
  try { state.history = await api.history(); } catch { /* keep what we have */ }
  if (state.view === "home") renderSoon();
  if (state.view === "setup") setupNoticeFunds(setupHost, null);
}

/** Receipt check for anything this companion sent that is still pending: mined ones get their
 *  outcome, and the rest of their nonce group (a speed-up's original, a cancelled transaction)
 *  is marked dropped. In the app the background watcher does this too, window open or not. */
async function pollPending() {
  const chains = new Set(state.history.filter((e) => e.kind === "out" && e.status === "pending" && e.hash && Date.now() / 1000 - e.time < 86400 * 7).map((e) => e.chain_id));
  for (const c of chains) {
    try {
      const before = state.history.filter((e) => e.status === "pending").length;
      state.history = await api.historyReconcile(rpcFor(c));
      if (state.history.filter((e) => e.status === "pending").length !== before) refreshBalance(byId(c));
    } catch { /* retry next round */ }
  }
  if (chains.size && state.view === "home") renderSoon();
}

// ------------------------------------------------------------------ shell

const app = document.getElementById("app")!;
const header = h("header", { class: "top" });
const main = h("main", { id: "view" });
const scrim = h("div", { class: "scrim", onclick: () => closeDrawer() });
app.append(header, main, scrim, drawer);

function go(v: View) { if (v === "home") btcGoHome(); state.view = v; main.scrollTop = 0; window.scrollTo(0, 0); render(); }

function renderHeader() {
  const phone = state.status?.phone ?? "none";
  let label = state.statusError ? "USB unavailable" : phone === "accessory" ? "Phone connected" : phone === "android" ? "Phone on USB" : "No phone";
  let title = state.statusError ?? (phone === "android" ? "The phone is on USB. It switches to vault mode when a request is sent." : phone === "none" ? "Plug the vault into this Mac with a USB cable." : "The vault is connected in accessory mode.");
  let cls: string = state.statusError ? "none" : phone;
  if (!state.statusError && phone !== "none") {
    if (state.identity.s === "checking") { label = "Checking phone…"; title = "Asking the phone which wallet it holds."; }
    else if (state.identity.s === "match") { label = "Your phone"; title = "The phone on USB holds the wallet this Mac is paired with."; cls = "accessory"; }
    else if (state.identity.s === "other") { label = `Phone on ${state.identity.label}`; title = `The phone is using ${state.identity.label}; this Mac shows ${activeLabel()}. Click to switch.`; cls = "android"; }
    else if (state.identity.s === "different") { label = "Unpaired account"; title = "The phone on USB is using an account or wallet this Mac has not paired. Click to review."; cls = "danger"; }
    else if (state.identity.s === "unreadable") { label = "Unlock your phone"; title = "The phone is asking to be unlocked. This updates by itself once you unlock it."; }
  }
  const retry = state.identity.s === "unreadable" ? () => identifyPhone()
    : state.identity.s === "different" || state.identity.s === "other" ? () => { if (state.identity.s === "different" || state.identity.s === "other") state.identity.dismissed = false; renderPhoneNotice(); } : undefined;
  header.replaceChildren(...[
    h("button", { class: "brand", onclick: () => go("home"), title: "Home" }, padlock(2), h("span", null, "PHONE VAULT")),
    retry ? h("button", { class: `chip ${cls}`, title, onclick: retry }, h("i", { class: "dot" }), h("span", { class: "chip-label" }, label))
      : h("span", { class: `chip ${cls}`, title }, h("i", { class: "dot" }), h("span", { class: "chip-label" }, label)),
    phone !== "none" ? attBadge(state.device, openDeviceSettings) : null,
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
  if (!state.status) { main.replaceChildren(h("div", { class: "boot" }, h("div", { class: "spinner" }))); return; }
  // no pairing yet: the guided setup (it pairs as step 3)
  if (!state.status.paired && state.view !== "tool" && state.view !== "setup") { setupStart(setupHost); state.view = "setup"; }
  const el = state.view === "home" && prefs.btc ? btcMain() : state.view === "home" ? homeView() : state.view === "send" ? sendView() : state.view === "receive" ? receiveView() : state.view === "pair" ? pairView() : state.view === "setup" ? setupView(setupHost) : toolView();
  // Background refreshes (balances, prices, watcher, the clock) redraw the same screen: don't replay
  // the entrance animation or jump the scroll position then — only animate a real screen change.
  const sameScreen = state.view === lastRendered;
  if (sameScreen) el.querySelectorAll(".fade").forEach((n) => n.classList.remove("fade"));
  if (sameScreen && el.classList.contains("fade")) el.classList.remove("fade");
  const y = main.scrollTop, wy = window.scrollY;
  main.replaceChildren(el);
  if (sameScreen) { main.scrollTop = y; window.scrollTo(0, wy); }
  lastRendered = state.view;
}
let lastRendered: View | null = null;

// ------------------------------------------------------------------ home

const btcNets = () => BTC_NETS.filter((b) => !b.test || prefs.btcTestnets);
function selectBtc(b: BtcNet | null) {
  if (btcBusy()) return;
  prefs.btc = b; savePrefs();
  if (b) { const a = activeBtc(b); if (a) void refreshBtc(a.id); }
}
function networkSelect(onChange?: () => void, cls = "net-chip") {
  const sel = h("select", { class: "net-select", "aria-label": "Network", disabled: btcBusy() },
    NETWORKS.map((n) => h("option", { value: n.id, selected: !prefs.btc && n.id === prefs.chainId }, n.testnet ? `${n.name} (testnet)` : n.name)),
    btcNets().map((b) => h("option", { value: `btc:${b.id}`, selected: prefs.btc === b.id }, b.test ? `${b.name} (test)` : b.name)));
  sel.addEventListener("change", () => {
    // On a Receive screen, another network opens that network's Receive screen (Bitcoin's own, or the EVM one).
    const receiving = !onChange && (state.view === "receive" || (state.view === "home" && !!prefs.btc && btcOnReceive()));
    if (sel.value.startsWith("btc:")) {
      selectBtc(sel.value.slice(4) as BtcNet);
      if (receiving) { state.view = "home"; btcOpenReceive(); }
    } else {
      prefs.btc = null; prefs.chainId = Number(sel.value); savePrefs(); refreshBalance(net());
      if (receiving) { btcGoHome(); state.view = "receive"; }
    }
    onChange ? onChange() : render();
  });
  if (prefs.btc) return h("label", { class: cls }, h("i", { class: `net-dot nbtc-${prefs.btc}` }), h("span", null, btcNet(prefs.btc).name), icon("chevron", 14), sel);
  return h("label", { class: cls }, h("i", { class: `net-dot n${net().id}` }), h("span", null, net().name), icon("chevron", 14), sel);
}

function homeView() {
  const n = net();
  const b = balances.get(n.id);
  const err = balErrors.get(n.id);
  const addr = state.status!.paired_checksum!;
  const usd = b ? fmtUsd(b.eth, price(n)) : null;
  return h("div", { class: "stack fade" },
    state.device.report && state.device.report.verdict !== "genuine" ? h("button", { class: `att-banner ${state.device.report.verdict === "fail" ? "att-fail" : "att-dev"}`, onclick: openDeviceSettings },
      icon(state.device.report.verdict === "fail" ? "alert" : "shield", 16), h("span", { class: "grow" }, state.device.report.verdict === "fail" ? "This phone failed the genuine check. Sending is blocked." : state.device.report.headline), h("span", { class: "small" }, "Details")) : null,
    h("section", { class: "card account" },
      h("div", { class: "row between" },
        accountSelect(),
        networkSelect(),
      ),
      h("button", { class: "addr-btn", title: `${addr}\nClick to copy`, onclick: () => copy(addr) }, h("span", { class: "mono" }, short(addr)), icon("copy", 15)),
      h("div", { class: "balance" },
        b ? h("span", { class: "amount" }, fmtAmount(b.eth), h("span", { class: "unit" }, n.symbol)) : err ? null : h("span", { class: "amount skeleton" }, "0.0000"),
        usd ? h("span", { class: "fiat" }, usd) : null,
      ),
      err ? h("p", { class: "inline-error" }, icon("alert", 15), `Balance unavailable. ${explainNode(err)}`) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => startSend() }, icon("up", 20), "Send"),
        h("button", { class: "big", onclick: () => go("receive") }, icon("down", 20), "Receive"),
      ),
    ),
    wcHomeSlot(),
    numberingHomeSlot(() => { if (state.view === "home") render(); }),
    homeTabs(),
    prefs.tab === "nfts" ? nftSection(nftHost) : prefs.tab === "activity" ? activitySection(activityHost) : assetsTab(n),
  );
}

const accountBusy = () => state.view === "send" && sendStage() !== "form";
async function selectAccount(address: string) {
  if (accountBusy()) return;
  try { await api.selectAccount(address); await refreshStatus(); } catch (e) { state.statusError = errText(e); renderHeader(); }
}
function accountSelect() {
  const list = pairedAccounts();
  const onPhone = (a: PairedAccount) => state.phoneAddress?.toLowerCase() === a.address.toLowerCase() && state.identity.s !== "unreadable";
  if (list.length < 2) return h("p", { class: "kicker" }, activeLabel());
  const sel = h("select", { class: "net-select", "aria-label": "Account" },
    list.map((a) => h("option", { value: a.address, selected: a.active }, `${a.label} · ${short(a.checksum)}${onPhone(a) ? " · on the phone" : ""}`)));
  sel.addEventListener("change", () => { void selectAccount(sel.value); });
  return h("label", { class: "net-chip acct-chip", title: "Accounts paired with this Mac. Requests are pinned to the one shown; the phone must be on the same account." },
    h("span", { class: "kicker" }, activeLabel()), icon("chevron", 14), sel);
}

function homeTabs() {
  const pending = state.history.filter((e) => e.status === "pending").length;
  const tab = (t: HomeTab, label: string, extra?: Node | null) => h("button", { class: prefs.tab === t ? "on" : "", onclick: () => { prefs.tab = t; savePrefs(); render(); } }, label, extra ?? null);
  return h("nav", { class: "tabs", "aria-label": "Wallet" }, tab("assets", "Assets"), tab("nfts", "NFTs"), tab("activity", "Activity", pending ? h("span", { class: "count" }, `· ${pending}`) : null));
}

/** USD of everything loaded: native coins (Coinbase spot) and listed tokens (see tokens.ts usdBasis). */
function usdTotal(chains: Network[]): { usd: number; partial: boolean } {
  let usd = 0, partial = false;
  for (const x of chains) {
    if (x.testnet) continue;
    const b = balances.get(x.id); const p = price(x);
    if (!b || p === null) { partial = true; continue; }
    usd += Number(b.eth) * p;
    for (const t of tokenBalancesFor(x.id) ?? []) {
      if (!t.amount || t.raw === "0") continue;
      const v = tokenUsd(t.symbol, t.amount, prices);
      if (v === null) partial = true; else usd += v;
    }
    if (tokensOn(x.id).length && !tokenBalancesFor(x.id)) partial = true;
  }
  return { usd, partial };
}

let tokensLoadedAt = 0;
function assetsTab(n: Network) {
  // token balances for every network, at most every two minutes, for the totals
  if (Date.now() - tokensLoadedAt > 120_000 && state.status?.paired) {
    tokensLoadedAt = Date.now();
    for (const x of NETWORKS) if (x.id !== n.id) void refreshTokenBalances(x.id, rpcFor(x.id)).then(() => { if (state.view === "home") renderSoon(); });
  }
  const all = usdTotal(NETWORKS);
  const btcMain_ = btcBalanceSats("bitcoin");
  if (activeBtc("bitcoin")) { if (btcMain_ === null || prices.BTC == null) all.partial = true; else all.usd += (btcMain_ / 1e8) * prices.BTC; }
  const here = usdTotal([n]);
  const fmt = (v: number) => fmtUsd(v, 1) ?? "";
  return h("div", { class: "stack" },
    h("section", { class: "section" },
      h("div", { class: "total-line" },
        h("h3", { class: "section-title" }, "Balances"),
        all.usd > 0 ? h("span", { title: all.partial ? "Some balances or prices are not loaded yet" : "Native coins and listed tokens on all mainnets" }, h("span", { class: "muted small" }, "Total "), h("span", { class: "usd" }, `${all.partial ? "≈ " : ""}${fmt(all.usd)}`)) : null,
      ),
      h("ul", { class: "list nets" }, NETWORKS.map((x) => {
        const bx = balances.get(x.id); const ex = balErrors.get(x.id);
        const zero = bx && bx.wei === 0n;
        const t = usdTotal([x]);
        return h("li", null, h("button", { class: `net-row${x.id === n.id ? " on" : ""}${zero ? " zero" : ""}`, onclick: () => { prefs.chainId = x.id; savePrefs(); render(); refreshBalance(x); } },
          h("i", { class: `net-dot n${x.id}` }),
          h("span", { class: "grow" }, x.name, x.testnet ? h("span", { class: "tag" }, "testnet") : null),
          ex && !bx ? h("span", { class: "muted small", title: ex }, "unavailable") : h("span", { class: "mono num" }, bx ? `${fmtAmount(bx.eth, 5)} ${x.symbol}` : "…"),
          h("span", { class: "muted small fiat-col", title: "Native coin plus listed tokens" }, bx && !x.testnet && price(x) !== null ? fmt(t.usd) : ""),
        ));
      }),
      btcNets().filter((b) => activeBtc(b.id)).map((b) => {
        const sats = btcBalanceSats(b.id);
        return h("li", null, h("button", { class: `net-row${sats === 0 ? " zero" : ""}`, onclick: () => { selectBtc(b.id); render(); } },
          h("i", { class: `net-dot nbtc-${b.id}` }),
          h("span", { class: "grow" }, b.name, b.test ? h("span", { class: "tag" }, "test") : null),
          h("span", { class: "mono num" }, sats === null ? "…" : `${fmtBtc(sats).replace(/^(\d+\.\d{5})\d+$/, "$1")} ${b.unit}`),
          h("span", { class: "muted small fiat-col" }, sats !== null && !b.test && prices.BTC != null ? fmt((sats / 1e8) * prices.BTC) : ""),
        ));
      })),
    ),
    tokenSection(n.id, n.name, (sym, amt) => { const v = tokenUsd(sym, amt, prices); return v === null || n.testnet ? null : fmtUsd(v, 1); }),
    here.usd > 0 && !n.testnet ? h("p", { class: "muted small" }, `On ${n.name}: ${here.partial ? "≈ " : ""}${fmt(here.usd)} including listed tokens.`) : null,
  );
}

// ------------------------------------------------------------------ guided setup (onboarding.ts)

const setupHost: SetupHost = {
  status: () => state.status,
  device: () => state.device,
  recheck: () => { void identifyPhone(); },
  confirmPairing: async (address) => { await pairAccount(address, null); state.phoneAddress = address; state.identity = { s: "match" }; await refreshStatus(); },
  chainId: () => prefs.chainId,
  setChain: (id) => { prefs.chainId = id; savePrefs(); },
  balanceOf: (id) => balances.get(id)?.wei ?? null,
  refreshBalance: (id) => { void refreshBalance(byId(id)); },
  history: () => state.history,
  finish: (then) => {
    prefs.setupDone = true; savePrefs();
    if (then === "home") go("home");
    else startSendTo(then.sendTo ?? "");
  },
  rerender: () => { if (state.view === "setup") render(); },
};
increaseListeners.add((chainId, prevWei) => { if (state.view === "setup") setupNoticeFunds(setupHost, chainId, prevWei); });

const nftHost: NftHost = { chainId: () => prefs.chainId, rpcFor, rerender: () => { if (state.view === "home" && prefs.tab === "nfts") renderSoon(); } };

const activityHost: ActivityHost = {
  history: () => state.history,
  chainId: () => prefs.chainId,
  address: () => state.status?.paired_checksum ?? null,
  filter: prefs.activity,
  saveFilter: () => savePrefs(),
  rerender: () => { if (state.view === "home") render(); },
  replace: (e, kind) => { void startReplacement(e, kind); },
};

// ------------------------------------------------------------------ receive

function receiveView() {
  const n = net();
  const addr = state.status!.paired_checksum!;
  const qr = h("div", { class: "qr", html: qrSvg(addr, { dark: "#060608", light: "#ffffff", label: `QR code for ${addr}` }) });
  return h("div", { class: "stack fade" },
    topbar("Receive", () => go("home")),
    h("section", { class: "card receive" },
      h("div", { class: "row between" }, h("p", { class: "kicker" }, "Your address"), networkSelect()),
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

// ------------------------------------------------------------------ pairing


/** Ask the phone which account it is on (number, standard/passphrase) to label a new pairing. Best effort. */
async function describePhoneAccount(address: string): Promise<{ label: string; account: number | null; wallet: string | null } | null> {
  try {
    const info = await api.readAddress();
    return info.address.toLowerCase() === address.toLowerCase() ? { label: info.label, account: info.account, wallet: info.wallet } : null;
  } catch { return null; }
}

async function pairAccount(address: string, label: string | null, known?: { account?: number | null; wallet?: string | null }) {
  const info = known?.account !== undefined ? null : await describePhoneAccount(address);
  await api.confirmPairing(address, label ?? info?.label ?? null, known?.account ?? info?.account ?? null, known?.wallet ?? info?.wallet ?? null);
}

function pairView() {
  const paired = !!state.status?.paired;
  const phone = state.status?.phone ?? "none";
  const back = paired ? () => { state.pair = { s: "idle" }; go("home"); } : null;
  let body: Node;
  if (state.pair.s === "compare") {
    const address = state.pair.address;
    const cmp = state.pair;
    const att = state.device.report;
    const attOk = !!att && att.verdict !== "fail" && att.address?.toLowerCase() === address.toLowerCase();
    const labelInput = h("input", { type: "text", maxlength: "40", spellcheck: "false", value: cmp.label ?? "", placeholder: `Account ${pairedAccounts().length + 1}`, "aria-label": "Name for this account on this Mac" }) as HTMLInputElement;
    if (cmp.label === undefined) void describePhoneAccount(address).then((info) => {
      if (state.pair !== cmp) return;
      cmp.label = info?.label ?? ""; cmp.account = info?.account ?? null; cmp.wallet = info?.wallet ?? null;
      if (!labelInput.value) labelInput.value = cmp.label;
    });
    body = h("div", { class: "stack" }, h("section", { class: "card" },
      h("p", { class: "kicker" }, "Compare"),
      h("h3", null, "Does this match your phone?"),
      h("p", { class: "muted" }, "On the phone, open Wallet. Compare every group of four characters below with the address it shows."),
      h("p", { class: "addr-compare mono" }, grouped(address)),
      h("label", { class: "field" }, h("span", { class: "muted small" }, "Name on this Mac"), labelInput),
      cmp.wallet === "passphrase" ? h("p", { class: "muted small" }, "This is a passphrase wallet. The phone forgets the passphrase when it locks: open the same passphrase wallet on the phone before each use.") : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: async () => {
          try { await pairAccount(address, labelInput.value.trim() || null, cmp.label === undefined ? undefined : { account: cmp.account ?? null, wallet: cmp.wallet ?? null }); state.pair = { s: "idle" }; await refreshStatus(); state.phoneAddress = address; state.identity = classifyPhone(address); renderHeader(); renderPhoneNotice(); offerNumberingScan(); go("home"); } catch (e) { state.pair = { s: "idle", error: errText(e) }; render(); }
        }, disabled: !attOk, title: attOk ? "" : state.device.checking ? "Waiting for the genuine check" : "The genuine check must pass first" }, icon("check", 18), state.device.checking ? "Checking phone…" : "It matches"),
        h("button", { class: "big", onclick: () => { state.pair = { s: "mismatch" }; render(); } }, "It doesn't"),
      ),
    ), verdictCard(state.device, () => identifyPhone()));
  } else if (state.pair.s === "mismatch") {
    body = h("section", { class: "card danger-card" },
      h("p", { class: "kicker danger" }, "Not paired"),
      h("h3", null, "Stop here"),
      h("p", null, "If the phone shows a different address, something between this Mac and the phone is changing data. Nothing was saved. Use another cable and port, and don't send funds until the addresses match."),
      h("div", { class: "actions" }, h("button", { onclick: () => { state.pair = { s: "idle" }; render(); } }, "Start over")),
    );
  } else {
    const reading = state.pair.s === "reading";
    body = h("section", { class: "card pair" },
      h("div", { class: "pair-hero" }, padlock(6)),
      h("h3", null, paired ? "Pair another account" : "Pair your phone"),
      h("p", { class: "muted" }, paired
        ? "Each account (and each passphrase wallet) is paired on its own. On the phone, switch to it first (☰ → Accounts, or ☰ → Passphrase wallet), then read it here."
        : "This Mac remembers your phone's address and checks every signature against it. It never sees a key."),
      h("ol", { class: "steps" },
        h("li", { class: phone !== "none" ? "done" : "" }, paired ? "Plug in the vault, unlock it and switch to the account." : "Plug the vault into this Mac and unlock it."),
        h("li", null, "Read its address over USB."),
        h("li", null, "Compare it with the phone's screen, then pair."),
      ),
      state.pair.s === "idle" && state.pair.error ? h("p", { class: "inline-error" }, icon("alert", 15), explainPlain(state.pair.error)) : null,
      state.device.report?.verdict === "fail" ? verdictCard(state.device, () => identifyPhone()) : null,
      h("div", { class: "actions" },
        h("button", { class: "big primary", disabled: reading, onclick: readAddress }, reading ? h("i", { class: "mini-spin" }) : icon("phone", 18), reading ? "Asking the phone…" : "Read address from phone"),
      ),
      reading ? h("p", { class: "muted small center" }, "Unlock the phone if it asks. This takes a few seconds.") : null,
    );
  }
  return h("div", { class: "stack fade" }, paired ? topbar("Pairing", back) : null, body);
}

// ------------------------------------------------------------------ tools
//
// Message / EIP-712 signing (personal_sign, eth_signTypedData_v4) is self-contained in `signing.ts`,
// loaded when the tool is first opened.

function toolView() {
  const host = h("div", { class: "tool-host" }, h("div", { class: "boot" }, h("div", { class: "spinner" })));
  (async () => {
    try {
      const { mountSigning } = await import("./signing");
      host.replaceChildren();
      mountSigning(host);
    } catch (e) { host.replaceChildren(h("p", { class: "inline-error" }, icon("alert", 15), capitalize(errText(e)))); }
  })();
  return h("div", { class: "stack fade" }, topbar("Sign a message", () => go("home")), host);
}

// ------------------------------------------------------------------ boot

initIdentity({ renderHeader, render, renderSoon, go, openDrawer, renderDrawer, selectAccount, accountBusy });
initSend({ go, render, refreshHistory, refreshBalance });
initSettings({ refreshStatus, renderHeader, render, go, refreshBalance, selectAccount, accountBusy, selectBtc, btcNets, restartSetup: () => { setupStart(setupHost); go("setup"); } });
applyTheme();
if (!isTauri) document.body.append(h("span", { class: "preview-badge", title: "Running in a browser without Tauri: all data is fake" }, "PREVIEW DATA"));
renderHeader();
render();
mountWalletConnect({
  paired: () => state.status?.paired_checksum ?? null,
  rpcFor,
  phoneBlocked: () => state.device.report?.verdict === "fail" ? "This phone failed the genuine check (Settings → Device). Signing is blocked."
    : state.identity.s === "different" ? "The phone on USB is using an account this Mac hasn't paired. Pair it first (Settings → Phone)."
    : state.identity.s === "other" ? `The phone is using ${state.identity.label}, but this Mac shows ${activeLabel()}. Switch accounts on the phone or in Settings → Phone.`
    : state.identifying ? "Checking which wallet the phone holds. Try again in a moment."
    : state.view === "send" && ["connecting", "on_phone", "verifying"].includes(sendStage()) ? "The phone is busy with your Send. Finish it first." : null,
  changed: () => { if (state.view === "home") renderSoon(); if (state.drawerOpen && !drawer.contains(document.activeElement)) renderDrawer(); },
  sent: (chainId) => { refreshHistory(); refreshBalance(byId(chainId)); },
  openSettings: () => openDrawer(),
});
(async () => {
  await refreshStatus();
  await btcInit({
    net: () => prefs.btc ?? "bitcoin",
    showTestnets: () => prefs.btcTestnets,
    setShowTestnets: (on) => { prefs.btcTestnets = on; if (!on && prefs.btc && prefs.btc !== "bitcoin") prefs.btc = "bitcoin"; savePrefs(); render(); },
    price: () => prices.BTC ?? null,
    rerender: () => { if (state.view === "home") renderSoon(); },
    renderNow: () => { if (state.view === "home") render(); },
    topbar: (title, back) => topbar(title, back),
    networkSelect: () => networkSelect(),
    phoneBlocked: () => state.device.report?.verdict === "fail" ? "This phone failed the genuine check (Settings → Device). Signing is blocked." : null,
    phoneBusy: () => (state.view === "send" && ["connecting", "on_phone", "verifying"].includes(sendStage())) || wcPhoneBusy() || state.identifying,
  });
  render();
  // Preview only (no Tauri): ?open=drawer opens Settings, ?open=pair the pairing screen, ?open=btc
  // Bitcoin (with ?btc=0 its pairing screen), ?open=btcsettings the Bitcoin settings, for screenshots.
  if (!isTauri) {
    const o = new URLSearchParams(location.search).get("open");
    if (o === "drawer") openDrawer(); else if (o === "pair") { state.pair = { s: "idle" }; go("pair"); }
    else if (o === "btc") { prefs.btc = "bitcoin"; await reloadAccounts(); render(); }
    else if (o === "btcsettings") { prefs.btc = "bitcoin"; await reloadAccounts(); render(); openDrawer(); requestAnimationFrame(() => document.getElementById("btc-section")?.scrollIntoView({ block: "start" })); }
  }
  refreshHistory().then(pollPending);
  refreshPrices();
  setInterval(refreshStatus, STATUS_POLL_MS);
  pushWatchConfig();
  // The background watcher (Rust) reads balances, finds incoming transfers and settles pending
  // transactions on its own schedule and tells the UI; the preview has no watcher, so it polls.
  void onEvent<WatchBalance>("watch-balance", (b) => {
    const n = byId(b.chain_id); if (n.id !== b.chain_id || !state.status?.paired) return;
    if (b.owner && b.owner.toLowerCase() !== state.status.paired.toLowerCase()) return; // a reading for the previously shown account
    setBalance(n.id, BigInt(b.balance_wei), b.balance_eth);
    if (state.view === "home") renderSoon();
    if (state.view === "send" && sendStage() === "form") updateFormBalance();
    if (n.id === prefs.chainId) void refreshTokenBalances(n.id, rpcFor(n.id)).then(() => { if (state.view === "home") renderSoon(); });
  });
  void onEvent("history-changed", () => { void refreshHistory(); });
  if (!isTauri) {
    setInterval(() => { if (state.status?.paired) refreshBalance(net()); }, PREVIEW_BALANCE_POLL_MS);
    setInterval(() => { if (state.status?.paired) refreshAllBalances(); }, PREVIEW_ALL_BALANCES_POLL_MS);
  }
  setInterval(refreshPrices, PRICE_POLL_MS);
  setInterval(pollPending, PENDING_POLL_MS);
  setInterval(() => { if (state.view === "home") renderSoon(); }, RELATIVE_TIME_REFRESH_MS);
})();
