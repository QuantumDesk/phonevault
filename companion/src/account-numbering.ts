// "Find accounts from another wallet" (Settings → Phone, and once on Home after pairing): which
// account numbering holds the funds of someone who comes from Ledger Live or another wallet.
// The Mac asks the phone for the first 5 addresses under each numbering (the phone asks the user
// to share them), Rust checks every address and the pairing pin, reads balances from the user's
// own nodes, and says what to do (numbering.rs). The phone decides: this Mac never changes the
// numbering, and "it switched" is believed only when the phone's getAddress says so.

import { api, call, registerPreview, errText } from "./api";
import { h, icon, short, copy } from "./ui";

export type Scheme = "standard" | "ledger-live";
export type Advice = "switch_to_ledger_live" | "switch_to_standard" | "already_ledger_live" | "already_standard" | "both" | "only_account1" | "no_funds";
export interface Holding { chain_id: number; network: string; symbol: string; amount: string }
export interface AccountFunds { account: number; path: string; address: string; holdings: Holding[] }
export interface NumberingScan { current: Scheme; standard: AccountFunds[]; ledger_live: AccountFunds[]; advice: Advice; message: string; complete: boolean; errors: string[] }

const NAME: Record<Scheme, string> = { "standard": "Standard", "ledger-live": "Ledger Live" };
/** The numbering the advice asks the user to switch the phone to, if any. */
const target = (a: Advice): Scheme | null => a === "switch_to_ledger_live" ? "ledger-live" : a === "switch_to_standard" ? "standard" : null;

type Phase =
  | { s: "idle" }
  | { s: "scanning" }
  | { s: "done"; r: NumberingScan; check?: { s: "checking" } | { s: "result"; ok: boolean; text: string } }
  | { s: "error"; message: string };
let phase: Phase = { s: "idle" };
let redraw: () => void = () => {};
/** Set after a pairing: Home offers the scan once. */
let offerOnHome = false;

/** Call after a phone account was paired: Home shows the offer until it is used or dismissed. */
export function offerNumberingScan() { offerOnHome = true; }

async function runScan() {
  if (phase.s === "scanning") return;
  phase = { s: "scanning" }; redraw();
  try { phase = { s: "done", r: await call<NumberingScan>("numbering_scan") }; }
  catch (e) { phase = { s: "error", message: errText(e) }; }
  redraw();
}

/** "I switched it": ask the phone (getAddress) which numbering it uses now. Nothing is assumed. */
async function checkSwitch(want: Scheme) {
  if (phase.s !== "done") return;
  const done = phase;
  done.check = { s: "checking" }; redraw();
  try {
    const now: Scheme = (await api.readAddress()).scheme ?? "standard";
    done.check = now === want
      ? { s: "result", ok: true, text: `Your phone now uses ${NAME[want]} account numbering. Pair the accounts you use (Settings → Pair another account).` }
      : { s: "result", ok: false, text: `Your phone still uses ${NAME[now]} account numbering. Switch it on the phone (Settings → Accounts → Account numbering), then check again.` };
  } catch (e) { done.check = { s: "result", ok: false, text: errText(e) }; }
  redraw();
}

function accountRows(list: AccountFunds[]): HTMLElement {
  return h("div", { class: "att-details" }, list.map((a) => h("div", { class: "set-row" },
    h("span", { class: "muted" }, `Account ${a.account}`, h("br"), h("span", { class: "mono small" }, a.path)),
    h("span", { class: "att-val" },
      h("button", { class: "link mono small", title: a.address, onclick: () => copy(a.address) }, short(a.address), icon("copy", 12)),
      h("br"),
      a.holdings.length ? a.holdings.map((x, i) => [i ? h("br") : null, `${x.amount} ${x.symbol} · ${x.network}`]) : h("span", { class: "muted small" }, "empty")))));
}

/** The body: button, progress, result. Shared by the Settings section and the Home card. */
function panel(): HTMLElement {
  const box = h("div", { class: "stack" });
  if (phase.s === "scanning") {
    box.append(h("p", { class: "muted small" }, "On your phone: approve \"Share 5 addresses with your Mac?\" twice (Standard, then Ledger Live). Then balances are read from your nodes…"));
  } else if (phase.s === "error") {
    box.append(h("p", { class: "field-msg bad" }, phase.message));
  } else if (phase.s === "done") {
    const r = phase.r;
    const want = target(r.advice);
    box.append(
      h("div", { class: `callout${want ? " accent" : ""}` }, icon(want ? "alert" : "check", 16), h("span", null, r.message)),
      h("p", { class: "muted small" }, `Your phone uses ${NAME[r.current]} account numbering (as it reported just now).`),
      h("h4", null, "STANDARD · m/44'/60'/0'/0/n"), accountRows(r.standard),
      h("h4", null, "LEDGER LIVE · m/44'/60'/n'/0/0"), accountRows(r.ledger_live),
    );
    if (r.errors.length) box.append(h("p", { class: "muted small" }, "Not read: ", r.errors.join("; ")));
    if (want) {
      const c = phase.check;
      box.append(h("div", { class: "row gap" }, h("button", { disabled: c?.s === "checking", onclick: () => void checkSwitch(want) }, c?.s === "checking" ? "Asking the phone…" : "I switched it on the phone · check")));
      if (c?.s === "result") box.append(h("p", { class: `field-msg ${c.ok ? "ok" : "bad"}` }, c.text));
    }
  }
  box.append(h("div", { class: "row gap" }, h("button", { disabled: phase.s === "scanning", onclick: () => void runScan() },
    icon("refresh", 15), phase.s === "idle" ? "Find accounts" : phase.s === "scanning" ? "Waiting for the phone…" : "Check again")));
  return box;
}

const INTRO = "Came from Ledger Live or another wallet with the same recovery phrase? Your Mac asks the phone for the first 5 addresses under each account numbering (you approve on the phone) and reads their balances from your nodes. Nothing changes on the phone unless you switch it there.";

/** Settings → Phone → "Find accounts from another wallet". */
export function numberingSection(rerender: () => void): HTMLElement {
  redraw = rerender;
  return h("section", { class: "set", id: "numbering-section" },
    h("h4", null, "FIND ACCOUNTS FROM ANOTHER WALLET"),
    h("p", { class: "muted small" }, INTRO),
    panel(),
  );
}

/** Home, once after pairing (null otherwise). */
export function numberingHomeSlot(rerender: () => void): HTMLElement | null {
  if (!offerOnHome) return null;
  redraw = rerender;
  return h("section", { class: "card" },
    h("div", { class: "row between" }, h("h3", null, "Find accounts from another wallet"),
      h("button", { class: "icon-btn", "aria-label": "Dismiss", onclick: () => { offerOnHome = false; rerender(); } }, icon("close", 16))),
    h("p", { class: "muted" }, INTRO),
    panel(),
  );
}

// ---------------------------------------------------------------- browser preview (no Tauri)
// ?numbering=ledger|standard|both|none|declined picks the mock phone's answer.
registerPreview((cmd) => cmd === "numbering_scan", async () => async () => {
  await new Promise((r) => setTimeout(r, 1500));
  const kind = new URLSearchParams(location.search).get("numbering") ?? "ledger";
  if (kind === "declined") throw "You chose not to share the addresses on the phone. Nothing was checked.";
  const std = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0", "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A", "0xF3f50213C1d2e255e4B2bAD430F8A38EEF8D718E", "0x51cA8ff9f1C0a99f88E86B8112eA3237F55374cA"];
  const ll = ["0x9858EfFD232B4033E47d90003D41EC34EcaEda94", "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265", "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231", "0x8559A4270Db933caC30830f2be9D099fD477A51D", "0xB9506F020318c2ECA294e0557222511f1e5333CB"];
  const eth = (amount: string): Holding => ({ chain_id: 1, network: "Ethereum", symbol: "ETH", amount });
  const usdc = (amount: string): Holding => ({ chain_id: 8453, network: "Base", symbol: "USDC", amount });
  const fundStd = kind === "standard" || kind === "both", fundLl = kind === "ledger" || kind === "both";
  const rows = (list: string[], scheme: Scheme, funded: boolean): AccountFunds[] => list.map((address, i) => ({
    account: i + 1, path: scheme === "standard" ? `m/44'/60'/0'/0/${i}` : `m/44'/60'/${i}'/0/0`, address,
    holdings: i === 0 ? [eth("0.0123")] : funded && i < 3 ? [eth(`0.${i}5`), usdc(`${i * 100}`)] : [],
  }));
  const advice: Advice = kind === "ledger" ? "switch_to_ledger_live" : kind === "standard" ? "already_standard" : kind === "both" ? "both" : "only_account1";
  const message: Record<Advice, string> = {
    switch_to_ledger_live: "Your funds are on Ledger Live accounts. Switch account numbering on your phone: Settings → Accounts → Account numbering.",
    switch_to_standard: "", already_ledger_live: "",
    already_standard: "Your funds are on Standard accounts, which your phone already uses. Nothing to change.",
    both: "There are funds under both numberings. Your phone shows one numbering at a time: switch it to reach the other accounts (Settings → Accounts → Account numbering).",
    only_account1: "Only Account 1 holds funds, and it is the same under both numberings. Nothing to change.",
    no_funds: "",
  };
  const r: NumberingScan = { current: "standard", standard: rows(std, "standard", fundStd), ledger_live: rows(ll, "ledger-live", fundLl), advice, message: message[advice], complete: true, errors: [] };
  return r;
});
