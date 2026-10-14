// The phone on USB: which wallet it holds (phone identity) and whether it is genuine (device check),
// plus the notices that follow from them (failed check, another paired account, an unpaired one).

import { api, errText } from "./api";
import type { Attestation } from "./api";
import { verdictCard } from "./attestation";
import { h, icon, short } from "./ui";
import { explainPlain } from "./errors";
import { wcPhoneBusy } from "./walletconnect";
import { state, activeLabel, pairedAccounts, type Identity, type View } from "./state";

/** What identity.ts needs from the shell (main.ts) and the settings drawer (settings.ts). */
export interface IdentityHost {
  renderHeader(): void;
  render(): void;
  renderSoon(): void;
  go(v: View): void;
  openDrawer(): void;
  renderDrawer(): void;
  selectAccount(address: string): Promise<void>;
  /** a Send is past its form (the phone is or may be busy with it) */
  accountBusy(): boolean;
}
let host: IdentityHost;

export function initIdentity(h0: IdentityHost) {
  host = h0;
  void api.developerMode().then((on) => { state.devMode = on; if (state.drawerOpen) host.renderDrawer(); }).catch(() => { /* off */ });
}

// ------------------------------------------------------------------ phone identity
// When a phone appears, ask it which wallet it holds and compare with the pairing, so a reset,
// restored or swapped phone is noticed at once instead of at signing time. Pairing itself still
// ends with the person comparing the address against the phone's own screen.

/** Where the phone's account stands against this Mac: the one shown, another paired one, or unpaired. */
export function classifyPhone(address: string): Identity {
  if (!state.status?.paired) return { s: "unknown" };
  if (address.toLowerCase() === state.status.paired.toLowerCase()) return { s: "match" };
  const other = pairedAccounts().find((a) => a.address.toLowerCase() === address.toLowerCase());
  return other ? { s: "other", address, label: other.label, dismissed: false } : { s: "different", address, dismissed: false };
}

/** Read fresh each time: status changes while a request is in flight. */
const phonePresent = (): boolean => (state.status?.phone ?? "none") !== "none";
export async function identifyPhone() {
  if (state.identifying || state.pair.s === "reading" || !state.status || state.status.phone === "none") return;
  if (host.accountBusy()) { setTimeout(identifyPhone, 5000); return; } // never talk over a send
  if (wcPhoneBusy()) { setTimeout(identifyPhone, 5000); return; } // nor over a WalletConnect request
  state.identifying = true;
  // A locked phone holds the request on its lock screen and answers after unlock; keep the
  // "Unlock your phone" label steady while asking again rather than flickering to "Checking".
  if (state.identity.s !== "unreadable") { state.identity = { s: "checking" }; host.renderHeader(); }
  try {
    const report = await checkDevice();
    const address = report.address;
    state.phoneAddress = address;
    if (!address) { state.identity = { s: "unknown" }; } // refused without naming a wallet (e.g. an app too old to attest); the badge says why
    else if (!state.status?.paired) { state.identity = { s: "unknown" }; if (state.view === "setup") host.render(); else { state.pair = { s: "compare", address }; host.go("pair"); } }
    else state.identity = classifyPhone(address);
  } catch (e) { state.identity = { s: "unreadable", error: errText(e) }; }
  finally { state.identifying = false; }
  host.renderHeader(); renderPhoneNotice();
  if (state.identity.s === "unreadable" && phonePresent()) setTimeout(identifyPhone, 2000);
}

let noticeEl: HTMLElement | null = null;
let noticeKey = "";
export function renderPhoneNotice() {
  // Re-render the same notice in place without replaying its entrance animation.
  const key = state.device.report?.verdict === "fail" && !state.failDismissed && state.view !== "pair" && state.view !== "setup"
    ? `fail:${state.device.report?.headline ?? ""}`
    : state.identity.s === "different" && !state.identity.dismissed && state.view !== "pair" ? `diff:${state.identity.address}` : "";
  const replaying = !!noticeEl && key !== "" && key === noticeKey;
  noticeKey = key;
  noticeEl?.remove(); noticeEl = null;
  if (replaying) queueMicrotask(() => noticeEl?.classList.remove("fade"));
  if (state.device.report?.verdict === "fail" && !state.failDismissed && state.view !== "pair" && state.view !== "setup") {
    const close = () => { state.failDismissed = true; renderPhoneNotice(); };
    noticeEl = h("div", { class: "modal-scrim fade", onclick: (e: Event) => { if (e.target === noticeEl) close(); } },
      h("div", { class: "modal", role: "dialog", "aria-modal": "true" },
        verdictCard(state.device, () => identifyPhone()),
        h("div", { class: "actions" },
          h("button", { class: "big", onclick: () => { close(); openDeviceSettings(); } }, icon("shield", 18), "Details"),
          h("button", { class: "big", onclick: close }, "Close"),
        ),
      ));
    document.body.append(noticeEl);
    return;
  }
  if (state.identity.s === "other" && !state.identity.dismissed && state.view !== "pair" && state.view !== "setup") {
    const { address, label } = state.identity;
    const close = () => { if (state.identity.s === "other") state.identity.dismissed = true; renderPhoneNotice(); };
    noticeEl = h("div", { class: "modal-scrim fade", onclick: (e: Event) => { if (e.target === noticeEl) close(); } },
      h("section", { class: "card modal", role: "dialog", "aria-modal": "true" },
        h("p", { class: "kicker" }, "Other account on the phone"),
        h("h3", null, `The phone is using ${label}`),
        h("p", { class: "muted" }, `This Mac shows ${activeLabel()}. Requests from this Mac are pinned to the account it shows, and the phone refuses a request for an account that is not active on it. Show ${label} here, or switch accounts on the phone (☰ → Accounts).`),
        h("div", { class: "set-row" }, h("span", { class: "muted" }, "This Mac shows"), h("span", { class: "mono" }, `${activeLabel()} · ${short(state.status?.paired_checksum ?? "")}`)),
        h("div", { class: "set-row" }, h("span", { class: "muted" }, "Phone is on"), h("span", { class: "mono" }, `${label} · ${short(address)}`)),
        h("div", { class: "actions" },
          h("button", { class: "big primary", disabled: host.accountBusy(), onclick: () => { noticeEl?.remove(); noticeEl = null; void host.selectAccount(address); } }, icon("check", 18), `Show ${label} here`),
          h("button", { class: "big", onclick: close }, "Not now"),
        ),
      ));
    document.body.append(noticeEl);
    return;
  }
  if (state.identity.s !== "different" || state.identity.dismissed || state.view === "pair" || state.view === "setup") return;
  const found = state.identity.address;
  const close = () => { if (state.identity.s === "different") state.identity.dismissed = true; renderPhoneNotice(); };
  noticeEl = h("div", { class: "modal-scrim fade", onclick: (e: Event) => { if (e.target === noticeEl) close(); } },
    h("section", { class: "card modal", role: "dialog", "aria-modal": "true" },
      h("p", { class: "kicker" }, "Unpaired account on USB"),
      h("h3", null, "The phone is using an account this Mac hasn't paired"),
      h("p", { class: "muted" }, "That happens when you switch to a new account or a passphrase wallet on the phone, after the phone was reset or restored, or with a different phone. Sending from it stays blocked until you pair it; your other paired accounts stay as they are."),
      h("div", { class: "set-row" }, h("span", { class: "muted" }, "Paired with"), h("span", { class: "mono" }, short(state.status?.paired_checksum ?? ""))),
      h("div", { class: "set-row" }, h("span", { class: "muted" }, "Phone on USB"), h("span", { class: "mono" }, short(found))),
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => { noticeEl?.remove(); noticeEl = null; state.identity = { s: "unknown" }; state.pair = { s: "compare", address: found }; host.go("pair"); } }, icon("phone", 18), "Pair this account"),
        h("button", { class: "big", onclick: close }, "Not now"),
      ),
    ));
  document.body.append(noticeEl);
}

export async function readAddress() {
  state.pair = { s: "reading" }; host.render();
  try {
    const r = await checkDevice();
    state.pair = r.address ? { s: "compare", address: r.address } : { s: "idle", error: r.problems[0] ?? "The phone did not say which wallet it holds." };
  } catch (e) { state.pair = { s: "idle", error: errText(e) }; }
  if (state.view === "pair") host.render();
}

// ------------------------------------------------------------------ device check (attestation)
// Run on every identify/pair and (in Rust) before every send; cached per USB connection there.

async function checkDevice(): Promise<Attestation> {
  state.device = { ...state.device, checking: true, error: null };
  host.renderHeader(); if (state.drawerOpen) host.renderDrawer();
  try {
    const r = await api.attest();
    state.device = { report: r, checking: false, error: null };
    if (r.verdict !== "fail") state.failDismissed = false;
    return r;
  } catch (e) {
    state.device = { ...state.device, checking: false, error: explainPlain(errText(e)) };
    throw e;
  } finally {
    host.renderHeader(); if (state.drawerOpen) host.renderDrawer(); if (state.view === "pair" || state.view === "setup") host.render(); else if (state.view === "home") host.renderSoon();
    renderPhoneNotice();
  }
}

/** After a blocked send the Rust side holds the newest verdict; show it. */
export async function refreshCachedDevice() {
  try { const r = await api.attestationCached(); if (r) { state.device = { report: r, checking: false, error: null }; host.renderHeader(); renderPhoneNotice(); } } catch { /* the badge keeps the last one */ }
}

export function openDeviceSettings() {
  host.openDrawer();
  requestAnimationFrame(() => document.getElementById("device-section")?.scrollIntoView({ block: "start", behavior: "smooth" }));
}
