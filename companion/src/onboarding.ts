// Guided setup: a full-screen stepper for the first run (no pairing yet), re-runnable from
// Settings. 1 Plug in (live USB detection) → 2 Genuine? (device check, big verdict) → 3 Pair
// (compare the address with the phone's screen) → 4 Receive (QR, wait for a small test deposit)
// → 5 First send (optional) → done. Every state comes from the real app state (USB presence,
// the Rust device-check verdict, the pairing file, balances from the node); nothing is simulated.

import type { Attestation, HistoryEntry, Status } from "./api";
import { errText } from "./api";
import type { DeviceCheck } from "./attestation";
import { verdictLabel } from "./attestation";
import { NETWORKS, byId, type Network } from "./networks";
import { h, icon, padlock, grouped, short, fmtAmount, copy } from "./ui";
import { qrSvg } from "./qr";
import { fmtExact } from "./tokens";
import { backupCardPicker } from "./backup-card";

export interface SetupHost {
  status: () => Status | null;
  device: () => DeviceCheck;
  recheck: () => void;
  confirmPairing: (address: string) => Promise<void>;
  chainId: () => number;
  setChain: (id: number) => void;
  balanceOf: (id: number) => bigint | null;
  refreshBalance: (id: number) => void;
  history: () => HistoryEntry[];
  /** Leave setup: to the wallet, or into Send with a prefilled recipient. */
  finish: (then: "home" | { sendTo: string | null }) => void;
  rerender: () => void;
}

type Step = 0 | 1 | 2 | 3 | 4 | 5;
const LABELS = ["Plug in", "Genuine", "Pair", "Receive", "Send"];

interface S {
  step: Step;
  mismatch: boolean; pairing: boolean; pairError: string | null;
  /** step 4: balances when the step was entered, the time, and what arrived */
  baseline: Map<number, bigint>; since: number;
  arrived: { chainId: number; text: string; from: string | null } | null;
}
let s: S = fresh();
let poll = 0;
function fresh(): S { return { step: 0, mismatch: false, pairing: false, pairError: null, baseline: new Map(), since: 0, arrived: null }; }

export function setupStart(host: SetupHost) { s = fresh(); clearInterval(poll); advance(host); }
export const setupStep = () => s.step;

/** Move forward on its own when the real state allows it (phone plugged in; already paired). */
function advance(host: SetupHost) {
  const st = host.status();
  if (s.step === 0 && st && st.phone !== "none") s.step = 1;
}

function go(host: SetupHost, step: Step) {
  s.step = step;
  clearInterval(poll);
  if (step === 3) {
    s.since = Date.now() / 1000; s.arrived = null; s.baseline = new Map();
    for (const n of NETWORKS) { const b = host.balanceOf(n.id); if (b !== null) s.baseline.set(n.id, b); }
    // check the shown network often while waiting (the background watcher covers the rest)
    poll = window.setInterval(() => host.refreshBalance(host.chainId()), 6000);
    host.refreshBalance(host.chainId());
  }
  host.rerender();
}

/** Called by the app on every balance increase and history change. */
export function setupNoticeFunds(host: SetupHost, chainId: number | null, prevWei?: bigint) {
  if (s.step !== 3 || s.arrived) return;
  const st = host.status();
  // a transfer with a hash (token or ETH) recorded since the step started
  const e = host.history().find((x) => x.kind === "in" && x.time >= s.since - 5);
  if (e) {
    const n = byId(e.chain_id);
    s.arrived = { chainId: e.chain_id, text: e.token_symbol ? `${fmtExact(e.token_amount ?? "?")} ${e.token_symbol}` : `${fmtAmount(e.amount_eth, 8)} ${n.symbol}`, from: e.counterparty && e.counterparty.toLowerCase() !== st?.paired?.toLowerCase() ? e.counterparty : null };
  } else if (chainId !== null) {
    const now = host.balanceOf(chainId);
    // a network whose balance wasn't loaded when the step began: its previous reading is the baseline
    const before = s.baseline.get(chainId) ?? prevWei;
    if (now === null || before === undefined) return;
    if (now <= before) return;
    const d = now - before; const n = byId(chainId);
    const eth = `${d / 10n ** 18n}.${(d % 10n ** 18n).toString().padStart(18, "0")}`.replace(/\.?0+$/, "");
    s.arrived = { chainId, text: `${fmtAmount(eth, 8)} ${n.symbol}`, from: null };
  }
  if (s.arrived) { clearInterval(poll); host.rerender(); }
}

// ------------------------------------------------------------------ view

function stepper() {
  const at = Math.min(s.step, 4);
  return h("ol", { class: "stepper", "aria-label": "Setup progress" }, LABELS.map((label, i) =>
    h("li", { class: i < at || s.step === 5 ? "done" : i === at ? "now" : "" },
      h("span", { class: "bullet" }, i < at || s.step === 5 ? icon("check", 12) : String(i + 1)), h("span", { class: "lbl" }, label))));
}

function plugStep(host: SetupHost) {
  const phone = host.status()?.phone ?? "none";
  const found = phone !== "none";
  return h("section", { class: "card setup-card" },
    h("div", { class: `plug ${found ? "found" : "searching"}` }, h("div", { class: "phone-art" }, h("div", { class: "phone-screen" }, padlock(3)))),
    h("p", { class: "kicker" }, "STEP 1 OF 5"),
    h("h3", null, found ? "Phone found" : "Plug in your Phone Vault"),
    h("p", { class: "muted" }, found
      ? "Your phone is on USB. Next, this Mac checks that it really is Phone Vault hardware and firmware."
      : "Connect the phone to this Mac with a USB cable and unlock it. This screen notices it by itself."),
    !found ? h("span", { class: "wait-line" }, h("i", { class: "mini-spin" }), "Looking for a phone on USB…") : null,
    h("div", { class: "callout" },
      h("strong", null, "If nothing happens"),
      h("span", null, "Use a data cable (some only charge), try another port, and unplug and reconnect after the phone is unlocked. If you use Android tools on this Mac, run `adb kill-server` first: it holds the phone's USB connection.")),
    found ? h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => go(host, 1) }, "Continue")) : null,
  );
}

function verdictBig(c: DeviceCheck) {
  if (!c.report) {
    return h("div", { class: "verdict-big" },
      h("div", { class: "shield att-checking" }, c.checking ? h("i", { class: "spinner" }) : icon("shield", 40)),
      h("span", { class: "label muted" }, c.checking ? "CHECKING…" : "NOT CHECKED YET"));
  }
  const { label, cls } = verdictLabel(c.report);
  return h("div", { class: "verdict-big" }, h("div", { class: `shield ${cls}` }, icon(c.report.verdict === "fail" ? "alert" : "shield", 40)), h("span", { class: "label" }, label.toUpperCase()));
}

function genuineStep(host: SetupHost) {
  const c = host.device();
  const r: Attestation | null = c.report;
  const legend = h("div", { class: "compare-legend" },
    h("div", { class: "ok" }, h("strong", null, "Genuine"), "Locked Phone Vault firmware, the release-signed app, keys in the Titan M chip. Ready for real funds."),
    h("div", { class: "dev" }, h("strong", null, "Development"), "A phone someone flashed for testing (bootloader unlocked or development-signed app). Fine for small test amounts only."));
  const body: (Node | null)[] = [];
  if (!r) {
    body.push(h("p", { class: "muted" }, c.checking ? "The phone is proving, with a fresh challenge from this Mac, that its keys are in secure hardware and it runs Phone Vault firmware and app. Unlock the phone if it asks." : c.error ? c.error : "Waiting for the phone…"));
    if (!c.checking) body.push(h("div", { class: "actions" }, h("button", { class: "big primary", onclick: host.recheck }, icon("refresh", 18), "Check now")));
  } else if (r.verdict === "fail") {
    body.push(
      h("h3", null, "This phone is not genuine"),
      r.problems.length ? h("ul", { class: "att-reasons", style: "text-align:left" }, r.problems.map((p) => h("li", null, p))) : null,
      h("div", { class: "callout", style: "border-color:color-mix(in srgb, var(--danger) 45%, transparent)" },
        h("strong", null, "Stop here: don't put funds on this phone"),
        h("span", null, "It could not prove it is Phone Vault hardware running Phone Vault's firmware and app, so a modified phone could show you one thing and sign another."),
        h("span", null, "If someone sold you this phone already set up, don't use it. Flash it yourself from phonevault.org, then plug it in again.")),
      h("div", { class: "actions" }, h("button", { class: "big", onclick: host.recheck, disabled: c.checking }, icon("refresh", 18), c.checking ? "Checking…" : "Check again")),
    );
  } else {
    body.push(
      h("h3", null, r.verdict === "genuine" ? "Genuine Phone Vault" : "Development phone"),
      h("p", { class: "muted" }, r.verdict === "genuine" ? "Google's attestation proves the keys are in the Titan M, the app is Phone Vault's, and the phone booted locked Phone Vault firmware."
        : "It passed as a development phone. Use it only with amounts you can afford to lose: an unlocked phone's software above the security chip could be modified."),
      legend,
      h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => go(host, 2) }, "Continue")),
    );
  }
  return h("section", { class: "card setup-card" },
    verdictBig(c),
    h("p", { class: "kicker" }, "STEP 2 OF 5 · IS IT GENUINE?"),
    ...body,
    !r ? legend : null,
  );
}

function pairStep(host: SetupHost) {
  const st = host.status();
  const r = host.device().report;
  const address = r?.address ?? null;
  if (!address || !r || r.verdict === "fail") return genuineStep(host);
  const already = !!st?.paired && st.paired.toLowerCase() === address.toLowerCase();
  if (s.mismatch) return h("section", { class: "card setup-card danger-card" },
    h("p", { class: "kicker danger" }, "NOT PAIRED"),
    h("h3", null, "Stop here"),
    h("p", null, "If the phone shows a different address, something between this Mac and the phone is changing data. Nothing was saved. Try another cable and port, and don't send funds until the addresses match."),
    h("div", { class: "actions" }, h("button", { class: "big", onclick: () => { s.mismatch = false; host.recheck(); go(host, 1); } }, "Start over")));
  return h("section", { class: "card setup-card" },
    h("p", { class: "kicker" }, "STEP 3 OF 5 · PAIR"),
    h("h3", null, already ? "Already paired with this phone" : "Does this match your phone?"),
    h("p", { class: "muted" }, already ? "This Mac already checks every signature against this address." : "On the phone, open Wallet. Compare every group of four characters below with the address it shows."),
    h("p", { class: "addr-compare mono" }, grouped(address)),
    s.pairError ? h("p", { class: "inline-error" }, icon("alert", 15), s.pairError) : null,
    already ? h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => go(host, 3) }, "Continue"))
      : h("div", { class: "actions" },
        h("button", { class: "big primary", disabled: s.pairing, onclick: async () => {
          s.pairing = true; s.pairError = null; host.rerender();
          try { await host.confirmPairing(address); s.pairing = false; go(host, 3); }
          catch (e) { s.pairing = false; s.pairError = errText(e); host.rerender(); }
        } }, s.pairing ? h("i", { class: "mini-spin" }) : icon("check", 18), "It matches"),
        h("button", { class: "big", onclick: () => { s.mismatch = true; host.rerender(); } }, "It doesn't")),
    h("p", { class: "muted small" }, "Only the address is stored on this Mac. It never sees a key."),
  );
}

function confetti() {
  const colors = ["var(--accent)", "#1f5eff", "var(--warn)", "#ff2a3a", "#8a52e8"];
  return h("div", { class: "confetti", "aria-hidden": "true" }, Array.from({ length: 28 }, (_, i) =>
    h("i", { style: `left:${(i * 37) % 100}%;background:${colors[i % colors.length]};animation-delay:${(i % 7) * 60}ms` })));
}

function receiveStep(host: SetupHost) {
  const st = host.status();
  const addr = st?.paired_checksum ?? "";
  const n: Network = byId(host.chainId());
  if (s.arrived) {
    const an = byId(s.arrived.chainId);
    return h("section", { class: "card setup-card celebrate" }, confetti(),
      h("div", { class: "result-ic ok big" }, icon("check", 32)),
      h("p", { class: "kicker" }, "STEP 4 OF 5 · IT ARRIVED"),
      h("h3", null, `${s.arrived.text} received`),
      h("p", { class: "muted" }, `Your wallet on ${an.name} received it${s.arrived.from ? ` from ${short(s.arrived.from)}` : ""}. You'll get a notification like this whenever funds arrive, even with the window closed.`),
      h("div", { class: "actions" },
        h("button", { class: "big primary", onclick: () => go(host, 4) }, "Next: try a send"),
        h("button", { class: "big", onclick: () => go(host, 5) }, "Skip")));
  }
  const sel = h("select", { class: "net-select", "aria-label": "Network" }, NETWORKS.map((x) => h("option", { value: x.id, selected: x.id === n.id }, x.testnet ? `${x.name} (testnet)` : x.name)));
  sel.addEventListener("change", () => { host.setChain(Number(sel.value)); go(host, 3); });
  return h("section", { class: "card setup-card" },
    h("p", { class: "kicker" }, "STEP 4 OF 5 · RECEIVE"),
    h("h3", null, "Send a small test amount"),
    h("p", { class: "muted" }, `From an exchange or another wallet, send a small amount to this address on ${n.name}. Before sharing it for anything larger, compare it with the Wallet screen on your phone.`),
    h("label", { class: "net-chip" }, h("i", { class: `net-dot n${n.id}` }), h("span", null, n.name), icon("chevron", 14), sel),
    h("div", { class: "qr-tile" }, h("div", { class: "qr", html: qrSvg(addr, { dark: "#060608", light: "#ffffff", label: `QR code for ${addr}` }) })),
    h("button", { class: "addr-full", onclick: () => copy(addr), title: "Click to copy" }, h("span", { class: "mono" }, grouped(addr)), icon("copy", 16)),
    h("span", { class: "wait-line" }, h("i", { class: "mini-spin" }), `Waiting for a deposit on ${n.name}… this updates by itself`),
    h("div", { class: "actions" }, h("button", { class: "big", onclick: () => go(host, 4) }, "Skip for now")),
  );
}

function sendStep(host: SetupHost) {
  const back = s.arrived?.from ?? null;
  return h("section", { class: "card setup-card" },
    h("div", { class: "pair-hero" }, padlock(5)),
    h("p", { class: "kicker" }, "STEP 5 OF 5 · FIRST SEND (OPTIONAL)"),
    h("h3", null, "Send a little back"),
    h("p", { class: "muted" }, back ? `Send a small amount back to ${short(back)} to see the whole path: this Mac quotes it, your phone shows it and you approve there, this Mac checks the signature, then you press Broadcast.`
      : "Send a small amount to an address you control to see the whole path: this Mac quotes it, your phone shows it and you approve there, this Mac checks the signature, then you press Broadcast."),
    h("dl", { class: "facts" },
      h("div", { class: "fact" }, h("dt", null, "On the phone"), h("dd", null, "Check the amount, recipient, network and fee, then Approve & sign")),
      h("div", { class: "fact" }, h("dt", null, "On this Mac"), h("dd", null, "Nothing is sent until you press Broadcast"))),
    h("div", { class: "actions" },
      h("button", { class: "big primary", onclick: () => host.finish({ sendTo: back }) }, icon("up", 18), "Start a send"),
      h("button", { class: "big", onclick: () => go(host, 5) }, "Skip")),
  );
}

function doneStep(host: SetupHost) {
  return h("section", { class: "card setup-card celebrate" }, confetti(),
    h("div", { class: "result-ic ok big" }, icon("check", 32)),
    h("h3", null, "You're set"),
    h("ul", { class: "verified", style: "text-align:left" },
      h("li", null, icon("check", 14), "This Mac is paired with your phone and checks every signature against it"),
      h("li", null, icon("check", 14), "Notifications tell you when funds arrive; Phone Vault keeps watching from the menu bar when the window is closed"),
      h("li", null, icon("check", 14), "Stuck transaction? Activity → Speed up or Cancel")),
    h("div", { class: "callout" },
      h("strong", null, "Back up on paper"),
      h("span", null, "Print a blank backup card and copy your 24 words onto it by hand from the phone (Security → Show recovery phrase). Two copies, separate places, never photographed. Settings → Backup has it later too."),
      backupCardPicker()),
    h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => host.finish("home") }, "Open my wallet")),
  );
}

export function setupView(host: SetupHost): HTMLElement {
  advance(host);
  const paired = !!host.status()?.paired;
  const body = s.step === 0 ? plugStep(host) : s.step === 1 ? genuineStep(host) : s.step === 2 ? pairStep(host) : s.step === 3 ? receiveStep(host) : s.step === 4 ? sendStep(host) : doneStep(host);
  return h("div", { class: "setup fade" },
    h("div", { class: "topbar" }, h("span", { class: "icon-btn ghosted" }), h("h2", null, "Set up Phone Vault"), h("span", { class: "icon-btn ghosted" })),
    s.step < 5 ? stepper() : null,
    body,
    h("div", { class: "setup-foot" },
      h("span", null, paired ? "Paired. You can finish the rest later." : "About 3 minutes. Nothing leaves this Mac but public addresses."),
      paired && s.step < 5 ? h("button", { class: "ghost", onclick: () => host.finish("home") }, "Skip setup") : null),
  );
}
