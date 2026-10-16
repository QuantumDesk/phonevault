// Bitcoin send flow: form → quote → review → phone → verify → broadcast → confirmations, and
// speed-up (RBF) of a stuck transaction. Every state is entered only from a real command result
// or a `send-progress` event carrying this attempt's ticket, exactly like the EVM send.

import { onProgress, openExternal, errText, REVIEW_LIMIT_MS } from "./api";
import type { SendError } from "./api";
import { h, icon, padlock, short, copy, toast, capitalize, fact, statusCard } from "./ui";
import { stepper, clockLine, clockTicker, cancelButton } from "./send-flow";
import { explainSendError, asSendError } from "./errors";
import { btcState, btcApi, wallets, go, btcNet, btcKind, fmtBtc, fmtSats, usd, groupedBtc, btcToSats, satsToBtcStr } from "./bitcoin-core";
import type { BtcAccount, BtcHistory, BtcQuote, Fees, AddrCheck, Signed } from "./bitcoin-core";

/** What the send flow needs from the Bitcoin screens (bitcoin.ts). */
export interface BtcSendHost {
  loadWallet(id: string): Promise<void>;
  refreshBtc(id: string, full?: boolean): Promise<void>;
}
let sendHost: BtcSendHost;

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

export const btcSendBusy = () => btcState.sub === "send" && !["form", "quoting", "review", "failed", "signed", "broadcast_failed", "bump_failed"].includes(flow.s);

function setFlow(f: Flow) {
  flow = f;
  tickFor(f.s);
  if (btcState.sub === "send") btcState.host.renderNow();
}

export function startSend(a: BtcAccount) {
  const blocked = btcState.host.phoneBlocked();
  if (blocked) { toast(blocked); return; }
  flow = { s: "form" }; formError = null; activeTicket = null; addr = null; draft.bumpOf = null;
  go("send");
  void loadFees(a);
}

async function loadFees(a: BtcAccount) {
  try { fees = await btcApi.fees(a.id); } catch (e) { fees = null; formError = `Fee estimates unavailable (${errText(e)}). Enter a custom fee rate.`; draft.fee = "custom"; }
  if (btcState.sub === "send" && flow.s === "form") btcState.host.renderNow();
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
  const p = btcState.host.price(); const usdV = Number(v);
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

export function sendView(a: BtcAccount) {
  const n = btcNet(a.network);
  const back = btcSendBusy() ? null : () => { if (flow.s === "review" && !draft.bumpOf) setFlow({ s: "form" }); else { flow = { s: "form" }; go("home"); } };
  return h("div", { class: "stack fade" },
    btcState.host.topbar(draft.bumpOf ? "Speed up" : `Send ${n.unit === "BTC" ? "bitcoin" : n.unit}`, back),
    stepper(stepOf(flow), flow.s === "submitted" && flow.confs > 0, flow.s === "failed" || flow.s === "broadcast_failed"),
    h("div", { class: "flow-body", "aria-live": "polite" }, flowBody(a)),
  );
}

function flowBody(a: BtcAccount): Node {
  const n = btcNet(a.network);
  const $ = (sats: number) => usd(sats, btcState.host.price(), n.test);
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
        // the fee is checked by the quote; the amount alone can't be more than the balance
        const held = w ? w.confirmed_sats + w.unconfirmed_sats : null;
        const over = !draft.max && !!btc && held !== null && btcToSats(btc)! > held;
        if (draft.max) amtMsg.textContent = "Everything this account holds, minus the fee. No change output.";
        else if (over) amtMsg.textContent = `More than this account holds: ${fmtBtc(held!)} ${n.unit} available`;
        else if (btc) { const s = btcToSats(btc)!; amtMsg.textContent = [draft.unit !== "BTC" ? `${btc} ${n.unit}` : null, draft.unit !== "sats" ? fmtSats(s) : null, draft.unit !== "USD" ? $(s) : null].filter(Boolean).join(" · "); }
        else amtMsg.textContent = draft.amount ? (draft.unit === "USD" && !btcState.host.price() ? "No USD price right now" : "Not a valid amount") : "";
        amtMsg.className = `field-msg${(draft.amount && !btc && !draft.max) || over ? " bad" : ""}`;
        goBtn.disabled = quoting || over || !(addr?.ok && (draft.max || btc) && rateOf());
        goBtn.title = over ? amtMsg.textContent ?? "" : "";
      };
      const check = async () => {
        const v = draft.to.trim(); addr = null;
        if (!v) { toMsg.textContent = ""; sync(); return; }
        const seq = ++addrSeq;
        try {
          const r = await btcApi.checkAddress(a.id, v);
          if (seq !== addrSeq) return;
          addr = r;
          if (!r.ok && incomplete(v)) { toMsg.textContent = "Address incomplete: keep typing or paste the whole address"; toMsg.className = "field-msg"; }
          else if (!r.ok) { toMsg.textContent = r.error ?? "Not a valid address"; toMsg.className = "field-msg bad"; }
          else if (r.own) { toMsg.textContent = "This is one of your own addresses (this account). The coins would stay with you, minus the fee."; toMsg.className = "field-msg warn"; }
          else { toMsg.replaceChildren(icon("check", 13), ` Valid ${n.name} address${r.kind ? ` · ${r.kind}` : ""} · checksum OK`); toMsg.className = "field-msg ok"; }
        } catch { addr = null; }
        sync();
      };
      toInput.addEventListener("input", () => { draft.to = toInput.value; void check(); });
      amtInput.addEventListener("input", () => { draft.amount = amtInput.value.replace(",", "."); sync(); });
      const unitSeg = h("div", { class: "segmented unit-seg" }, (["BTC", "sats", "USD"] as Unit[]).map((u) => h("button", { type: "button", class: draft.unit === u ? "on" : "", disabled: n.test && u === "USD",
        onclick: () => { const btc = amountBtc(); draft.unit = u; if (btc) { const s = btcToSats(btc)!; draft.amount = u === "BTC" ? btc : u === "sats" ? String(s) : btcState.host.price() ? ((s / 1e8) * btcState.host.price()!).toFixed(2) : ""; } btcState.host.renderNow(); } }, u === "BTC" ? n.unit : u)));
      const maxBtn = h("button", { class: `chip-btn${draft.max ? " on" : ""}`, type: "button", disabled: quoting, onclick: () => { draft.max = !draft.max; btcState.host.renderNow(); } }, "Max");
      const feeBtn = (k: "slow" | "normal" | "fast", label: string, eta: string) => {
        const r = fees ? fees[k] : null;
        const vb = btcKind(a.kind).vbytes; // a typical 1-input, 2-output send
        return h("button", { type: "button", class: `fee-opt${draft.fee === k ? " on" : ""}`, disabled: !fees, onclick: () => { draft.fee = k; btcState.host.renderNow(); } },
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
      const bx = flow.s === "broadcast_failed" ? { ...explainBroadcast(flow.message), message: flow.message } : null;
      return h("section", { class: "card result" },
        h("div", { class: "result-ic ok" }, icon("check", 28)),
        q.replaces ? h("p", { class: "kicker" }, "Replaces ", h("span", { class: "kicker-hash mono" }, short(q.replaces))) : null,
        h("h3", null, "Signed and verified"),
        h("ul", { class: "verified" }, s.checks.map((c) => h("li", null, icon("check", 14), c))),
        h("dl", { class: "facts" },
          fact("Send", h("span", null, `${fmtBtc(s.amount_sats)} ${n.unit}`, $(s.amount_sats) ? h("span", { class: "muted" }, ` · ${$(s.amount_sats)}`) : null)),
          fact("To", h("span", { class: "mono" }, short(s.recipient))),
          fact("Fee", `${fmtSats(s.fee_sats)} · ${s.rate} sat/vB · ${s.vsize} vB`),
          fact("Transaction ID", h("button", { class: "link mono", onclick: () => copy(s.txid, "Transaction ID") }, short(s.txid))),
        ),
        bx ? h("div", { class: "inline-error block" }, icon("alert", 15), h("span", null, h("strong", null, "The server didn't accept it. "), bx.text, h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, bx.message)))) : null,
        h("p", { class: "note" }, bx?.requote ? "Nothing was sent to the network. This signature is for the old fee, so it can't be used." : `Not on the network yet. Send to network hands it to ${w?.server ?? "your server"}.`),
        h("div", { class: "actions" },
          // when the advice is a higher fee, that is the primary action (sending this one again fails the same way)
          bx?.requote
            ? h("button", { class: "big primary", onclick: () => refee(a, q) }, icon("refresh", 18), "Choose a higher fee")
            : h("button", { class: "big primary", disabled: sending, onclick: () => doBroadcast(a, q, s) }, sending ? [h("i", { class: "mini-spin" }), "Sending…"] : [icon("up", 18), bx ? "Try sending again" : `Send to ${n.name}`]),
          h("button", { class: "big", disabled: sending, onclick: () => { activeTicket = null; flow = { s: "form" }; go("home"); } }, "Discard"),
        ));
    }
    case "submitted": {
      const s = flow.signed;
      const conf = flow.confs;
      return h("section", { class: "card result" },
        conf > 0 ? h("div", { class: "result-ic ok big" }, icon("check", 32)) : h("div", { class: "result-ic pending" }, h("i", { class: "spinner" })),
        h("h3", null, conf > 0 ? `Confirmed · ${conf} confirmation${conf === 1 ? "" : "s"}` : `Sent to ${n.name}`),
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
  const $ = (sats: number) => usd(sats, btcState.host.price(), n.test);
  const change = q.outputs.find((o) => o.change);
  const big = q.fee_sats > q.amount_sats * 0.1 && q.fee_sats > 5_000;
  return h("section", { class: "card" },
    h("p", { class: "kicker" }, q.replaces ? ["Replacement for ", h("span", { class: "kicker-hash mono" }, short(q.replaces)), " · higher fee"] : "Check, then send to your phone"),
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
    h("p", { class: "note" }, "Your phone shows the address, amount, fee and change, and checks the change belongs to your key. Approve there only if they match. After signing, this Mac re-checks every signature and the exact amounts before anything can be sent to the network."),
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

export async function startBump(a: BtcAccount, e: BtcHistory) {
  const blocked = btcState.host.phoneBlocked(); if (blocked) { toast(blocked); return; }
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
  if (btcState.host.phoneBusy()) { toast("The phone is answering another request. Finish it first."); return; }
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
    void sendHost.loadWallet(a.id);
    for (;;) {
      await new Promise((r) => setTimeout(r, CONFIRMATION_POLL_MS));
      if (flow.s !== "submitted" || flow.signed.txid !== s.txid) return;
      try {
        const st = await btcApi.txStatus(a.id, s.txid);
        if (flow.s !== "submitted" || flow.signed.txid !== s.txid) return;
        if (st.confirmed) { setFlow({ ...flow, confs: st.confirmations }); void sendHost.refreshBtc(a.id); return; }
      } catch { /* try again */ }
      if (Date.now() - t0 > 3 * 3600_000) return;
    }
  } catch (e) { setFlow({ s: "broadcast_failed", q, signed: s, message: errText(e) }); }
}

/** Why the server refused a signed transaction, and whether only a new fee can help. */
function explainBroadcast(m: string): { text: string; requote: boolean } {
  if (/insufficient fee|min relay fee|mempool min fee/i.test(m)) return { text: "The fee is below what the network accepts right now. Choose a higher fee and approve it on your phone again. ", requote: true };
  if (/missingorspent|bad-txns-inputs-missingorspent|conflict/i.test(m)) return { text: "Its coins were already spent by another transaction. Refresh and check Activity. ", requote: false };
  if (/unreachable|timed out/i.test(m)) return { text: "The server couldn't be reached. Try sending again, or set another server in Settings → Bitcoin. ", requote: false };
  return { text: "", requote: false };
}

/** Throw away this signature: back to the form (fee picker), or a fresh speed-up quote. */
function refee(a: BtcAccount, q: BtcQuote) {
  activeTicket = null;
  if (q.replaces) {
    const e = wallets.get(a.id)?.history.find((x) => x.txid === q.replaces);
    if (e) { void startBump(a, e); return; }
    flow = { s: "form" }; go("home"); return;
  }
  if (draft.fee !== "custom") draft.fee = "fast";
  setFlow({ s: "form" });
}

/** A Bitcoin address still being typed (or pasted in part): too short for its kind yet. */
function incomplete(v: string): boolean {
  const t = v.replace(/^bitcoin:/i, "");
  if (/^(b|bc|t|tb|bcrt)$/i.test(t)) return true;
  if (/^(bc|tb|bcrt)1[02-9ac-hj-np-z]*$/i.test(t)) return /^(bc|tb|bcrt)1p/i.test(t) ? t.length < 62 : t.length < 42;
  return /^[123mn][1-9A-HJ-NP-Za-km-z]*$/.test(t) && t.length < 26;
}

/** The send form itself (not a later step) is on screen. */
export const btcSendFormOpen = () => btcState.sub === "send" && flow.s === "form";

export function initBtcSend(h0: BtcSendHost) {
  sendHost = h0;
  onProgress((ticket, stage) => {
    if (ticket !== activeTicket) return;
    if (stage === "waiting" && flow.s === "connecting") setFlow({ ...flow, waiting: true });
    else if (stage === "connecting" && flow.s === "connecting" && flow.waiting) setFlow({ ...flow, waiting: false, t0: Date.now() });
    else if (stage === "delivered" && flow.s === "connecting") setFlow({ s: "on_phone", q: flow.q, ticket, t0: Date.now(), cancelling: flow.cancelling });
    else if (stage === "verifying" && flow.s === "on_phone") setFlow({ s: "verifying", q: flow.q, ticket });
  });
}
