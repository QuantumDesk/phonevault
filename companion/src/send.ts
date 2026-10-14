// The Ethereum send flow (and speed-up / cancel of a pending transaction, which reuses it): form →
// quote → review → phone → verify → broadcast → receipt.

import { api, onProgress, openExternal, errText, REVIEW_LIMIT_MS } from "./api";
import type { Quote, Signed, SendError, HistoryEntry, FeeEstimate } from "./api";
import { byId, type Network } from "./networks";
import { h, icon, padlock, short, shortHash, grouped, fmtAmount, fmtUsd, fmtInt, copy, capitalize, fact, statusCard, topbar } from "./ui";
import { stepper, clockLine, clockTicker, cancelButton } from "./send-flow";
import { tokensOn, tokenAt, tokenBalanceOf, fmtExact, validTokenAmount, quoteAmount } from "./tokens";
import { explainSendError, asSendError } from "./errors";
import { simulationFor, resimulate, simPanel, gatedSendButton } from "./simulation";
import { renderPhoneNotice, refreshCachedDevice } from "./identity";
import { state, balances, price, rpcFor, net, activeLabel, type View } from "./state";

/** What the send flow needs from the shell (main.ts). */
export interface SendHost {
  go(v: View): void;
  render(): void;
  refreshHistory(): Promise<void>;
  refreshBalance(n: Network): Promise<void>;
}
let host: SendHost;
export function initSend(h0: SendHost) { host = h0; }

// ------------------------------------------------------------------ send flow
//
// Every state below is entered only from a real result: a command returning, a command failing,
// or a `send-progress` event carrying this attempt's ticket. "Review on your phone" requires the
// `delivered` event, i.e. the USB write to the phone completed.

type Flow =
  | { s: "form" }
  | { s: "quoting" }
  | { s: "review"; quote: Quote }
  | { s: "connecting"; quote: Quote; ticket: string; t0: number; cancelling?: boolean; waiting?: boolean }
  | { s: "on_phone"; quote: Quote; ticket: string; t0: number; cancelling?: boolean }
  | { s: "verifying"; quote: Quote; ticket: string }
  | { s: "failed"; quote: Quote; err: SendError }
  | { s: "signed"; quote: Quote; signed: Signed }
  | { s: "broadcasting"; quote: Quote; signed: Signed }
  | { s: "broadcast_failed"; quote: Quote; signed: Signed; message: string }
  | { s: "submitted"; quote: Quote; hash: string; t0: number; slow: boolean; trouble: boolean }
  | { s: "done"; quote: Quote; hash: string; block: number; ok: boolean; note?: string }
  // speed-up / cancel of a pending transaction: quoting it, or why it couldn't be quoted
  | { s: "replacing"; kind: "speedup" | "cancel"; hash: string }
  | { s: "prep_failed"; kind: "speedup" | "cancel"; hash: string; message: string };

let flow: Flow = { s: "form" };
let flowNet: Network = net();
let activeTicket: string | null = null;
let formError: string | null = null;
/** asset: "" for the native coin, else a token contract from the built-in list on flowNet */
const draft = { to: "", amount: "", asset: "" };
const draftToken = () => (draft.asset ? tokenAt(flowNet.id, draft.asset) : undefined);
let fee: FeeEstimate | null = null;
const tickFor = clockTicker();

function setFlow(f: Flow) {
  flow = f;
  tickFor(f.s);
  if (state.view === "send") host.render();
}

export function startSend() {
  if (state.identity.s === "different") { state.identity.dismissed = false; renderPhoneNotice(); return; }
  if (state.device.report?.verdict === "fail") { state.failDismissed = false; renderPhoneNotice(); return; }
  flow = { s: "form" }; formError = null; activeTicket = null; flowNet = net(); fee = null;
  if (draft.asset && !tokenAt(flowNet.id, draft.asset)) { draft.asset = ""; draft.amount = ""; }
  host.go("send");
  loadFee();
}

async function loadFee() {
  const n = flowNet;
  try { const f = await api.feeEstimate(rpcFor(n.id)); if (n === flowNet) { fee = f; updateFormExtras(); } } catch { fee = null; updateFormExtras(); }
}

function stepOf(f: Flow): number {
  switch (f.s) {
    case "form": case "quoting": case "review": case "replacing": case "prep_failed": return 0;
    case "connecting": case "on_phone": case "verifying": case "failed": return 1;
    case "signed": case "broadcasting": case "broadcast_failed": return 2;
    default: return 3;
  }
}

export function sendView() {
  const busy = ["connecting", "on_phone", "verifying", "broadcasting", "submitted"].includes(flow.s);
  const repl = replacementOf(flow);
  const back = busy ? null : () => { if (flow.s === "review" && !repl) { setFlow({ s: "form" }); } else host.go("home"); };
  return h("div", { class: "stack fade" },
    topbar(repl ? `${repl === "cancel" ? "Cancel" : "Speed up"} on ${flowNet.name}` : `Send on ${flowNet.name}`, back),
    stepper(stepOf(flow), flow.s === "done" && flow.ok, flow.s === "failed" || flow.s === "broadcast_failed" || (flow.s === "done" && !flow.ok)),
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
        h("div", { class: "from-line" }, h("span", { class: "muted small" }, `From ${activeLabel()} · `, h("span", { class: "mono" }, short(state.status!.paired_checksum!))), refs.avail),
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
    case "replacing":
      return statusCard(flow.kind === "cancel" ? "Preparing the cancel…" : "Preparing the speed-up…", `Checking that ${shortHash(flow.hash)} is still pending and quoting a higher fee for the same nonce.`, [], [], "connecting");
    case "prep_failed":
      return h("section", { class: "card result" },
        h("div", { class: "result-ic neutral" }, icon("x", 28)),
        h("h3", null, flow.kind === "cancel" ? "Can't cancel it" : "Can't speed it up"),
        h("p", null, capitalize(flow.message) + "."),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => host.go("home") }, "Back to activity"),
          flow.kind === "speedup" && /only be cancelled/.test(flow.message) ? h("button", { class: "big", onclick: () => { const e = state.history.find((x) => x.hash === (flow as { hash: string }).hash); if (e) startReplacement(e, "cancel"); } }, "Cancel it instead") : null,
        ),
      );
    case "review": {
      const quote = flow.quote;
      if (quote.replaces) return replacementReview(quote);
      const sim = reviewSimulation(quote);
      return h("section", { class: "card" },
        h("p", { class: "kicker" }, "Check, then send to your phone"),
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
        simPanel(sim, () => { resimulate(rpcFor(n.id), quote, rerenderReview(quote)); host.render(); }),
        n.l2 ? h("p", { class: "note" }, `${n.name} also charges a small L1 data fee that neither this Mac nor the phone can bound in advance. It is usually a fraction of a cent.`) : null,
        quote.token ? h("p", { class: "note" }, `Your phone names the token from its own built-in list: it should read "Send ${fmtExact(quote.token.amount)} ${quote.token.symbol} to" this recipient. If it says "Unknown token contract", reject it there.`) : null,
        h("p", { class: "note" }, "Your phone shows these same details. Approve there only if they match. Nothing reaches the network until you press Broadcast afterwards."),
        h("div", { class: "actions" },
          gatedSendButton(sim, "Send to phone", () => sendToPhone(quote)),
          h("button", { class: "big", onclick: () => setFlow({ s: "form" }) }, "Edit"),
        ),
      );
    }
    case "connecting":
      if (flow.waiting) return statusCard("Waiting for your phone…", "Your phone is answering another request (a device check or a dApp request). Your transaction goes to it as soon as that one finishes. Nothing has been sent yet.",
        [clockLine(flow.t0, null)], [cancelButton(flow.cancelling, cancelSign)], "connecting");
      return statusCard("Reaching your phone…", "Opening the USB connection and switching the phone to vault mode. The request is not on the phone yet.",
        [clockLine(flow.t0, null)], [cancelButton(flow.cancelling, cancelSign)], "connecting");
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
        h("div", { class: "actions" }, cancelButton(flow.cancelling, cancelSign)),
      );
    case "verifying":
      return statusCard("Checking the signature…", "Decoding what the phone returned and comparing every field with what you entered.", [], [], "connecting");
    case "failed": {
      const x = explainSendError(flow.err, { chain: "eth" });
      const quote = flow.quote;
      return h("section", { class: `card result ${x.danger ? "danger-card" : ""}` },
        h("div", { class: `result-ic ${x.danger ? "bad" : x.neutral ? "neutral" : "warn"}` }, icon(x.danger ? "alert" : "x", 28)),
        h("h3", null, x.title),
        h("p", null, x.body),
        flow.err.message && !x.hideDetail ? h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, flow.err.message)) : null,
        h("div", { class: "actions" },
          x.danger ? null : h("button", { class: "big primary", onclick: () => sendToPhone(quote) }, icon("refresh", 18), "Try again"),
          x.danger && replacementOf(flow) ? null : h("button", { class: "big", onclick: () => replacementOf(flow) ? host.go("home") : setFlow({ s: "form" }) }, replacementOf(flow) ? "Close" : "Edit"),
          x.danger ? h("button", { class: "big", onclick: () => host.go("home") }, "Close") : null,
        ),
      );
    }
    case "signed": case "broadcasting": case "broadcast_failed": {
      const signed = flow.signed; const quote = flow.quote;
      const sending = flow.s === "broadcasting";
      return h("section", { class: "card result" },
        h("div", { class: "result-ic ok" }, icon("check", 28)),
        quote.replaces ? h("p", { class: "kicker" }, `Replacement for tx ${shortHash(quote.replaces.hash)}`) : null,
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
        h("div", { class: "actions" }, h("button", { class: "big", onclick: () => host.go("home") }, "Close")),
      );
    }
    case "done": {
      const r = flow.quote.replaces;
      if (r && flow.note) return h("section", { class: "card result" },
        h("div", { class: "result-ic neutral" }, icon("check", 28)),
        h("h3", null, "The original went through first"),
        h("p", { class: "muted" }, flow.note),
        hashLinks(flow.hash),
        h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => host.go("home") }, "Done")));
      if (r && r.kind === "cancel" && flow.ok) return h("section", { class: "card result" },
        h("div", { class: "result-ic ok big" }, icon("check", 32)),
        h("h3", null, "Cancelled"),
        h("p", { class: "muted" }, `Your 0 ${n.symbol} self-transfer was included in block ${fmtInt(flow.block)}, so ${shortHash(r.hash)} can never be included. Only the network fee was paid.`),
        hashLinks(flow.hash),
        h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => host.go("home") }, "Done")));
      return h("section", { class: `card result ${flow.ok ? "" : "danger-card"}` },
        h("div", { class: `result-ic ${flow.ok ? "ok big" : "bad"}` }, icon(flow.ok ? "check" : "alert", 32)),
        h("h3", null, flow.ok ? "Confirmed" : "Included, but it failed"),
        h("p", { class: "muted" }, flow.ok ? `${quoteAmount(flow.quote, `${fmtAmount(flow.quote.amount_eth, 8)} ${n.symbol}`)} sent on ${n.name}, in block ${fmtInt(flow.block)}.` : `The network ran it in block ${fmtInt(flow.block)} and it reverted. The amount was not sent, but the fee was paid.`),
        hashLinks(flow.hash),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => host.go("home") }, "Done"),
          h("button", { class: "big", onclick: () => { draft.amount = ""; startSend(); } }, "Send another"),
        ),
      );
    }
  }
}

// ------------------------------------------------------------------ speed up / cancel
// A replacement is quoted in Rust (replace.rs) from the recorded transaction and then goes through
// exactly the Send pipeline below: the phone reviews it like any transaction, Rust verifies it.

function replacementOf(f: Flow): "speedup" | "cancel" | null {
  if (f.s === "replacing" || f.s === "prep_failed") return f.kind;
  return "quote" in f && f.quote.replaces ? f.quote.replaces.kind : null;
}

const gwei = (q: string | null | undefined) => {
  if (!q) return "?";
  const v = Number(BigInt(q)) / 1e9;
  return v >= 100 ? v.toFixed(0) : v >= 1 ? v.toFixed(2) : v.toPrecision(3);
};

export async function startReplacement(e: HistoryEntry, kind: "speedup" | "cancel") {
  if (!e.hash) return;
  if (state.identity.s === "different") { state.identity.dismissed = false; renderPhoneNotice(); return; }
  if (state.device.report?.verdict === "fail") { state.failDismissed = false; renderPhoneNotice(); return; }
  const hash = e.hash;
  flowNet = byId(e.chain_id); activeTicket = null;
  flow = { s: "replacing", kind, hash };
  host.go("send");
  try {
    const quote = await api.replacementQuote(rpcFor(e.chain_id), hash, kind);
    if (flow.s !== "replacing" || flow.hash !== hash) return;
    if (parseInt(quote.chain_id, 16) !== e.chain_id || quote.replaces?.hash.toLowerCase() !== hash.toLowerCase()) throw "the quote is not for this transaction";
    setFlow({ s: "review", quote });
  } catch (err) {
    if (flow.s === "replacing" && flow.hash === hash) setFlow({ s: "prep_failed", kind, hash, message: errText(err) });
  }
}

function replacementReview(quote: Quote) {
  const n = flowNet;
  const r = quote.replaces!;
  const cancel = r.kind === "cancel";
  const usd = (eth: string) => fmtUsd(eth, price(n));
  const sim = reviewSimulation(quote);
  return h("section", { class: "card replace-card" },
    h("p", { class: "kicker" }, `Replacement for tx ${shortHash(r.hash)}`),
    h("h3", null, cancel ? "Cancel this transaction" : "Speed up this transaction"),
    h("p", { class: "muted" }, cancel
      ? "This sends 0 to your own address with the same nonce and a higher fee. If it is included first, the original can never be included. You pay only the network fee."
      : "This sends the same transaction again with the same nonce and a higher fee, so the network picks it up sooner. Only one of the two can ever be included."),
    h("dl", { class: "facts" },
      fact("Replaces", h("button", { class: "link mono", title: r.hash, onclick: () => openExternal(`${n.explorer}/tx/${r.hash}`) }, shortHash(r.hash), icon("external", 13))),
      cancel ? fact("Sends", h("span", null, `0 ${n.symbol} to yourself `, h("span", { class: "mono muted" }, short(checksumOf(quote.to)))))
        : fact("Sends", quote.token ? `${fmtExact(quote.token.amount)} ${quote.token.symbol} to ${short(checksumOf(quote.token.recipient))}` : `${fmtAmount(quote.amount_eth, 8)} ${n.symbol} to ${short(checksumOf(quote.to))}`),
      fact("Nonce", h("span", { class: "mono" }, `${parseInt(quote.nonce, 16)} (same as the original)`)),
      fact("Max fee / gas", h("span", null, `${gwei(quote.max_fee_per_gas)} gwei`, h("span", { class: "muted" }, ` · was ${gwei(r.previous_max_fee_per_gas)}`))),
      fact("Priority fee", h("span", null, `${gwei(quote.max_priority_fee_per_gas)} gwei`, h("span", { class: "muted" }, ` · was ${gwei(r.previous_max_priority_fee_per_gas)}`))),
      fact("Network fee", h("span", null, `at most ${fmtAmount(quote.max_fee_eth, 8)} ${n.symbol}`, usd(quote.max_fee_eth) ? h("span", { class: "muted" }, ` · ${usd(quote.max_fee_eth)}`) : null)),
    ),
    simPanel(sim, () => { resimulate(rpcFor(n.id), quote, rerenderReview(quote)); host.render(); }),
    h("p", { class: "note" }, cancel
      ? `Your phone shows it as a normal transaction: send 0 ${n.symbol} to your own address. Approve there only if that is what it says.`
      : "Your phone shows it as a normal transaction with these same details. Approve there only if they match."),
    h("div", { class: "actions" },
      gatedSendButton(sim, "Send to phone", () => sendToPhone(quote)),
      h("button", { class: "big", onclick: () => host.go("home") }, "Not now"),
    ),
  );
}

/** Simulate the quote under review on the user's node (simulation.ts); re-renders when it's done. */
const rerenderReview = (quote: Quote) => () => { if (state.view === "send" && flow.s === "review" && flow.quote === quote) host.render(); };
function reviewSimulation(quote: Quote) { return simulationFor(rpcFor(flowNet.id), quote, rerenderReview(quote)); }

let toChecksum: string | null = null;
function checksumOf(lower: string) {
  if (state.status?.paired_checksum && state.status.paired_checksum.toLowerCase() === lower.toLowerCase()) return state.status.paired_checksum;
  return toChecksum && toChecksum.toLowerCase() === lower ? toChecksum : lower;
}
function hostOf(url: string) { try { return new URL(url).host; } catch { return url; } }
function hashLinks(hash: string) {
  const url = `${flowNet.explorer}/tx/${hash}`;
  return h("div", { class: "hash-box" },
    h("button", { class: "link mono", title: hash, onclick: () => copy(hash, "Hash") }, shortHash(hash), icon("copy", 14)),
    h("button", { class: "link", onclick: () => openExternal(url) }, `View on ${hostOf(flowNet.explorer)}`, icon("external", 14)),
  );
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
    else if (v.toLowerCase() === state.status?.paired?.toLowerCase()) { r.toMsg.textContent = "This is your own address."; r.toMsg.className = "field-msg warn"; }
    else if (v === v.toLowerCase() || v.slice(2) === v.slice(2).toUpperCase()) { r.toMsg.textContent = "Valid, but without a checksum: compare it carefully with the source."; r.toMsg.className = "field-msg warn"; }
    else { r.toMsg.replaceChildren(icon("check", 13), " Checksum OK"); r.toMsg.className = "field-msg ok"; }
  } catch { addrOk = false; }
  updateFormExtras();
}

export function updateFormBalance() {
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

async function sendToPhone(quote: Quote) {
  const ticket = crypto.randomUUID();
  activeTicket = ticket;
  setFlow({ s: "connecting", quote, ticket, t0: Date.now() });
  // Last-resort UI watchdog: the Rust side already bounds each phase; this only guards the UI.
  // Time spent queued behind another request on the phone does not count (each phase resets t0).
  const watchdog = window.setInterval(() => {
    if (activeTicket === ticket && (flow.s === "connecting" || flow.s === "on_phone") && !(flow.s === "connecting" && flow.waiting)
      && Date.now() - flow.t0 > REVIEW_LIMIT_MS + 90_000) {
      api.signCancel(ticket).catch(() => {});
      setFlow({ s: "failed", quote, err: { kind: "timeout", message: "no result from the USB session", delivered: flow.s === "on_phone" } });
    }
  }, 5000);
  try {
    const signed = await api.signStart(ticket, quote);
    // A verified signature is always shown if this attempt is still the current one, even if
    // the UI had already given up waiting: losing it is how "signed but nothing shown" happens.
    if (activeTicket === ticket) setFlow({ s: "signed", quote, signed });
  } catch (e) {
    if (activeTicket !== ticket || flow.s === "signed") return;
    const err = asSendError(e);
    if (err.kind === "attestation") refreshCachedDevice();
    setFlow({ s: "failed", quote, err });
  } finally { clearInterval(watchdog); }
}

async function cancelSign() {
  if (flow.s !== "connecting" && flow.s !== "on_phone") return;
  const ticket = flow.ticket;
  setFlow({ ...flow, cancelling: true });
  try { await api.signCancel(ticket); } catch { /* the command result will say */ }
  // The Rust side answers within a few seconds; if it can't (e.g. mid USB switch), stop waiting.
  setTimeout(() => {
    if (activeTicket === ticket && (flow.s === "connecting" || flow.s === "on_phone")) setFlow({ s: "failed", quote: flow.quote, err: { kind: "cancelled", message: "cancelled on this Mac", delivered: flow.s === "on_phone" } });
  }, 8000);
}

onProgress((ticket, stage) => {
  if (ticket !== activeTicket) return;
  if (stage === "waiting" && flow.s === "connecting") setFlow({ ...flow, waiting: true });
  else if (stage === "connecting" && flow.s === "connecting" && flow.waiting) setFlow({ ...flow, waiting: false, t0: Date.now() });
  else if (stage === "delivered" && flow.s === "connecting") setFlow({ s: "on_phone", quote: flow.quote, ticket, t0: Date.now(), cancelling: flow.cancelling });
  else if (stage === "verifying" && flow.s === "on_phone") setFlow({ s: "verifying", quote: flow.quote, ticket });
});

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
  host.refreshHistory();
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
        try { state.history = await api.historyMark(hash, rc.success ? "confirmed" : "failed", rc.block); } catch { /* best effort */ }
        setFlow({ s: "done", quote, hash, block: rc.block, ok: rc.success });
        host.refreshBalance(n);
        return;
      }
      // A replacement races its original: if the original was included instead, say so.
      const orig = quote.replaces?.hash;
      if (orig) {
        const ro = await api.receipt(rpcFor(n.id), orig);
        if (flow.s !== "submitted" || flow.hash !== hash) return;
        if (ro.mined) {
          try { state.history = await api.historyMark(orig, ro.success ? "confirmed" : "failed", ro.block); } catch { /* best effort */ }
          setFlow({ s: "done", quote, hash: orig, block: ro.block, ok: ro.success,
            note: `${shortHash(orig)} was included in block ${fmtInt(ro.block)} before the ${quote.replaces!.kind === "cancel" ? "cancel" : "speed-up"}, so the replacement was dropped. Nothing was paid for the replacement.` });
          host.refreshBalance(n);
          return;
        }
      }
      const slow = Date.now() - t0 > 180_000;
      if (slow !== flow.slow || flow.trouble) setFlow({ ...flow, slow, trouble: false });
    } catch {
      if (flow.s === "submitted" && !flow.trouble && i > 1) setFlow({ ...flow, trouble: true });
    }
  }
}

/** Where the flow is ("form" when no send is under way), for the shell's busy checks. */
export const sendStage = () => flow.s;
/** The network the send form is on. */
export const sendNet = () => flowNet;
/** Open Send with a fresh form, optionally addressed to `to` (the guided setup's first send). */
export function startSendTo(to: string) { draft.to = to; draft.amount = ""; draft.asset = ""; startSend(); }
