// WalletConnect, rendering half: the connect / proposal / request cards (one modal layer), the
// line under the account card and the Settings section. The engine (sessions, requests, the phone
// pipeline) is walletconnect.ts; it calls back into render() here.

import { call, openExternal, isTauri, REVIEW_LIMIT_MS } from "./api";
import type { Quote } from "./api";
import { byId, netName } from "./networks";
import { h, icon, short, shortHash, grouped, fmtAmount, copy, fact } from "./ui";
import type { VerifyIn } from "./wc-backend";
import { isExtTopic } from "./extension";
import { clockLine, updateClocks, cancelButton } from "./send-flow";
import { simulationFor, resimulate, simPanel, gatedSendButton } from "./simulation";
import { wc, startWalletConnect, type WcHost, type Item, type Note, INTERNAL, PROJECT_ID_RE, saveProjectId, notices, shown, sessionOf, dappName, chainNum, hostOf,
  start, prepare, approve, reject, cancel, closeItem, finalFail, broadcast, approveProposal, rejectProposal, pair, disconnect, openConnect } from "./walletconnect";

// ------------------------------------------------------------------ rendering: shared bits

function linkIcon(size = 18): SVGSVGElement {
  const wrap = document.createElement("span");
  wrap.innerHTML = `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/></svg>`;
  return wrap.firstElementChild as SVGSVGElement;
}


/** dApp icons come through Rust (nft.rs `dapp_icon`: https only, image types, 256 KiB) as data:
 *  URLs; the page's CSP loads no remote images, so the dApp's server never sees this app fetch it.
 *  url → data URL ("" = none), or the request in flight. */
const iconCache = new Map<string, string | Promise<string>>();

function dappIcon(url: string | undefined, size = 36) {
  const box = h("span", { class: "wc-icon", style: `width:${size}px;height:${size}px` });
  const show = (data: string) => {
    box.replaceChildren(data ? h("img", { src: data, alt: "", width: size, height: size }) : linkIcon(size * 0.5));
  };
  if (!url || !/^(https:|data:image\/)/.test(url) || url.length > 2048) { show(""); return box; }
  const hit = iconCache.get(url);
  if (typeof hit === "string") { show(hit); return box; }
  show("");
  const p = hit ?? call<string>("dapp_icon", { url }).catch(() => "");
  if (!hit) {
    if (iconCache.size > 64) iconCache.clear();
    iconCache.set(url, p);
    void p.then((d) => iconCache.set(url, d));
  }
  void p.then(show);
  return box;
}

/** Verify API result, prominent when it is anything but a verified match. */
function verifyBadge(v: VerifyIn | null, claimed: string) {
  if (v?.source === "browser") return v.local
    ? h("div", { class: "wc-verify unverified" }, icon("alert", 16), h("span", null, h("strong", null, "LOCAL PAGE. "), `${hostOf(v.origin)} is served from this Mac (development). Only continue if you started it yourself.`))
    : h("span", { class: "wc-verified" }, icon("check", 13), "Address from your browser");
  if (v?.isScam) return h("div", { class: "wc-verify threat" }, icon("alert", 16), h("span", null, h("strong", null, "THREAT. "), `WalletConnect flags ${hostOf(v.origin || claimed)} as malicious. Reject this.`));
  if (v?.validation === "INVALID") return h("div", { class: "wc-verify mismatch" }, icon("alert", 16), h("span", null, h("strong", null, "DOMAIN MISMATCH. "), `The request comes from ${hostOf(v.origin) || "another site"}, not ${hostOf(claimed)} as it claims.`));
  if (v?.validation === "VALID") return h("span", { class: "wc-verified" }, icon("check", 13), "Verified domain");
  return h("div", { class: "wc-verify unverified" }, icon("alert", 16), h("span", null, h("strong", null, "UNVERIFIED. "), `WalletConnect could not confirm this really is ${hostOf(claimed) || "the site it claims"}. Check you opened it yourself.`));
}

function dappHeader(meta: { name: string; url: string; icons: string[] }, v: VerifyIn | null) {
  return h("div", { class: "wc-dapp" },
    dappIcon(meta.icons[0], 40),
    h("div", { class: "grow" },
      h("div", { class: "wc-dapp-name" }, meta.name),
      h("div", { class: "muted small mono" }, hostOf(meta.url) || "no URL given")),
    v?.validation === "VALID" && !v.isScam && !v.local ? verifyBadge(v, meta.url) : null,
  );
}
function verifyWarning(meta: { url: string }, v: VerifyIn | null) {
  if (v?.source === "browser") return v.local ? verifyBadge(v, meta.url) : null;
  return v?.validation === "VALID" && !v.isScam ? null : verifyBadge(v, meta.url);
}

function notesList(notes: Note[]) {
  if (!notes.length) return null;
  return h("ul", { class: "wc-notes" }, notes.map((n) => h("li", { class: n.level }, icon(n.level === "info" ? "check" : "alert", 14), h("span", null, n.text))));
}

// ------------------------------------------------------------------ rendering: layer

let layer: HTMLElement | null = null;
let clockTimer = 0;

function render() {
  wc.host?.changed();
  const content = wc.proposal ? proposalCard() : wc.connect ? connectCard() : shown().length && !wc.requestsHidden ? requestsCard() : null;
  if (!content) { layer?.remove(); layer = null; return; }
  if (!layer) {
    layer = h("div", { class: "modal-scrim wc-layer fade" });
    document.body.append(layer);
  }
  layer.replaceChildren(content);
  clearInterval(clockTimer);
  if (layer.querySelector(".clock")) clockTimer = window.setInterval(updateClocks, 1000);
}

function connectCard() {
  const c = wc.connect!;
  if (wc.engine.s !== "ready") {
    return h("section", { class: "card modal wc-modal", role: "dialog", "aria-modal": "true" },
      h("p", { class: "kicker" }, "WalletConnect"),
      h("h3", null, wc.engine.s === "starting" ? "Starting WalletConnect…" : wc.engine.s === "error" ? "WalletConnect didn't start" : "Add a project ID first"),
      wc.engine.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), wc.engine.message) : null,
      wc.engine.s === "off" ? h("p", { class: "muted" }, "WalletConnect needs a free project ID from Reown (cloud.reown.com). Paste it in Settings → WalletConnect. It is stored only on this Mac.") : null,
      h("div", { class: "actions" },
        wc.engine.s === "off" || wc.engine.s === "error" ? h("button", { class: "big primary", onclick: () => { wc.connect = null; render(); wc.host.openSettings(); } }, "Open Settings") : null,
        h("button", { class: "big", onclick: () => { wc.connect = null; render(); } }, "Close")));
  }
  const input = h("input", { type: "text", placeholder: "wc:…", spellcheck: "false", autocomplete: "off", value: c.uri, disabled: c.busy || c.waiting });
  const go = h("button", { class: "big primary", disabled: c.busy || c.waiting, onclick: () => (c.uri.trim() ? pair() : paste()) }, c.busy ? [h("i", { class: "mini-spin" }), "Connecting…"] : c.uri.trim() ? "Connect" : "Paste & connect");
  input.addEventListener("input", () => { c.uri = input.value; c.error = null; if (!c.busy) go.textContent = c.uri.trim() ? "Connect" : "Paste & connect"; });
  input.addEventListener("keydown", (e) => { if ((e as KeyboardEvent).key === "Enter") pair(); });
  queueMicrotask(() => { if (!c.busy && !c.waiting) input.focus(); });
  const paste = async () => {
    try { const t = (await navigator.clipboard.readText()).trim(); c.uri = t; input.value = t; c.error = null; if (t.startsWith("wc:")) pair(); else { c.error = "The clipboard doesn't hold a wc: link. In the dApp choose WalletConnect, then “Copy link”."; render(); } }
    catch { c.error = "Couldn't read the clipboard. Paste into the field with ⌘V."; render(); }
  };
  return h("section", { class: "card modal wc-modal", role: "dialog", "aria-modal": "true" },
    h("p", { class: "kicker" }, "Connect a dApp"),
    h("h3", null, "Paste the WalletConnect link"),
    h("p", { class: "muted small" }, "In the dApp, choose WalletConnect, then “Copy link” under the QR code. The dApp will see your address and can ask for signatures; each one still needs your phone."),
    h("label", { class: "field" }, input),
    c.error ? h("p", { class: "inline-error" }, icon("alert", 15), c.error) : null,
    c.waiting ? h("p", { class: "muted small row" }, h("i", { class: "mini-spin" }), "Waiting for the dApp to ask for a connection…") : null,
    h("div", { class: "actions" },
      go,
      h("button", { class: "big", onclick: () => { wc.connect = null; render(); } }, "Cancel")));
}

function proposalCard() {
  const pr = wc.proposal!;
  const { meta, verify } = pr.p;
  const plan = pr.plan;
  const paired = wc.host.paired();
  const danger = verify?.isScam || verify?.validation === "INVALID";
  const chainRows = plan ? plan.chains.map((c) => {
    const box = h("input", { type: "checkbox", checked: pr.selected.has(c.id), disabled: !c.supported || c.required || pr.busy });
    box.addEventListener("change", () => { if (box.checked) pr.selected.add(c.id); else pr.selected.delete(c.id); render(); });
    return h("label", { class: `wc-chain${c.supported ? "" : " off"}` }, box, h("i", { class: `net-dot n${c.id}` }), h("span", { class: "grow" }, c.name),
      c.required ? h("span", { class: "tag" }, "required") : null, c.supported ? null : h("span", { class: "muted small" }, "not on your phone"));
  }) : [h("p", { class: "muted small row" }, h("i", { class: "mini-spin" }), "Checking what it asks for…")];
  const approveOk = !!plan && !plan.blocker && pr.selected.size > 0 && !!paired && !pr.busy;
  return h("section", { class: `card modal wc-modal${danger ? " danger-card" : ""}`, role: "dialog", "aria-modal": "true" },
    h("p", { class: `kicker${danger ? " danger" : ""}` }, verify?.source === "browser" ? "Browser connection request" : "Connection request"),
    dappHeader(meta, verify),
    verifyWarning(meta, verify),
    meta.description ? h("p", { class: "muted small wc-desc" }, meta.description) : null,
    h("div", { class: "wc-sub" }, "Networks"),
    h("div", { class: "wc-chains" }, chainRows),
    plan ? h("div", { class: "wc-sub" }, "Asks to use") : null,
    plan ? h("div", { class: "wc-methods" }, plan.methods.map((m) => h("span", { class: `wc-method${plan.refused_methods.includes(m) ? " refused" : ""}`, title: plan.refused_methods.includes(m) ? "Always refused by this wallet" : "" }, m))) : null,
    plan?.refused_methods.length ? h("p", { class: "muted small" }, "Struck-through methods are always refused, with an error to the dApp.") : null,
    h("dl", { class: "facts wc-facts" }, fact("Account", paired ? h("span", { class: "mono" }, short(paired)) : h("span", { class: "muted" }, "not paired")), fact("Signing", "Every request is shown here first, then reviewed and approved on your phone.")),
    plan?.blocker ? h("p", { class: "inline-error" }, icon("alert", 15), `Can't connect: ${plan.blocker}`) : null,
    pr.error ? h("p", { class: "inline-error" }, icon("alert", 15), pr.error) : null,
    h("div", { class: "actions" },
      h("button", { class: `big ${danger ? "" : "primary"}`, disabled: !approveOk, onclick: approveProposal }, pr.busy ? [h("i", { class: "mini-spin" }), "Connecting…"] : `Connect${pr.selected.size ? ` on ${pr.selected.size} network${pr.selected.size > 1 ? "s" : ""}` : ""}`),
      h("button", { class: `big ${danger ? "primary" : ""}`, disabled: pr.busy, onclick: rejectProposal }, "Reject")));
}

function requestsCard() {
  const list = shown();
  const head = list[0];
  const rest = list.slice(1);
  return h("section", { class: "card modal wc-modal wc-req", role: "dialog", "aria-modal": "true" },
    itemView(head),
    rest.length ? h("div", { class: "wc-queue" },
      h("div", { class: "wc-sub" }, `Waiting (${rest.length})`),
      h("ul", null, rest.map((it) => h("li", null,
        dappIcon(sessionOf(it.req.topic)?.meta.icons[0], 22),
        h("span", { class: "grow" }, h("strong", null, dappName(it.req.topic)), " · ", methodLabel(it.req.method)),
        h("button", { class: "chip-btn", onclick: () => reject(it) }, "Reject"))))) : null,
  );
}

function methodLabel(m: string) {
  return m === "eth_sendTransaction" ? "transaction" : m === "personal_sign" ? "sign message" : m === "eth_signTypedData_v4" ? "sign typed data" : m === "wallet_switchEthereumChain" ? "switch network" : m;
}

function itemView(it: Item): Node {
  const s = sessionOf(it.req.topic);
  const meta = s?.meta ?? { name: "Unknown dApp", url: "", icons: [] };
  const v = it.req.verify;
  const prep = it.prep;
  const chain = chainNum(it.req.chainId);
  const later = h("button", { class: "link wc-later", onclick: () => { wc.requestsHidden = true; render(); }, title: "Hide this; it stays waiting on the main view" }, "Decide later");
  const head = [h("p", { class: "kicker" }, prep?.kind === "transaction" ? "Transaction request" : prep?.kind === "switch_chain" ? "Network request" : "Signature request"), dappHeader(meta, v), verifyWarning(meta, v)];

  switch (it.stage.s) {
    case "waiting": case "preparing":
      return h("div", { class: "wc-item" }, head, h("p", { class: "muted row" }, h("i", { class: "mini-spin" }), it.req.method === "eth_sendTransaction" ? "Quoting nonce, fees and gas from your node…" : "Checking the request…"),
        h("div", { class: "actions" }, h("button", { class: "big", onclick: () => reject(it) }, "Reject")), later);
    case "review": {
      const err = it.stage.error;
      const approveLabel = prep?.kind === "switch_chain" ? `Switch to ${prep.name}` : "Send to phone";
      return h("div", { class: "wc-item" }, head, reviewBody(it, chain),
        err ? h("p", { class: "inline-error" }, icon("alert", 15), err) : null,
        prep?.kind !== "switch_chain" ? h("p", { class: "note" }, "Your phone shows this again in full. Approve there only if it matches. Reject here and nothing reaches the phone.") : null,
        h("div", { class: "actions" },
          // a transaction's send button follows its simulation: blocked on a revert, "Send anyway" when it couldn't run
          prep?.kind === "transaction" ? gatedSendButton(txSimulation(prep.quote, chain), approveLabel, () => approve(it))
            : h("button", { class: "big primary", onclick: () => approve(it) }, prep?.kind === "switch_chain" ? null : icon("phone", 18), approveLabel),
          h("button", { class: "big", onclick: () => reject(it) }, "Reject")), later);
    }
    case "connecting":
      return h("div", { class: "wc-item" }, head, statusLine("Reaching your phone…", "Opening the USB connection. The request is not on the phone yet."),
        clockLine(it.stage.t0, REVIEW_LIMIT_MS),
        h("div", { class: "actions" }, cancelButton(it.cancelling, () => cancel(it))));
    case "on_phone":
      return h("div", { class: "wc-item wc-center" }, head,
        h("div", { class: "phone-art" }, h("div", { class: "phone-screen" }, icon("phone", 22))),
        h("h3", null, "Review on your phone"),
        h("p", { class: "muted" }, prep?.kind === "transaction" ? "The request is on your phone. Unlock it, check the details, and approve or reject." : "Sent to your phone. Unlock it, read the review, and approve or reject."),
        clockLine(it.stage.t0, REVIEW_LIMIT_MS),
        prep?.kind === "transaction" ? h("div", { class: "actions" }, cancelButton(it.cancelling, () => cancel(it))) : null);
    case "verifying":
      return h("div", { class: "wc-item" }, head, statusLine("Checking the signature…", "Decoding what the phone returned and comparing every field with this request."));
    case "broadcasting":
      return h("div", { class: "wc-item" }, head, statusLine(`Broadcasting to ${netName(chain)}…`, "Signed and verified. Sending it through your node."));
    case "broadcast_failed": {
      const st = it.stage;
      return h("div", { class: "wc-item" }, head,
        h("div", { class: "inline-error block" }, icon("alert", 15), h("span", null, h("strong", null, "Signed and verified, but the node didn't accept it. "), h("code", { class: "mono small" }, st.message))),
        h("div", { class: "actions" },
          h("button", { class: "big primary", onclick: () => broadcast(it, st.hash, chain) }, icon("refresh", 18), "Retry broadcast"),
          h("button", { class: "big", onclick: () => { finalFail(it, INTERNAL, `The node refused the transaction: ${st.message}`, "Not sent", "The signed transaction was discarded. Nothing was broadcast.", "neutral"); render(); } }, "Give up")));
    }
    case "done": {
      const st = it.stage;
      const n = st.chain ? byId(st.chain) : null;
      return h("div", { class: "wc-item wc-center" }, head,
        h("div", { class: "result-ic ok" }, icon("check", 28)),
        h("h3", null, st.title), h("p", { class: "muted" }, st.body),
        st.hash && n ? h("div", { class: "hash-box" },
          h("button", { class: "link mono", onclick: () => copy(st.hash!, "Hash") }, shortHash(st.hash), icon("copy", 14)),
          h("button", { class: "link", onclick: () => openExternal(`${n.explorer}/tx/${st.hash}`) }, `View on ${hostOf(n.explorer)}`, icon("external", 14))) : null,
        h("div", { class: "actions" }, h("button", { class: "big primary", onclick: () => closeItem(it) }, "Done")));
    }
    case "failed": {
      const st = it.stage;
      return h("div", { class: `wc-item wc-center${st.tone === "danger" ? " wc-danger" : ""}` }, head,
        h("div", { class: `result-ic ${st.tone === "danger" ? "bad" : st.tone}` }, icon(st.tone === "neutral" ? "x" : "alert", 28)),
        h("h3", null, st.title), h("p", null, st.body),
        st.detail ? h("details", { class: "detail" }, h("summary", null, "Details"), h("code", null, st.detail)) : null,
        h("div", { class: "actions" },
          st.retry ? h("button", { class: "big primary", onclick: () => (it.prep ? approve(it) : prepare(it)) }, icon("refresh", 18), "Try again") : null,
          st.retry ? h("button", { class: "big", onclick: () => reject(it) }, "Reject") : h("button", { class: "big primary", onclick: () => closeItem(it) }, "Close")));
    }
  }
}

function statusLine(title: string, body: string) {
  return h("div", { class: "wc-status" }, h("i", { class: "spinner" }), h("div", null, h("strong", null, title), h("p", { class: "muted small" }, body)));
}

function reviewBody(it: Item, chain: number): Node[] {
  const prep = it.prep!;
  const n = byId(chain);
  switch (prep.kind) {
    case "transaction": {
      const q = prep.quote; const c = prep.call;
      const what = c.kind === "transfer" ? `Send ${fmtAmount(q.amount_eth, 8)} ${n.symbol}`
        : c.kind === "token_transfer" ? "Token transfer" : c.kind === "token_approve" ? "Token approval" : "Contract call";
      return [
        h("div", { class: "hero-amount" }, h("span", { class: "wc-what" }, what), h("span", { class: "muted small" }, `on ${netName(chain)}`)),
        h("dl", { class: "facts" },
          fact(c.kind === "transfer" ? "To" : "Contract", h("span", { class: "mono break" }, grouped(q.to))),
          c.kind !== "transfer" && q.value !== "0x0" ? fact("Also sends", `${fmtAmount(q.amount_eth, 8)} ${n.symbol}`) : null,
          c.party ? fact(c.kind === "token_approve" ? "Spender" : "Recipient", h("span", { class: "mono break" }, grouped(c.party))) : null,
          c.amount ? fact("Amount (raw)", h("span", { class: `mono${c.amount === "unlimited" ? " wc-danger-text" : ""}` }, c.amount === "unlimited" ? "UNLIMITED" : c.amount)) : null,
          c.kind === "contract_call" ? fact("Data", h("span", { class: "mono" }, `${c.selector ?? ""} · ${c.data_bytes} bytes`)) : null,
          fact("Network fee", `at most ${fmtAmount(q.max_fee_eth, 8)} ${n.symbol}`),
          fact("Total at most", `${fmtAmount(q.total_eth, 8)} ${n.symbol}`),
          fact("Nonce", h("span", { class: "mono" }, String(parseInt(q.nonce, 16)))),
        ),
        notesList(prep.notes),
        simPanel(txSimulation(q, chain), () => { resimulate(wc.host.rpcFor(chain), q, render); render(); }),
      ].filter(Boolean) as Node[];
    }
    case "personal_sign":
      return [
        h("p", { class: "wc-what" }, "Sign a message"),
        h("pre", { class: `wc-msg${prep.text === null ? " hex" : ""}` }, prep.text ?? prep.message_hex),
        notesList(prep.notes),
        h("p", { class: "muted small" }, `Signed as your account on ${netName(chain)}. A signature can be used by whoever receives it; sign only what you expect.`),
      ].filter(Boolean) as Node[];
    case "typed_data": {
      const s = prep.summary;
      return [
        h("p", { class: "wc-what" }, `Sign ${s.primary_type || "typed data"}`),
        h("dl", { class: "facts" },
          fact("Domain", [s.domain_name, s.domain_version ? `v${s.domain_version}` : null].filter(Boolean).join(" ") || "—"),
          fact("Chain", s.domain_chain === null ? "not named" : netName(s.domain_chain)),
          s.verifying_contract ? fact("Contract", h("span", { class: "mono break" }, grouped(s.verifying_contract))) : null,
        ),
        notesList(prep.notes),
        h("details", { class: "detail" }, h("summary", null, "Full data"), h("pre", { class: "wc-msg" }, prettyJson(prep.typed_data))),
      ].filter(Boolean) as Node[];
    }
    case "switch_chain":
      return [h("p", { class: "wc-what" }, `Switch to ${prep.name}`), h("p", { class: "muted" }, prep.in_session ? "The dApp is already connected on this network; it asks to make it the active one." : `Adds ${prep.name} to this connection with the same account. Your phone has a reviewed profile for it.`)];
    default:
      return [];
  }
}

/** The dApp transaction simulated on the user's node for its chain (simulation.ts). */
function txSimulation(q: Quote, chain: number) { return simulationFor(wc.host.rpcFor(chain), q, render); }

function prettyJson(t: string) { try { return JSON.stringify(JSON.parse(t), null, 2); } catch { return t; } }

// ------------------------------------------------------------------ main view + settings hooks

/** Subtle line under the account card: connected dApps and waiting requests. */
export function wcHomeSlot(): HTMLElement {
  const waiting = shown().length;
  if (!wc.sessions.length && !waiting) {
    return h("div", { class: "wc-slot quiet" },
      h("span", { class: "muted small row" }, linkIcon(15), "No dApps connected"),
      h("button", { class: "chip-btn", onclick: openConnect }, "Connect a dApp"));
  }
  const names = wc.sessions.map((s) => s.meta.name);
  return h("div", { class: `wc-slot${waiting ? " busy" : ""}` },
    h("span", { class: "wc-dot" }),
    h("span", { class: "grow small" }, names.length ? `Connected to ${names.slice(0, 2).join(", ")}${names.length > 2 ? ` +${names.length - 2}` : ""}` : "WalletConnect"),
    waiting ? h("button", { class: "chip-btn primary", onclick: () => { wc.requestsHidden = false; render(); } }, `${waiting} request${waiting > 1 ? "s" : ""} waiting`) : null,
    h("button", { class: "chip-btn", onclick: openConnect, title: "Connect another dApp" }, "Connect"));
}

export function wcSettingsSection(): HTMLElement {
  const input = h("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: "32-character project ID", value: wc.projectId === "preview" ? "" : wc.projectId });
  const msg = h("p", { class: "field-msg" });
  const save = () => {
    const v = input.value.trim();
    if (v && !PROJECT_ID_RE.test(v)) { msg.textContent = "A project ID is 32 hexadecimal characters."; msg.className = "field-msg bad"; return; }
    if (v === wc.projectId) { msg.textContent = "Saved."; msg.className = "field-msg ok"; return; }
    const had = wc.engine.s === "ready" && isTauri;
    saveProjectId(v); wc.projectId = v;
    if (had) { msg.textContent = "Saved. Restart the app to use the new project ID."; msg.className = "field-msg warn"; return; }
    msg.textContent = v ? "Saved. Starting WalletConnect…" : "Removed."; msg.className = "field-msg ok";
    if (v) start(); else { wc.engine = { s: "off" }; render(); }
  };
  const relayErr = wc.engine.s === "ready" ? wc.backend?.relayError() ?? null : null;
  const status = wc.engine.s === "ready" ? (wc.backend?.online() ? ["accessory", "Relay connected"] : relayErr ? ["danger", "Relay error"] : ["none", "Ready (connects when needed)"])
    : wc.engine.s === "starting" ? ["android", "Starting…"] : wc.engine.s === "error" ? ["danger", "Didn't start"] : ["none", "Off"];
  return h("section", { class: "set" },
    h("h4", null, "WALLETCONNECT"),
    h("div", { class: "set-row" }, h("span", null, "Status"), h("span", { class: `chip ${status[0]}` }, h("i", { class: "dot" }), status[1])),
    wc.engine.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), wc.engine.message) : null,
    relayErr && !wc.backend?.online() ? h("p", { class: "inline-error" }, icon("alert", 15), relayErr) : null,
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Project ID"), input, msg),
    h("div", { class: "row gap" },
      h("button", { onclick: save }, "Save"),
      h("button", { class: "ghost", onclick: () => openExternal("https://cloud.reown.com") }, "Get a project ID", icon("external", 14))),
    !wc.projectId ? h("p", { class: "muted small" }, "WalletConnect is off until you add a project ID. Create a free project at cloud.reown.com and paste its ID here. It is stored only on this Mac; WalletConnect's relay sees it with each connection.") : null,
    h("div", { class: "set-row" }, h("span", null, "Connected dApps"), h("button", { class: "chip-btn", onclick: openConnect }, "Connect a dApp")),
    wcOnly().length ? h("ul", { class: "wc-sessions" }, wcOnly().map((s) => h("li", null,
      dappIcon(s.meta.icons[0], 28),
      h("div", { class: "grow" },
        h("div", { class: "wc-dapp-name small" }, s.meta.name),
        h("div", { class: "muted small" }, `${hostOf(s.meta.url)} · ${(s.namespaces.eip155?.chains ?? []).map((c) => netName(chainNum(c))).join(", ")}`),
        h("div", { class: "muted small" }, `Expires ${new Date(s.expiry * 1000).toLocaleDateString(undefined, { month: "short", day: "numeric" })}`)),
      h("button", { class: "danger-ghost chip-btn", onclick: () => disconnect(s.topic) }, "Disconnect"))))
      : h("p", { class: "muted small" }, "None. Sessions are kept across restarts until you disconnect them or they expire (7 days)."),
    notices.length ? h("details", { class: "detail" }, h("summary", null, "Recent WalletConnect events"), h("ul", { class: "wc-log" }, notices.map((n) => h("li", null, h("span", { class: "muted" }, new Date(n.time).toLocaleTimeString()), " ", n.text)))) : null,
  );
}

/** WalletConnect sessions only (browser extension sites have their own Settings section). */
const wcOnly = () => wc.sessions.filter((s) => !isExtTopic(s.topic));

export function mountWalletConnect(h0: WcHost) { startWalletConnect(h0, render); }
