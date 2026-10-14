// WalletConnect v2, wallet side. dApps connect by a pasted `wc:` link; their requests are shown here
// first (who is asking, what for) and can be rejected before anything reaches the phone.
//
// Trust boundaries:
//  * The SDK (wc-backend.ts) only carries messages. It cannot sign.
//  * What a dApp may ask is decided in Rust (wc.rs: `wc_prepare`, `wc_session_namespaces`). The
//    account offered to dApps comes from the pairing file there, never from the dApp or from here.
//  * Signatures come only from the existing phone commands: `sign_start` → `broadcast_verified` for
//    transactions (the Send flow's pipeline), `sign_message` / `sign_typed_data` for messages. Each
//    goes to the phone for review and returns only what Rust verified against the pinned signer.
//  * One request goes to the phone at a time; the rest wait in a visible queue.

import { api, call, registerPreview, onProgress, onEvent, openExternal, errText, isTauri, REVIEW_LIMIT_MS } from "./api";
import type { Quote, SendError } from "./api";
import { NETWORKS, byId, netName } from "./networks";
import { h, icon, short, shortHash, grouped, fmtAmount, copy, toast, fact } from "./ui";
import type { Backend, Events, ProposalIn, RequestIn, SessionIn, VerifyIn } from "./wc-backend";
import { createExtBackend, combine, isExtTopic, onExtChange } from "./extension";
import { explainSendError, explainPlain, asSendError } from "./errors";
import { clockLine, updateClocks, cancelButton } from "./send-flow";
import { simulationFor, resimulate, simPanel, gatedSendButton } from "./simulation";
import "./walletconnect.css";

// ------------------------------------------------------------------ host hooks (from main.ts)

export interface WcHost {
  /** Paired address (checksummed) for display, or null. Never sent to dApps from here. */
  paired(): string | null;
  rpcFor(chainId: number): string;
  /** A reason the phone can't take a request right now (other wallet on USB, Send in progress). */
  phoneBlocked(): string | null;
  /** The main view should re-render (indicator). */
  changed(): void;
  /** A transaction was broadcast: refresh activity and balance. */
  sent(chainId: number): void;
  openSettings(): void;
}

// ------------------------------------------------------------------ types shared with wc.rs

interface RpcError { code: number; message: string }
interface Note { level: "info" | "warn" | "danger"; text: string }
interface CallInfo { kind: "transfer" | "token_transfer" | "token_approve" | "contract_call"; selector: string | null; data_bytes: number; party: string | null; amount: string | null; phone_supported: boolean }
interface TypedSummary { primary_type: string; domain_name: string | null; domain_version: string | null; domain_chain: number | null; verifying_contract: string | null }
type Prepared =
  | { kind: "answer"; result: unknown }
  | { kind: "transaction"; chain_id: number; quote: Quote; call: CallInfo; notes: Note[] }
  | { kind: "personal_sign"; chain_id: number; message_hex: string; text: string | null; notes: Note[] }
  | { kind: "typed_data"; chain_id: number; typed_data: string; summary: TypedSummary; notes: Note[] }
  | { kind: "switch_chain"; chain_id: number; name: string; in_session: boolean };
interface ChainOffer { caip: string; id: number; name: string; supported: boolean; required: boolean }
interface SessionPlan { chains: ChainOffer[]; methods: string[]; refused_methods: string[]; required_refused_methods: string[]; other_namespaces: string[]; blocker: string | null }

const USER_REJECTED = 4001;
const INTERNAL = -32603;

// ------------------------------------------------------------------ bridge

const mock = () => import("./wc-mock");
registerPreview((cmd) => cmd.startsWith("wc_") || cmd === "dapp_icon", async () => (await mock()).mockInvoke);

/** The site that asked, only when it is trusted: the browser-reported origin (extension), or
 *  WalletConnect Verify's origin when it says VALID and does not flag it. Rust checks sign-in
 *  messages against it and passes it to the phone; anything else counts as unverified. */
const trustedOrigin = (v: VerifyIn | null): string | null =>
  v && v.origin && (v.source === "browser" || (v.validation === "VALID" && !v.isScam)) ? v.origin : null;

const rpcErrorOf = (e: unknown): RpcError =>
  e && typeof e === "object" && "code" in e && "message" in e ? { code: Number((e as RpcError).code), message: String((e as RpcError).message) } : { code: INTERNAL, message: errText(e) };

// ------------------------------------------------------------------ settings (local, non-secret)

const KEY = "phonevault.wc.v1";
function loadProjectId(): string {
  try { const v = JSON.parse(localStorage.getItem(KEY) ?? "{}").projectId; return typeof v === "string" ? v : ""; } catch { return ""; }
}
function saveProjectId(id: string) { try { localStorage.setItem(KEY, JSON.stringify({ projectId: id })); } catch { /* shown as not saved */ } }
const PROJECT_ID_RE = /^[0-9a-f]{32}$/i;

// ------------------------------------------------------------------ state

type Engine = { s: "off" } | { s: "starting" } | { s: "ready" } | { s: "error"; message: string };
let host: WcHost;
let backend: Backend | null = null;
let engine: Engine = { s: "off" };
let projectId = "";
let sessions: SessionIn[] = [];

let proposal: { p: ProposalIn; plan: SessionPlan | null; selected: Set<number>; busy: boolean; error: string | null } | null = null;
let connect: { uri: string; busy: boolean; error: string | null; waiting: boolean } | null = null;

type Stage =
  | { s: "waiting" }
  | { s: "preparing" }
  | { s: "review"; error?: string }
  | { s: "connecting"; t0: number }
  | { s: "on_phone"; t0: number }
  | { s: "verifying" }
  | { s: "broadcasting"; hash: string }
  | { s: "broadcast_failed"; hash: string; message: string }
  | { s: "done"; title: string; body: string; hash?: string; chain?: number }
  | { s: "failed"; title: string; body: string; detail?: string; retry: boolean; tone: "danger" | "warn" | "neutral" };
interface Item { req: RequestIn; prep: Prepared | null; stage: Stage; ticket: string | null; cancelling: boolean; answered: boolean }
const items = new Map<number, Item>();
let requestsHidden = false;
let phoneBusy = false;
const notices: { text: string; time: number }[] = [];

/** True while a WalletConnect request is with the phone (main.ts holds its own USB traffic). */
export const wcPhoneBusy = () => phoneBusy;

const inFlight = (it: Item) => ["connecting", "on_phone", "verifying", "broadcasting"].includes(it.stage.s);
const sessionOf = (topic: string) => sessions.find((s) => s.topic === topic);
const chainNum = (caip: string) => { const n = Number(caip.split(":")[1]); return Number.isFinite(n) ? n : 0; };
const hostOf = (url: string) => { try { return new URL(url).host; } catch { return url; } };
const RELAY_CHECK_MS = 500;
const RELAY_TIMEOUT_MS = 30_000;
const PAIRING_CHECK_MS = 1000;
const PENDING_SYNC_MS = 2000;

function notice(text: string) {
  notices.unshift({ text, time: Date.now() });
  notices.length = Math.min(notices.length, 6);
  toast(text.length > 80 ? text.slice(0, 77) + "…" : text);
}

// ------------------------------------------------------------------ engine

const events: Events = {
  proposal: (p) => { connect = null; openProposal(p); },
  changed: () => sync(true),
  requestExpired: (id) => {
    const it = items.get(id);
    if (!it) return;
    if (inFlight(it)) return; // checked again before anything is returned or broadcast
    items.delete(id);
    notice(`${dappName(it.req.topic)}: a ${it.req.method} request expired.`);
    sync();
  },
  proposalExpired: (id) => { if (proposal?.p.id === id) { proposal = null; notice("The connection request expired. Start again from the dApp."); render(); } },
  sessionGone: (topic, why) => {
    const s = sessionOf(topic);
    for (const [id, it] of items) if (it.req.topic === topic && !inFlight(it)) items.delete(id);
    if (s) notice(`${s.meta.name} ${why === "expired" ? "session expired" : "disconnected"}.`);
    sync();
  },
};

// The browser extension (extension.ts) shares these cards; it needs no project ID.
let ext: ReturnType<typeof createExtBackend> | null = null;

async function start() {
  ext ??= createExtBackend(events, (c) => host.rpcFor(c));
  backend = combine(null, ext);
  if (!isTauri) {
    const m = await mock();
    if (m.mockNoProjectId()) { engine = { s: "off" }; sync(); return; }
    projectId = projectId || "preview";
    backend = combine(m.createMockBackend(events), ext);
    engine = { s: "ready" }; sync(); return;
  }
  if (!projectId) { engine = { s: "off" }; sync(); return; }
  engine = { s: "starting" }; render();
  try {
    const { createSdkBackend } = await import("./wc-backend");
    backend = combine(await createSdkBackend(projectId, events), ext);
    engine = { s: "ready" };
    await checkSessions();
    sync();
  } catch (e) {
    engine = { s: "error", message: errText(e) };
    render();
  }
}

/** Disconnect sessions whose account is not the paired address (phone re-paired or forgotten). */
let lastPaired: string | null | undefined;
async function checkSessions() {
  if (!backend) return;
  for (const s of backend.sessions()) {
    let ok = false;
    try { ok = await call<boolean>("wc_session_matches", { namespaces: s.namespaces }); } catch { ok = false; }
    if (!ok) {
      try { await backend.disconnect(s.topic); } catch { /* gone already */ }
      notice(`Disconnected ${s.meta.name}: it was connected to a different account than the paired phone.`);
    }
  }
  sync();
}

let lastSnapshot = "";
function sync(periodic = false) {
  if (!backend) { render(); return; }
  sessions = backend.sessions();
  const pending = backend.requests();
  const ids = new Set(pending.map((r) => r.id));
  let fresh = false;
  for (const r of pending) {
    if (items.has(r.id)) continue;
    const it: Item = { req: r, prep: null, stage: { s: "waiting" }, ticket: null, cancelling: false, answered: false };
    items.set(r.id, it);
    fresh = true;
    // Transactions are quoted only when they reach the front (nonce, fees); everything else is
    // checked at once so read-only calls are answered and refused methods are refused right away.
    if (r.method !== "eth_sendTransaction") prepare(it);
  }
  for (const [id, it] of items) if (!ids.has(id) && !it.answered && !inFlight(it)) items.delete(id);
  const head = headItem();
  if (head && head.stage.s === "waiting") prepare(head);
  if (fresh) requestsHidden = false;
  const snap = `${backend.online()}|${sessions.map((x) => x.topic + (x.namespaces.eip155?.chains ?? []).join()).join()}|${[...items.keys()].join()}`;
  if (periodic && snap === lastSnapshot) return;
  lastSnapshot = snap;
  render();
}

/** Methods that get a card. Everything else is answered or refused without showing anything
 *  but a notice (read-only calls, refused methods, invalid params). */
const USER_METHODS = new Set(["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain"]);
const shown = () => [...items.values()].filter((it) => USER_METHODS.has(it.req.method));
/** The request the user is looking at: the oldest one needing attention. */
const headItem = (): Item | null => shown()[0] ?? null;

function paramsFor(r: RequestIn): unknown {
  // Typed data sent as an object is passed on as the text the phone will parse.
  if (r.method === "eth_signTypedData_v4" && Array.isArray(r.params) && r.params[1] && typeof r.params[1] === "object") return [r.params[0], JSON.stringify(r.params[1])];
  return r.params;
}

async function prepare(it: Item) {
  it.stage = { s: "preparing" };
  const session = sessionOf(it.req.topic);
  const chain = chainNum(it.req.chainId);
  try {
    if (!session) throw { code: 4100, message: "unknown session" } satisfies RpcError;
    const prep = await call<Prepared>("wc_prepare", {
      rpcUrl: NETWORKS.some((n) => n.id === chain) ? host.rpcFor(chain) : null,
      chain: it.req.chainId, sessionChains: session.namespaces.eip155?.chains ?? [], method: it.req.method, params: paramsFor(it.req),
      origin: trustedOrigin(it.req.verify),
    });
    if (!items.has(it.req.id)) return;
    if (prep.kind === "answer") { await answer(it, prep.result); items.delete(it.req.id); sync(); return; }
    it.prep = prep;
    it.stage = { s: "review" };
  } catch (e) {
    if (!items.has(it.req.id)) return;
    const err = rpcErrorOf(e);
    // A transaction the node couldn't quote gets a card (try again / reject) instead of a silent refusal.
    if (it.req.method === "eth_sendTransaction" && (err.code === INTERNAL || err.code === -32003)) {
      it.stage = { s: "failed", title: "Couldn't prepare this transaction", body: err.message, retry: true, tone: "warn" };
    } else {
      await answerError(it, err.code, err.message);
      items.delete(it.req.id);
      // "Blocked: <site> asked you to sign in to <domain>…" (a sign-in for another site) stands on its own
      notice(err.message.startsWith("Blocked:") ? err.message : `Refused ${it.req.method} from ${session?.meta.name ?? "a dApp"}: ${err.message}`);
    }
  }
  render();
}

async function answer(it: Item, result: unknown) {
  it.answered = true;
  try { await backend!.respond(it.req.topic, it.req.id, result); } catch (e) { notice(`Couldn't reply to the dApp: ${errText(e)}`); }
}
async function answerError(it: Item, code: number, message: string) {
  it.answered = true;
  try { await backend!.respondError(it.req.topic, it.req.id, code, message); } catch { /* the dApp may be gone */ }
}

function closeItem(it: Item) { items.delete(it.req.id); sync(); }

async function reject(it: Item) {
  await answerError(it, USER_REJECTED, "User rejected the request.");
  closeItem(it);
}

function finalFail(it: Item, code: number, message: string, title: string, body: string, tone: "danger" | "warn" | "neutral", detail?: string) {
  answerError(it, code, message);
  it.stage = { s: "failed", title, body, detail, retry: false, tone };
}

// ------------------------------------------------------------------ approve: into the phone pipeline

async function approve(it: Item) {
  const prep = it.prep;
  if (!prep || !backend) return;
  if (prep.kind === "switch_chain") return switchChain(it, prep.chain_id, prep.in_session);
  const blocked = host.phoneBlocked();
  if (blocked) { it.stage = { s: "review", error: blocked }; render(); return; }
  if (phoneBusy) { it.stage = { s: "review", error: "The phone is busy with another request." }; render(); return; }
  phoneBusy = true;
  try {
    if (prep.kind === "transaction") await sendTransaction(it, prep.quote, prep.chain_id);
    else if (prep.kind === "personal_sign" || prep.kind === "typed_data") await signMessage(it, prep);
  } finally { phoneBusy = false; render(); }
}

/** eth_sendTransaction: the Send flow's pipeline, unchanged: sign_start (phone review + verify.rs)
 *  → broadcast_verified (only a transaction verified in this session, by hash) → hash to the dApp. */
async function sendTransaction(it: Item, quote: Quote, chain: number) {
  const ticket = crypto.randomUUID();
  it.ticket = ticket; it.cancelling = false;
  it.stage = { s: "connecting", t0: Date.now() }; render();
  let hash: string;
  try {
    hash = (await api.signStart(ticket, quote)).hash;
  } catch (e) {
    txFailure(it, asSendError(e));
    return;
  } finally { it.ticket = null; }
  if (!backend!.isPending(it.req.id)) {
    it.answered = true;
    it.stage = { s: "failed", title: "The dApp stopped waiting", body: "Your phone signed it, but the dApp is no longer waiting for an answer, so it was not broadcast. Nothing was sent.", retry: false, tone: "warn" };
    return;
  }
  await broadcast(it, hash, chain);
}

async function broadcast(it: Item, hash: string, chain: number) {
  it.stage = { s: "broadcasting", hash }; render();
  try { await api.broadcast(host.rpcFor(chain), hash); }
  catch (e) {
    const m = errText(e);
    if (!/already known|known transaction/i.test(m)) { it.stage = { s: "broadcast_failed", hash, message: m }; render(); return; }
  }
  await answer(it, hash);
  it.stage = { s: "done", title: `Sent on ${netName(chain)}`, body: "Signed on your phone, verified on this Mac and broadcast. The dApp has the transaction hash.", hash, chain };
  host.sent(chain);
}

function txFailure(it: Item, err: SendError) {
  const x = explainSendError(err, { chain: "eth" });
  switch (err.kind) {
    case "busy": it.stage = { s: "review", error: "The phone is still finishing another request. Try again in a few seconds." }; return;
    case "rejected": return finalFail(it, USER_REJECTED, "User rejected the request on the phone.", x.title, "No signature was created. The dApp was told you declined.", "neutral");
    case "cancelled": return finalFail(it, USER_REJECTED, "User cancelled the request.", x.title, x.body, "neutral");
    case "verify": return finalFail(it, INTERNAL, "The signature failed verification and was discarded.", x.title, "What came back does not match this request, or was not signed by your paired phone. It was thrown away and nothing was broadcast.", "danger", err.message);
    case "phone_error": return finalFail(it, INTERNAL, `The phone refused the request: ${err.message}`, x.title, x.body, "warn", err.message);
    case "not_paired": return finalFail(it, 4100, "The wallet is not paired.", x.title, x.body, "warn");
    case "reverts": return finalFail(it, INTERNAL, `The transaction would revert: ${err.message}`, x.title, `Simulated on your node, this transaction fails (${err.message}). It was not sent to your phone, and the dApp was told.`, "warn");
  }
  // anything else can be tried again, or rejected here
  it.stage = { s: "failed", title: x.title, body: x.body, detail: err.message, retry: true, tone: x.danger ? "danger" : "warn" };
}

async function signMessage(it: Item, prep: Extract<Prepared, { kind: "personal_sign" | "typed_data" }>) {
  it.stage = { s: "on_phone", t0: Date.now() }; render();
  try {
    const r = prep.kind === "personal_sign"
      ? await call<{ signature: string }>("sign_message", { message: prep.message_hex, isHex: true, chainId: prep.chain_id, origin: trustedOrigin(it.req.verify) })
      : await call<{ signature: string }>("sign_typed_data", { typedData: prep.typed_data, chainId: prep.chain_id, origin: trustedOrigin(it.req.verify) });
    if (!backend!.isPending(it.req.id)) {
      it.answered = true;
      it.stage = { s: "failed", title: "The dApp stopped waiting", body: "Your phone signed it, but the dApp is no longer waiting, so the signature was not sent anywhere.", retry: false, tone: "warn" };
      return;
    }
    await answer(it, r.signature);
    it.stage = { s: "done", title: "Signed", body: "Signed on your phone; this Mac recomputed the digest and checked the signer before sending the signature to the dApp." };
  } catch (e) {
    const m = errText(e);
    if (m.startsWith("Blocked:")) return finalFail(it, 4100, m, "Blocked: sign-in for another site", m, "danger");
    if (/rejected on the phone/i.test(m)) return finalFail(it, USER_REJECTED, "User rejected the request on the phone.", "Rejected on the phone", "No signature was created. The dApp was told you declined.", "neutral");
    if (/^phone error:/i.test(m)) return finalFail(it, INTERNAL, `The phone refused the request: ${m.replace(/^phone error:\s*/i, "")}`, "The phone refused the request", explainPlain(m.replace(/^phone error:\s*/i, "")), "warn");
    if (/no Android device|held by another program|did not answer|not reading USB|re-enumerate|USB|timed out/i.test(m))
      { it.stage = { s: "failed", title: "The phone didn't answer", body: "Nothing was signed. Plug the phone in, unlock it, and try again, or reject the request.", detail: m, retry: true, tone: "warn" }; return; }
    if (/digest|recovered signer|claimed address|signature|unexpected fields|correlate/i.test(m))
      return finalFail(it, INTERNAL, "The signature failed verification and was discarded.", "Signature failed verification", "What came back does not match this request, or was not signed by your paired phone. It was thrown away.", "danger", m);
    return finalFail(it, INTERNAL, m, "Not signed", m, "warn");
  }
}

async function switchChain(it: Item, chain: number, inSession: boolean) {
  const s = sessionOf(it.req.topic);
  if (!s || !backend) return;
  it.stage = { s: "preparing" }; render();
  try {
    if (!inSession) {
      const ns = await call<unknown>("wc_add_chain", { namespaces: s.namespaces, chainId: chain });
      await backend.update(s.topic, ns);
    }
    await backend.emitChainChanged(s.topic, chain);
    await answer(it, null);
    closeItem(it);
    toast(`${s.meta.name} switched to ${netName(chain)}`);
  } catch (e) {
    finalFail(it, INTERNAL, errText(e), "Couldn't switch network", errText(e), "warn");
    render();
  }
}

async function cancel(it: Item) {
  it.cancelling = true; render();
  try { if (it.ticket) await api.signCancel(it.ticket); } catch { /* the command result says */ }
}

onProgress((ticket, stage) => {
  for (const it of items.values()) {
    if (it.ticket !== ticket) continue;
    if (stage === "delivered" && it.stage.s === "connecting") it.stage = { s: "on_phone", t0: Date.now() };
    else if (stage === "verifying" && it.stage.s === "on_phone") it.stage = { s: "verifying" };
    render();
  }
});

// ------------------------------------------------------------------ proposals

async function openProposal(p: ProposalIn) {
  proposal = { p, plan: null, selected: new Set(), busy: false, error: null };
  render();
  try {
    const plan = await call<SessionPlan>("wc_plan_session", { required: p.required, optional: p.optional });
    if (proposal?.p.id !== p.id) return;
    proposal.plan = plan;
    for (const c of plan.chains) if (c.supported) proposal.selected.add(c.id);
  } catch (e) { if (proposal) proposal.error = errText(e); }
  render();
}

async function approveProposal() {
  if (!proposal || !backend) return;
  const pr = proposal;
  if (!host.paired()) { pr.error = "Pair your phone first: the dApp is given the paired phone's address."; render(); return; }
  pr.busy = true; pr.error = null; render();
  try {
    const namespaces = await call<unknown>("wc_session_namespaces", { required: pr.p.required, optional: pr.p.optional, selected: [...pr.selected] });
    await backend.approve(pr.p.id, namespaces);
    proposal = null;
    toast(`Connected to ${pr.p.meta.name}`);
    sync();
  } catch (e) { pr.busy = false; pr.error = errText(e); render(); }
}

async function rejectProposal() {
  if (!proposal || !backend) return;
  const id = proposal.p.id;
  proposal = null; render();
  try { await backend.reject(id); } catch { /* expired already */ }
}

async function pair() {
  if (!connect || !backend) return;
  const uri = connect.uri.trim();
  if (!uri.startsWith("wc:")) { connect.error = "A WalletConnect link starts with wc:"; render(); return; }
  if (/@1\b/.test(uri)) { connect.error = "That is an old WalletConnect v1 link. The dApp needs WalletConnect v2."; render(); return; }
  if (!/@2\b/.test(uri) || !/symKey=/.test(uri)) { connect.error = "That doesn't look like a complete WalletConnect v2 link. Copy it again from the dApp."; render(); return; }
  connect.busy = true; connect.error = null; render();
  try {
    const b = backend;
    const t0 = Date.now();
    let poll = 0;
    const relayDown = new Promise<never>((_, fail) => {
      poll = window.setInterval(() => {
        const e = b.relayError();
        if (e && /project not found|unauthori[sz]ed|invalid.*project/i.test(e)) fail(new Error(`The WalletConnect relay refused the project ID (${e}). Check it in Settings → WalletConnect.`));
        else if (Date.now() - t0 > RELAY_TIMEOUT_MS) fail(new Error(`Couldn't reach the WalletConnect relay${e ? ` (${e})` : ""}. Check the internet connection.`));
      }, RELAY_CHECK_MS);
    });
    try { await Promise.race([b.pair(uri), relayDown]); } finally { clearInterval(poll); }
    if (connect) { connect.busy = false; connect.waiting = true; render(); }
  } catch (e) {
    if (connect) { connect.busy = false; connect.error = /expired/i.test(errText(e)) ? "This link has expired or was already used. Get a new one from the dApp." : errText(e); render(); }
  }
}

async function disconnect(topic: string) {
  if (!backend) return;
  const s = sessionOf(topic);
  for (const [id, it] of items) if (it.req.topic === topic && !inFlight(it)) { await answerError(it, 4100, "Disconnected"); items.delete(id); }
  try { await backend.disconnect(topic); } catch (e) { notice(errText(e)); }
  if (s) toast(`Disconnected ${s.meta.name}`);
  sync();
}

function openConnect() {
  connect = { uri: "", busy: false, error: null, waiting: false };
  render();
}

// ------------------------------------------------------------------ rendering: shared bits

function linkIcon(size = 18): SVGSVGElement {
  const wrap = document.createElement("span");
  wrap.innerHTML = `<svg class="ic" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 14a4.5 4.5 0 0 0 6.4 0l3-3a4.5 4.5 0 0 0-6.4-6.4l-1 1"/><path d="M14 10a4.5 4.5 0 0 0-6.4 0l-3 3a4.5 4.5 0 0 0 6.4 6.4l1-1"/></svg>`;
  return wrap.firstElementChild as SVGSVGElement;
}

const dappName = (topic: string) => sessionOf(topic)?.meta.name ?? "A dApp";

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
  host?.changed();
  const content = proposal ? proposalCard() : connect ? connectCard() : shown().length && !requestsHidden ? requestsCard() : null;
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
  const c = connect!;
  if (engine.s !== "ready") {
    return h("section", { class: "card modal wc-modal", role: "dialog", "aria-modal": "true" },
      h("p", { class: "kicker" }, "WalletConnect"),
      h("h3", null, engine.s === "starting" ? "Starting WalletConnect…" : engine.s === "error" ? "WalletConnect didn't start" : "Add a project ID first"),
      engine.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), engine.message) : null,
      engine.s === "off" ? h("p", { class: "muted" }, "WalletConnect needs a free project ID from Reown (cloud.reown.com). Paste it in Settings → WalletConnect. It is stored only on this Mac.") : null,
      h("div", { class: "actions" },
        engine.s === "off" || engine.s === "error" ? h("button", { class: "big primary", onclick: () => { connect = null; render(); host.openSettings(); } }, "Open Settings") : null,
        h("button", { class: "big", onclick: () => { connect = null; render(); } }, "Close")));
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
      h("button", { class: "big", onclick: () => { connect = null; render(); } }, "Cancel")));
}

function proposalCard() {
  const pr = proposal!;
  const { meta, verify } = pr.p;
  const plan = pr.plan;
  const paired = host.paired();
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
  const later = h("button", { class: "link wc-later", onclick: () => { requestsHidden = true; render(); }, title: "Hide this; it stays waiting on the main view" }, "Decide later");
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
        simPanel(txSimulation(q, chain), () => { resimulate(host.rpcFor(chain), q, render); render(); }),
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
function txSimulation(q: Quote, chain: number) { return simulationFor(host.rpcFor(chain), q, render); }

function prettyJson(t: string) { try { return JSON.stringify(JSON.parse(t), null, 2); } catch { return t; } }

// ------------------------------------------------------------------ main view + settings hooks

/** Subtle line under the account card: connected dApps and waiting requests. */
export function wcHomeSlot(): HTMLElement {
  const waiting = shown().length;
  if (!sessions.length && !waiting) {
    return h("div", { class: "wc-slot quiet" },
      h("span", { class: "muted small row" }, linkIcon(15), "No dApps connected"),
      h("button", { class: "chip-btn", onclick: openConnect }, "Connect a dApp"));
  }
  const names = sessions.map((s) => s.meta.name);
  return h("div", { class: `wc-slot${waiting ? " busy" : ""}` },
    h("span", { class: "wc-dot" }),
    h("span", { class: "grow small" }, names.length ? `Connected to ${names.slice(0, 2).join(", ")}${names.length > 2 ? ` +${names.length - 2}` : ""}` : "WalletConnect"),
    waiting ? h("button", { class: "chip-btn primary", onclick: () => { requestsHidden = false; render(); } }, `${waiting} request${waiting > 1 ? "s" : ""} waiting`) : null,
    h("button", { class: "chip-btn", onclick: openConnect, title: "Connect another dApp" }, "Connect"));
}

export function wcSettingsSection(): HTMLElement {
  const input = h("input", { type: "text", spellcheck: "false", autocomplete: "off", placeholder: "32-character project ID", value: projectId === "preview" ? "" : projectId });
  const msg = h("p", { class: "field-msg" });
  const save = () => {
    const v = input.value.trim();
    if (v && !PROJECT_ID_RE.test(v)) { msg.textContent = "A project ID is 32 hexadecimal characters."; msg.className = "field-msg bad"; return; }
    if (v === projectId) { msg.textContent = "Saved."; msg.className = "field-msg ok"; return; }
    const had = engine.s === "ready" && isTauri;
    saveProjectId(v); projectId = v;
    if (had) { msg.textContent = "Saved. Restart the app to use the new project ID."; msg.className = "field-msg warn"; return; }
    msg.textContent = v ? "Saved. Starting WalletConnect…" : "Removed."; msg.className = "field-msg ok";
    if (v) start(); else { engine = { s: "off" }; render(); }
  };
  const relayErr = engine.s === "ready" ? backend?.relayError() ?? null : null;
  const status = engine.s === "ready" ? (backend?.online() ? ["accessory", "Relay connected"] : relayErr ? ["danger", "Relay error"] : ["none", "Ready (connects when needed)"])
    : engine.s === "starting" ? ["android", "Starting…"] : engine.s === "error" ? ["danger", "Didn't start"] : ["none", "Off"];
  return h("section", { class: "set" },
    h("h4", null, "WALLETCONNECT"),
    h("div", { class: "set-row" }, h("span", null, "Status"), h("span", { class: `chip ${status[0]}` }, h("i", { class: "dot" }), status[1])),
    engine.s === "error" ? h("p", { class: "inline-error" }, icon("alert", 15), engine.message) : null,
    relayErr && !backend?.online() ? h("p", { class: "inline-error" }, icon("alert", 15), relayErr) : null,
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Project ID"), input, msg),
    h("div", { class: "row gap" },
      h("button", { onclick: save }, "Save"),
      h("button", { class: "ghost", onclick: () => openExternal("https://cloud.reown.com") }, "Get a project ID", icon("external", 14))),
    !projectId ? h("p", { class: "muted small" }, "WalletConnect is off until you add a project ID. Create a free project at cloud.reown.com and paste its ID here. It is stored only on this Mac; WalletConnect's relay sees it with each connection.") : null,
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
const wcOnly = () => sessions.filter((s) => !isExtTopic(s.topic));

export function mountWalletConnect(h0: WcHost) {
  host = h0;
  onExtChange(() => host.changed());
  // The bridge refused a browser request before it reached a card (a sign-in for another site).
  void onEvent<{ origin: string; message: string }>("bridge-blocked", (b) => { notice(b.message); render(); });
  projectId = loadProjectId();
  start();
  // pairing changes (forget / re-pair) end sessions offered with the old address
  window.setInterval(() => {
    const p = host.paired();
    if (lastPaired !== undefined && p !== lastPaired) checkSessions();
    lastPaired = p;
  }, PAIRING_CHECK_MS);
  // the SDK surfaces queued requests only through its pending store
  window.setInterval(() => { if (backend) sync(true); }, PENDING_SYNC_MS);
}
