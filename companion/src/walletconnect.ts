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
//
// This file is the engine (sessions, requests, the phone pipeline); the cards and the Settings
// section are drawn by wc-view.ts.

import { api, call, registerPreview, onProgress, onEvent, errText, isTauri } from "./api";
import type { Quote, SendError } from "./api";
import { NETWORKS, netName } from "./networks";
import { toast } from "./ui";
import type { Backend, Events, ProposalIn, RequestIn, SessionIn, VerifyIn } from "./wc-backend";
import { createExtBackend, combine, onExtChange } from "./extension";
import { explainSendError, explainPlain, asSendError } from "./errors";
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
export interface Note { level: "info" | "warn" | "danger"; text: string }
interface CallInfo { kind: "transfer" | "token_transfer" | "token_approve" | "contract_call"; selector: string | null; data_bytes: number; party: string | null; amount: string | null; phone_supported: boolean }
interface TypedSummary { primary_type: string; domain_name: string | null; domain_version: string | null; domain_chain: number | null; verifying_contract: string | null }
export type Prepared =
  | { kind: "answer"; result: unknown }
  | { kind: "transaction"; chain_id: number; quote: Quote; call: CallInfo; notes: Note[] }
  | { kind: "personal_sign"; chain_id: number; message_hex: string; text: string | null; notes: Note[] }
  | { kind: "typed_data"; chain_id: number; typed_data: string; summary: TypedSummary; notes: Note[] }
  | { kind: "switch_chain"; chain_id: number; name: string; in_session: boolean };
interface ChainOffer { caip: string; id: number; name: string; supported: boolean; required: boolean }
interface SessionPlan { chains: ChainOffer[]; methods: string[]; refused_methods: string[]; required_refused_methods: string[]; other_namespaces: string[]; blocker: string | null }

const USER_REJECTED = 4001;
export const INTERNAL = -32603;

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
export function saveProjectId(id: string) { try { localStorage.setItem(KEY, JSON.stringify({ projectId: id })); } catch { /* shown as not saved */ } }
export const PROJECT_ID_RE = /^[0-9a-f]{32}$/i;

// ------------------------------------------------------------------ state

/** The rendering half (wc-view.ts) draws the cards; set by startWalletConnect(). */
let renderView: () => void = () => {};
const render = () => renderView();

type Engine = { s: "off" } | { s: "starting" } | { s: "ready" } | { s: "error"; message: string };
/** State the rendering half (wc-view.ts) reads and changes. `host` is set by startWalletConnect(). */
export const wc: {
  host: WcHost;
  backend: Backend | null;
  engine: Engine;
  projectId: string;
  sessions: SessionIn[];
  proposal: { p: ProposalIn; plan: SessionPlan | null; selected: Set<number>; busy: boolean; error: string | null } | null;
  connect: { uri: string; busy: boolean; error: string | null; waiting: boolean } | null;
  /** the request cards were put away ("Decide later") */
  requestsHidden: boolean;
} = { host: undefined as unknown as WcHost, backend: null, engine: { s: "off" }, projectId: "", sessions: [], proposal: null, connect: null, requestsHidden: false };

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
export interface Item { req: RequestIn; prep: Prepared | null; stage: Stage; ticket: string | null; cancelling: boolean; answered: boolean }
const items = new Map<number, Item>();
let phoneBusy = false;
export const notices: { text: string; time: number }[] = [];

/** True while a WalletConnect request is with the phone (main.ts holds its own USB traffic). */
export const wcPhoneBusy = () => phoneBusy;

const inFlight = (it: Item) => ["connecting", "on_phone", "verifying", "broadcasting"].includes(it.stage.s);
export const sessionOf = (topic: string) => wc.sessions.find((s) => s.topic === topic);
export const dappName = (topic: string) => sessionOf(topic)?.meta.name ?? "A site";
export const chainNum = (caip: string) => { const n = Number(caip.split(":")[1]); return Number.isFinite(n) ? n : 0; };
export const hostOf = (url: string) => { try { return new URL(url).host; } catch { return url; } };
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
  proposal: (p) => { wc.connect = null; openProposal(p); },
  changed: () => sync(true),
  requestExpired: (id) => {
    const it = items.get(id);
    if (!it) return;
    if (inFlight(it)) return; // checked again before anything is returned or broadcast
    items.delete(id);
    notice(`${dappName(it.req.topic)}: a ${it.req.method} request expired.`);
    sync();
  },
  proposalExpired: (id) => { if (wc.proposal?.p.id === id) { wc.proposal = null; notice("The connection request expired. Start again from the site."); render(); } },
  sessionGone: (topic, why) => {
    const s = sessionOf(topic);
    for (const [id, it] of items) if (it.req.topic === topic && !inFlight(it)) items.delete(id);
    if (s) notice(`${s.meta.name} ${why === "expired" ? "session expired" : "disconnected"}.`);
    sync();
  },
};

// The browser extension (extension.ts) shares these cards; it needs no project ID.
let ext: ReturnType<typeof createExtBackend> | null = null;

export async function start() {
  ext ??= createExtBackend(events, (c) => wc.host.rpcFor(c));
  wc.backend = combine(null, ext);
  if (!isTauri) {
    const m = await mock();
    if (m.mockNoProjectId()) { wc.engine = { s: "off" }; sync(); return; }
    wc.projectId = wc.projectId || "preview";
    wc.backend = combine(m.createMockBackend(events), ext);
    wc.engine = { s: "ready" }; sync(); return;
  }
  if (!wc.projectId) { wc.engine = { s: "off" }; sync(); return; }
  wc.engine = { s: "starting" }; render();
  try {
    const { createSdkBackend } = await import("./wc-backend");
    wc.backend = combine(await createSdkBackend(wc.projectId, events), ext);
    wc.engine = { s: "ready" };
    await checkSessions();
    sync();
  } catch (e) {
    wc.engine = { s: "error", message: errText(e) };
    render();
  }
}

/** Disconnect sessions whose account is not the paired address (phone re-paired or forgotten). */
let lastPaired: string | null | undefined;
async function checkSessions() {
  if (!wc.backend) return;
  for (const s of wc.backend.sessions()) {
    let ok = false;
    try { ok = await call<boolean>("wc_session_matches", { namespaces: s.namespaces }); } catch { ok = false; }
    if (!ok) {
      try { await wc.backend.disconnect(s.topic); } catch { /* gone already */ }
      notice(`Disconnected ${s.meta.name}: it was connected to a different account than the paired phone.`);
    }
  }
  sync();
}

let lastSnapshot = "";
function sync(periodic = false) {
  if (!wc.backend) { render(); return; }
  wc.sessions = wc.backend.sessions();
  const pending = wc.backend.requests();
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
  if (fresh) wc.requestsHidden = false;
  const snap = `${wc.backend.online()}|${wc.sessions.map((x) => x.topic + (x.namespaces.eip155?.chains ?? []).join()).join()}|${[...items.keys()].join()}`;
  if (periodic && snap === lastSnapshot) return;
  lastSnapshot = snap;
  render();
}

/** Methods that get a card. Everything else is answered or refused without showing anything
 *  but a notice (read-only calls, refused methods, invalid params). */
const USER_METHODS = new Set(["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain"]);
export const shown = () => [...items.values()].filter((it) => USER_METHODS.has(it.req.method));
/** The request the user is looking at: the oldest one needing attention. */
const headItem = (): Item | null => shown()[0] ?? null;

function paramsFor(r: RequestIn): unknown {
  // Typed data sent as an object is passed on as the text the phone will parse.
  if (r.method === "eth_signTypedData_v4" && Array.isArray(r.params) && r.params[1] && typeof r.params[1] === "object") return [r.params[0], JSON.stringify(r.params[1])];
  return r.params;
}

export async function prepare(it: Item) {
  it.stage = { s: "preparing" };
  const session = sessionOf(it.req.topic);
  const chain = chainNum(it.req.chainId);
  try {
    if (!session) throw { code: 4100, message: "unknown session" } satisfies RpcError;
    const prep = await call<Prepared>("wc_prepare", {
      rpcUrl: NETWORKS.some((n) => n.id === chain) ? wc.host.rpcFor(chain) : null,
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
      notice(err.message.startsWith("Blocked:") ? err.message : `Refused ${it.req.method} from ${session?.meta.name ?? "a site"}: ${err.message}`);
    }
  }
  render();
}

async function answer(it: Item, result: unknown) {
  it.answered = true;
  try { await wc.backend!.respond(it.req.topic, it.req.id, result); } catch (e) { notice(`Couldn't reply to the site: ${errText(e)}`); }
}
async function answerError(it: Item, code: number, message: string) {
  it.answered = true;
  try { await wc.backend!.respondError(it.req.topic, it.req.id, code, message); } catch { /* the dApp may be gone */ }
}

export function closeItem(it: Item) { items.delete(it.req.id); sync(); }

export async function reject(it: Item) {
  await answerError(it, USER_REJECTED, "User rejected the request.");
  closeItem(it);
}

export function finalFail(it: Item, code: number, message: string, title: string, body: string, tone: "danger" | "warn" | "neutral", detail?: string) {
  answerError(it, code, message);
  it.stage = { s: "failed", title, body, detail, retry: false, tone };
}

// ------------------------------------------------------------------ approve: into the phone pipeline

export async function approve(it: Item) {
  const prep = it.prep;
  if (!prep || !wc.backend) return;
  if (prep.kind === "switch_chain") return switchChain(it, prep.chain_id, prep.in_session);
  const blocked = wc.host.phoneBlocked();
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
  if (!wc.backend!.isPending(it.req.id)) {
    it.answered = true;
    it.stage = { s: "failed", title: "The site stopped waiting", body: "Your phone signed it, but the site is no longer waiting for an answer. Nothing was sent to the network.", retry: false, tone: "warn" };
    return;
  }
  await broadcast(it, hash, chain);
}

export async function broadcast(it: Item, hash: string, chain: number) {
  it.stage = { s: "broadcasting", hash }; render();
  try { await api.broadcast(wc.host.rpcFor(chain), hash); }
  catch (e) {
    const m = errText(e);
    if (!/already known|known transaction/i.test(m)) { it.stage = { s: "broadcast_failed", hash, message: m }; render(); return; }
  }
  await answer(it, hash);
  it.stage = { s: "done", title: `Sent on ${netName(chain)}`, body: "Signed on your phone, verified on this Mac and sent to the network. The site has the transaction hash.", hash, chain };
  wc.host.sent(chain);
}

function txFailure(it: Item, err: SendError) {
  const x = explainSendError(err, { chain: "eth" });
  switch (err.kind) {
    case "busy": it.stage = { s: "review", error: "The phone is still finishing another request. Try again in a few seconds." }; return;
    case "rejected": return finalFail(it, USER_REJECTED, "User rejected the request on the phone.", x.title, "No signature was created. The site was told you declined.", "neutral");
    case "cancelled": return finalFail(it, USER_REJECTED, "User cancelled the request.", x.title, x.body, "neutral");
    case "verify": return finalFail(it, INTERNAL, "The signature failed verification and was discarded.", x.title, "What came back does not match this request, or was not signed by your paired phone. It was thrown away and nothing was sent to the network.", "danger", err.message);
    case "phone_error": return finalFail(it, INTERNAL, `The phone refused the request: ${err.message}`, x.title, x.body, "warn", err.message);
    case "not_paired": return finalFail(it, 4100, "Phone Vault Companion isn't paired with a phone yet.", x.title, x.body, "warn");
    case "reverts": return finalFail(it, INTERNAL, `The transaction would revert: ${err.message}`, x.title, `Simulated on your node, this transaction fails (${err.message}). It was not sent to your phone, and the site was told.`, "warn");
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
    if (!wc.backend!.isPending(it.req.id)) {
      it.answered = true;
      it.stage = { s: "failed", title: "The site stopped waiting", body: "Your phone signed it, but the site is no longer waiting, so the signature was not sent anywhere.", retry: false, tone: "warn" };
      return;
    }
    await answer(it, r.signature);
    it.stage = { s: "done", title: "Signed", body: "Signed on your phone; this Mac recomputed the digest and checked the signer before sending the signature to the site." };
  } catch (e) {
    const m = errText(e);
    if (m.startsWith("Blocked:")) return finalFail(it, 4100, m, "Blocked: sign-in for another site", m, "danger");
    if (/rejected on the phone/i.test(m)) return finalFail(it, USER_REJECTED, "User rejected the request on the phone.", "Rejected on the phone", "No signature was created. The site was told you declined.", "neutral");
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
  if (!s || !wc.backend) return;
  it.stage = { s: "preparing" }; render();
  try {
    if (!inSession) {
      const ns = await call<unknown>("wc_add_chain", { namespaces: s.namespaces, chainId: chain });
      await wc.backend.update(s.topic, ns);
    }
    await wc.backend.emitChainChanged(s.topic, chain);
    await answer(it, null);
    closeItem(it);
    toast(`${s.meta.name} switched to ${netName(chain)}`);
  } catch (e) {
    finalFail(it, INTERNAL, errText(e), "Couldn't switch network", errText(e), "warn");
    render();
  }
}

export async function cancel(it: Item) {
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
  wc.proposal = { p, plan: null, selected: new Set(), busy: false, error: null };
  render();
  try {
    const plan = await call<SessionPlan>("wc_plan_session", { required: p.required, optional: p.optional });
    if (wc.proposal?.p.id !== p.id) return;
    wc.proposal.plan = plan;
    for (const c of plan.chains) if (c.supported) wc.proposal.selected.add(c.id);
  } catch (e) { if (wc.proposal) wc.proposal.error = errText(e); }
  render();
}

export async function approveProposal() {
  if (!wc.proposal || !wc.backend) return;
  const pr = wc.proposal;
  if (!wc.host.paired()) { pr.error = "Pair your phone first: the site is given the paired phone's address."; render(); return; }
  pr.busy = true; pr.error = null; render();
  try {
    const namespaces = await call<unknown>("wc_session_namespaces", { required: pr.p.required, optional: pr.p.optional, selected: [...pr.selected] });
    await wc.backend.approve(pr.p.id, namespaces);
    wc.proposal = null;
    toast(`Connected to ${pr.p.meta.name}`);
    sync();
  } catch (e) { pr.busy = false; pr.error = errText(e); render(); }
}

export async function rejectProposal() {
  if (!wc.proposal || !wc.backend) return;
  const id = wc.proposal.p.id;
  wc.proposal = null; render();
  try { await wc.backend.reject(id); } catch { /* expired already */ }
}

export async function pair() {
  if (!wc.connect || !wc.backend) return;
  const uri = wc.connect.uri.trim();
  if (!uri.startsWith("wc:")) { wc.connect.error = "A WalletConnect link starts with wc:"; render(); return; }
  if (/@1\b/.test(uri)) { wc.connect.error = "That is an old WalletConnect v1 link. The site needs WalletConnect v2."; render(); return; }
  if (!/@2\b/.test(uri) || !/symKey=/.test(uri)) { wc.connect.error = "That doesn't look like a complete WalletConnect v2 link. Copy it again from the site."; render(); return; }
  wc.connect.busy = true; wc.connect.error = null; render();
  try {
    const b = wc.backend;
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
    if (wc.connect) { wc.connect.busy = false; wc.connect.waiting = true; render(); }
  } catch (e) {
    if (wc.connect) { wc.connect.busy = false; wc.connect.error = /expired/i.test(errText(e)) ? "This link has expired or was already used. Get a new one from the site." : errText(e); render(); }
  }
}

export async function disconnect(topic: string) {
  if (!wc.backend) return;
  const s = sessionOf(topic);
  for (const [id, it] of items) if (it.req.topic === topic && !inFlight(it)) { await answerError(it, 4100, "Disconnected"); items.delete(id); }
  try { await wc.backend.disconnect(topic); } catch (e) { notice(errText(e)); }
  if (s) toast(`Disconnected ${s.meta.name}`);
  sync();
}

export function openConnect() {
  wc.connect = { uri: "", busy: false, error: null, waiting: false };
  render();
}

// ------------------------------------------------------------------ start

/** Called by wc-view.ts's mountWalletConnect() with its renderer. */
export function startWalletConnect(h0: WcHost, renderer: () => void) {
  wc.host = h0;
  renderView = renderer;
  onExtChange(() => wc.host.changed());
  // The bridge refused a browser request before it reached a card (a sign-in for another site).
  void onEvent<{ origin: string; message: string }>("bridge-blocked", (b) => { notice(b.message); render(); });
  wc.projectId = loadProjectId();
  start();
  // pairing changes (forget / re-pair) end sessions offered with the old address
  window.setInterval(() => {
    const p = wc.host.paired();
    if (lastPaired !== undefined && p !== lastPaired) checkSessions();
    lastPaired = p;
  }, PAIRING_CHECK_MS);
  // the SDK surfaces queued requests only through its pending store
  window.setInterval(() => { if (wc.backend) sync(true); }, PENDING_SYNC_MS);
}
