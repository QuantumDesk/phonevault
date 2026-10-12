// Phone Vault background worker.
//
// Bridges tabs to the Phone Vault Companion app over native messaging (host "dev.phonevault",
// installed by the companion's "Install browser connection"). For every request it attaches the
// tab's origin as the BROWSER reports it for the sending frame (MessageSender.origin, falling back
// to the sender URL), never anything the page wrote. The companion makes every decision; this
// worker only routes, rate-limits and size-limits.
"use strict";

const HOST = "dev.phonevault";
const MAX_REQUEST_CHARS = 384 * 1024;
const MAX_OPEN_PER_TAB = 64;
const BUCKET_CAPACITY = 60;
const BUCKET_REFILL_PER_SEC = 20;
const ORIGIN_RE = /^(https:\/\/[a-z0-9.-]+(:\d{1,5})?|http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d{1,5})?)$/;

let native = null;
/** "unknown" | "connected" | "not_running" | "not_installed" | "error" */
let nativeState = "unknown";
let nativeMessage = "";
let paired = null;
let nextId = 1;
const pending = new Map(); // global id -> { port, pageId, origin }
const ports = new Set();
let idleTimer = 0;

function originOf(sender) {
  let o = typeof sender.origin === "string" ? sender.origin : "";
  if (!o || o === "null") { try { o = new URL(sender.url).origin; } catch { o = ""; } }
  o = o.toLowerCase();
  return ORIGIN_RE.test(o) ? o : null;
}

function failAll(code, message) {
  for (const [id, p] of pending) { try { p.port.postMessage({ type: "response", id: p.pageId, error: { code, message } }); } catch { /* tab gone */ } pending.delete(id); }
}

function connectNative() {
  if (native) return native;
  clearTimeout(idleTimer);
  const port = chrome.runtime.connectNative(HOST);
  native = port;
  nativeState = "unknown";
  port.onMessage.addListener(onNative);
  port.onDisconnect.addListener(() => {
    const err = chrome.runtime.lastError?.message ?? "";
    if (native === port) native = null;
    if (nativeState !== "not_running") {
      if (/not found|forbidden|not allowed/i.test(err)) { nativeState = "not_installed"; nativeMessage = "The browser connection isn't installed. In Phone Vault Companion: Settings → Browser extension → Install browser connection."; }
      else if (nativeState !== "connected" || err) { nativeState = "error"; nativeMessage = err || "Phone Vault Companion closed the connection."; }
      else { nativeState = "unknown"; nativeMessage = ""; }
    }
    failAll(4900, nativeMessage || "Phone Vault Companion is not reachable.");
    for (const p of ports) { try { p.postMessage({ type: "event", name: "disconnect" }); } catch { /* gone */ } }
  });
  port.postMessage({ type: "hello", version: 1, extension: chrome.runtime.getManifest().version });
  return port;
}

function onNative(m) {
  if (!m || typeof m !== "object") return;
  if (m.type === "hello") {
    if (m.ok) { nativeState = "connected"; nativeMessage = ""; paired = !!m.paired; }
    else { nativeState = m.error === "companion_not_running" ? "not_running" : "error"; nativeMessage = String(m.message ?? m.error ?? ""); }
    return;
  }
  if (m.type === "response") {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (p.reply) { p.reply(m); return; }
    try { p.port.postMessage({ type: "response", id: p.pageId, result: m.result, error: m.error }); } catch { /* tab gone */ }
    return;
  }
  if (m.type === "event" && typeof m.origin === "string") {
    for (const port of ports) if (port.phonevaultOrigin === m.origin) { try { port.postMessage({ type: "event", name: m.name, data: m.data }); } catch { /* gone */ } }
  }
}

function takeToken(b) {
  const now = Date.now();
  b.tokens = Math.min(BUCKET_CAPACITY, b.tokens + ((now - b.at) / 1000) * BUCKET_REFILL_PER_SEC);
  b.at = now;
  if (b.tokens < 1) return false;
  b.tokens -= 1;
  return true;
}

chrome.runtime.onConnect.addListener((port) => {
  const s = port.sender;
  // Only our own content script, in a tab's top frame.
  if (port.name !== "phonevault" || !s || s.id !== chrome.runtime.id || !s.tab || s.frameId !== 0) { port.disconnect(); return; }
  const origin = originOf(s);
  if (!origin) { port.disconnect(); return; }
  port.phonevaultOrigin = origin;
  const bucket = { tokens: BUCKET_CAPACITY, at: Date.now() };
  ports.add(port);
  clearTimeout(idleTimer);
  const openCount = () => { let n = 0; for (const p of pending.values()) if (p.source === port) n++; return n; };

  port.onMessage.addListener((m) => {
    if (!m || m.type !== "request" || !Number.isSafeInteger(m.id) || typeof m.method !== "string" || m.method.length > 64 || !Array.isArray(m.params)) return;
    const answer = (error) => port.postMessage({ type: "response", id: m.id, error });
    if (!takeToken(bucket)) return answer({ code: -32005, message: "Too many requests. Slow down." });
    if (openCount() >= MAX_OPEN_PER_TAB) return answer({ code: -32005, message: "Too many requests waiting." });
    let size = 0;
    try { size = JSON.stringify(m.params).length; } catch { return answer({ code: -32602, message: "params must be JSON" }); }
    if (size > MAX_REQUEST_CHARS) return answer({ code: -32602, message: "request too large" });
    const id = nextId++;
    pending.set(id, { source: port, port, pageId: m.id, origin });
    try { connectNative().postMessage({ type: "request", id, origin, method: m.method, params: m.params }); }
    catch (e) { pending.delete(id); answer({ code: 4900, message: `Phone Vault Companion is not reachable: ${e?.message ?? e}` }); }
  });

  port.onDisconnect.addListener(() => {
    ports.delete(port);
    // The tab closed or navigated: withdraw what it left waiting so the companion drops its cards.
    for (const [id, p] of [...pending]) if (p.source === port) { pending.delete(id); try { native?.postMessage({ type: "cancel", id }); } catch { /* gone */ } }
    if (!ports.size && !pending.size) {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => { if (!ports.size && native) { native.disconnect(); native = null; nativeState = "unknown"; } }, 30_000);
    }
  });
});

// Popup: companion status and whether the active tab's site is connected.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.tab) return false; // the popup only, not content scripts
  if (msg?.type !== "status" && msg?.type !== "disconnect_site") return false;
  let origin = null;
  try { const o = new URL(msg.url).origin.toLowerCase(); origin = ORIGIN_RE.test(o) ? o : null; } catch { /* not a web page */ }
  if (msg.type === "disconnect_site") {
    // Same as the site calling wallet_revokePermissions: it only ever removes a permission.
    if (!origin) { sendResponse({ ok: false }); return false; }
    const id = nextId++;
    pending.set(id, { reply: (m) => sendResponse({ ok: !m.error }) });
    try { connectNative().postMessage({ type: "request", id, origin, method: "wallet_revokePermissions", params: [{ eth_accounts: {} }] }); }
    catch { pending.delete(id); sendResponse({ ok: false }); return false; }
    return true;
  }
  let n;
  try { n = connectNative(); } catch (e) { sendResponse({ state: "error", message: String(e?.message ?? e), origin }); return false; }
  const id = nextId++;
  const timer = setTimeout(() => { pending.delete(id); sendResponse({ state: nativeState, message: nativeMessage, origin, site: null }); }, 1500);
  pending.set(id, { reply: (m) => { clearTimeout(timer); sendResponse({ state: nativeState, message: nativeMessage, origin, site: m.result ?? null }); } });
  if (origin) n.postMessage({ type: "site_status", id, origin });
  else { clearTimeout(timer); pending.delete(id); setTimeout(() => sendResponse({ state: nativeState, message: nativeMessage, origin: null, site: null }), 300); }
  return true;
});
