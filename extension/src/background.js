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
let nextId = 1;
const pending = new Map(); // global id -> { port, pageId, tabId, waiting? } (a tab request) or { reply } (popup)
const ports = new Set();
let idleTimer = 0;

function originOf(sender) {
  let o = typeof sender.origin === "string" ? sender.origin : "";
  if (!o || o === "null") { try { o = new URL(sender.url).origin; } catch { o = ""; } }
  o = o.toLowerCase();
  return ORIGIN_RE.test(o) ? o : null;
}

function failAll(code, message) {
  for (const [id, p] of pending) { if (p.reply) { pending.delete(id); p.reply({ error: { code, message } }); continue; } try { p.port.postMessage({ type: "response", id: p.pageId, error: { code, message } }); } catch { /* tab gone */ } pending.delete(id); }
  for (const tab of [...waitingTabs()]) updateBadge(tab);
}

// Requests the companion queued for the user (connect, sign, send): badge the tab's toolbar icon
// so a page that "just spins" says where to look.
function waitingCount(tabId) { let n = 0; for (const p of pending.values()) if (p.waiting && p.tabId === tabId) n++; return n; }
function waitingTabs() { const t = new Set(); for (const p of pending.values()) if (p.tabId != null) t.add(p.tabId); return t; }
function updateBadge(tabId) {
  if (tabId == null) return;
  const n = waitingCount(tabId);
  try {
    chrome.action.setBadgeText({ tabId, text: n ? String(n) : "" });
    if (n) chrome.action.setBadgeBackgroundColor({ tabId, color: "#d97706" });
    chrome.action.setTitle({ tabId, title: n ? "Phone Vault: approve this in Phone Vault Companion on your Mac" : "Phone Vault" });
  } catch { /* tab gone */ }
}

// Why the companion can't be reached, with what to do next. The browser's own words, if any,
// are kept in parentheses for support.
function unreachable(detail) {
  const d = String(detail ?? "").trim().replace(/\.$/, "");
  return `Phone Vault Companion couldn't be reached${d ? ` (the browser said: ${d})` : ""}. Open Phone Vault Companion on this Mac, then try again.`;
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
      else if (nativeState !== "connected" || err) { nativeState = "error"; nativeMessage = unreachable(err); }
      else { nativeState = "unknown"; nativeMessage = ""; }
    }
    failAll(4900, nativeMessage || unreachable(""));
    for (const p of ports) { try { p.postMessage({ type: "event", name: "disconnect" }); } catch { /* gone */ } }
  });
  port.postMessage({ type: "hello", version: 1, extension: chrome.runtime.getManifest().version });
  return port;
}

function onNative(m) {
  if (!m || typeof m !== "object") return;
  if (m.type === "hello") {
    if (m.ok) { nativeState = "connected"; nativeMessage = ""; }
    else { nativeState = m.error === "companion_not_running" ? "not_running" : "error"; nativeMessage = String(m.message ?? m.error ?? ""); }
    return;
  }
  if (m.type === "queued") {
    const p = pending.get(m.id);
    if (p && !p.reply) { p.waiting = true; updateBadge(p.tabId); }
    return;
  }
  if (m.type === "response") {
    const p = pending.get(m.id);
    if (!p) return;
    pending.delete(m.id);
    if (p.waiting) updateBadge(p.tabId);
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
  const openCount = () => { let n = 0; for (const p of pending.values()) if (p.port === port) n++; return n; };

  port.onMessage.addListener((m) => {
    if (!m || m.type !== "request" || !Number.isSafeInteger(m.id) || typeof m.method !== "string" || m.method.length > 64 || !Array.isArray(m.params)) return;
    const answer = (error) => port.postMessage({ type: "response", id: m.id, error });
    if (!takeToken(bucket)) return answer({ code: -32005, message: "Too many requests. Slow down." });
    if (openCount() >= MAX_OPEN_PER_TAB) return answer({ code: -32005, message: "Too many requests waiting." });
    let size = 0;
    try { size = JSON.stringify(m.params).length; } catch { return answer({ code: -32602, message: "params must be JSON" }); }
    if (size > MAX_REQUEST_CHARS) return answer({ code: -32602, message: "request too large" });
    const id = nextId++;
    pending.set(id, { port, pageId: m.id, tabId: s.tab.id });
    try { connectNative().postMessage({ type: "request", id, origin, method: m.method, params: m.params }); }
    catch (e) { pending.delete(id); answer({ code: 4900, message: unreachable(e?.message ?? e) }); }
  });

  port.onDisconnect.addListener(() => {
    ports.delete(port);
    // The tab closed or navigated: withdraw what it left waiting so the companion drops its cards.
    for (const [id, p] of [...pending]) if (p.port === port) { pending.delete(id); try { native?.postMessage({ type: "cancel", id }); } catch { /* gone */ } }
    updateBadge(s.tab.id);
    if (!ports.size && !pending.size) {
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => { if (!ports.size && native) { native.disconnect(); native = null; nativeState = "unknown"; } }, 30_000);
    }
  });
});

// Popup: companion status and whether the active tab's site is connected.
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || sender.tab) return false; // the popup only, not content scripts
  if (msg?.type === "show_window") {
    // "Open Phone Vault Companion": native messaging cannot start an app, but the running
    // companion can bring its window forward. Only when it is already connected.
    if (nativeState !== "connected" || !native) { sendResponse({ ok: false, state: nativeState }); return false; }
    const id = nextId++;
    const timer = setTimeout(() => { if (pending.delete(id)) sendResponse({ ok: false, state: nativeState }); }, 1500);
    pending.set(id, { reply: (m) => { clearTimeout(timer); sendResponse({ ok: m.result === true, state: nativeState }); } });
    try { native.postMessage({ type: "show_window", id }); }
    catch { clearTimeout(timer); pending.delete(id); sendResponse({ ok: false, state: nativeState }); return false; }
    return true;
  }
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
  try { n = connectNative(); } catch (e) { sendResponse({ state: "error", message: unreachable(e?.message ?? e), origin }); return false; }
  const id = nextId++;
  const timer = setTimeout(() => { pending.delete(id); sendResponse({ state: nativeState, message: nativeMessage, origin, site: null }); }, 1500);
  const waiting = Number.isSafeInteger(msg.tabId) ? waitingCount(msg.tabId) : 0;
  pending.set(id, { reply: (m) => { clearTimeout(timer); sendResponse({ state: nativeState, message: nativeMessage, origin, site: m.result ?? null, waiting }); } });
  if (origin) n.postMessage({ type: "site_status", id, origin });
  else { clearTimeout(timer); pending.delete(id); setTimeout(() => sendResponse({ state: nativeState, message: nativeMessage, origin: null, site: null }), 300); }
  return true;
});
