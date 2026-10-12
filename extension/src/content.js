// Phone Vault content script (extension's isolated world, top frame only).
//
// Carries requests from the in-page provider to the background worker and answers back. It adds
// nothing and decides nothing: the background stamps the origin from the browser's own record of
// this frame (MessageSender.origin), so a page cannot claim to be another site.
(() => {
  "use strict";
  const TO_CS = "phonevault:page->cs";
  const FROM_CS = "phonevault:cs->page";
  const MAX_REQUEST_CHARS = 384 * 1024;
  let port = null;
  const open = new Set(); // ids waiting for an answer

  const toPage = (m) => window.postMessage({ target: FROM_CS, ...m }, location.origin);

  function getPort() {
    if (port) return port;
    port = chrome.runtime.connect({ name: "phonevault" });
    port.onMessage.addListener((m) => {
      if (!m || typeof m !== "object") return;
      if (m.type === "response") { open.delete(m.id); toPage({ type: "response", id: m.id, result: m.result, error: m.error }); }
      else if (m.type === "event") toPage({ type: "event", name: m.name, data: m.data });
    });
    port.onDisconnect.addListener(() => {
      port = null;
      // The worker went away (extension reloaded or updated): fail what was waiting.
      for (const id of open) toPage({ type: "response", id, error: { code: 4900, message: "Phone Vault extension restarted. Try again." } });
      open.clear();
    });
    return port;
  }

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || ev.origin !== location.origin) return;
    const m = ev.data;
    if (!m || typeof m !== "object" || m.target !== TO_CS) return;
    if (!Number.isSafeInteger(m.id) || m.id <= 0 || typeof m.method !== "string" || m.method.length > 64 || !Array.isArray(m.params)) return;
    let size = 0;
    try { size = JSON.stringify(m.params).length; } catch { return; }
    if (size > MAX_REQUEST_CHARS) { toPage({ type: "response", id: m.id, error: { code: -32602, message: "request too large" } }); return; }
    open.add(m.id);
    try { getPort().postMessage({ type: "request", id: m.id, method: m.method, params: m.params }); }
    catch { open.delete(m.id); toPage({ type: "response", id: m.id, error: { code: 4900, message: "Phone Vault extension is not available. Reload the page." } }); }
  });
})();
