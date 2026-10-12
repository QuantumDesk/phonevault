// Phone Vault in-page provider (runs in the page's own JavaScript world).
//
// An EIP-1193 provider announced through EIP-6963 as "Phone Vault" (rdns dev.phonevault). It holds
// no keys and decides nothing: every request is passed to the extension's content script, which
// hands it to the background worker, which stamps the page's origin as reported by the browser and
// forwards it to the Phone Vault Companion app on this Mac. The companion decides, shows anything
// that needs a person, and every signature is reviewed and approved on the phone.
//
// Anything on this page can call this provider (that is what a provider is for); nothing on this
// page can choose which site the request is attributed to, and nothing here can sign.
(() => {
  "use strict";
  if (window.__phoneVaultProvider) return;

  const ICON = "__PHONEVAULT_ICON__"; // data: URI, filled in by build.mjs
  const INFO = Object.freeze({ uuid: crypto.randomUUID(), name: "Phone Vault", icon: ICON, rdns: "dev.phonevault" });
  const TO_CS = "phonevault:page->cs";
  const FROM_CS = "phonevault:cs->page";
  const MAX_REQUEST_CHARS = 384 * 1024;

  class ProviderRpcError extends Error {
    constructor(code, message, data) { super(message); this.code = code; if (data !== undefined) this.data = data; }
  }

  const listeners = new Map(); // event -> Set<fn>
  const waiting = new Map();   // id -> {resolve, reject}
  let nextId = 1;
  let chainId = null;
  let accounts = [];
  let connectedEmitted = false;

  function emit(event, ...args) {
    for (const fn of [...(listeners.get(event) ?? [])]) {
      try { fn(...args); } catch (e) { setTimeout(() => { throw e; }); }
    }
  }

  function setChain(c) {
    if (typeof c !== "string" || !/^0x[0-9a-f]+$/i.test(c)) return;
    const changed = chainId !== null && c !== chainId;
    chainId = c;
    if (!connectedEmitted) { connectedEmitted = true; emit("connect", { chainId: c }); }
    if (changed) emit("chainChanged", c);
  }

  function setAccounts(list) {
    if (!Array.isArray(list) || !list.every((a) => typeof a === "string")) return;
    const same = list.length === accounts.length && list.every((a, i) => a.toLowerCase() === accounts[i].toLowerCase());
    accounts = list.slice();
    if (!same) emit("accountsChanged", accounts.slice());
  }

  window.addEventListener("message", (ev) => {
    if (ev.source !== window || ev.origin !== location.origin) return;
    const m = ev.data;
    if (!m || typeof m !== "object" || m.target !== FROM_CS) return;
    if (m.type === "response") {
      const w = waiting.get(m.id);
      if (!w) return;
      waiting.delete(m.id);
      if (m.error) w.reject(new ProviderRpcError(Number(m.error.code) || -32603, String(m.error.message ?? "Request failed"), m.error.data));
      else w.resolve(m.result);
    } else if (m.type === "event") {
      if (m.name === "chainChanged") setChain(m.data);
      else if (m.name === "accountsChanged") setAccounts(m.data);
      else if (m.name === "disconnect") { emit("disconnect", new ProviderRpcError(4900, "Phone Vault Companion is not reachable")); }
    }
  });

  function request(args) {
    if (!args || typeof args !== "object" || Array.isArray(args)) return Promise.reject(new ProviderRpcError(-32600, "request() takes { method, params }"));
    const { method, params } = args;
    if (typeof method !== "string" || !method || method.length > 64) return Promise.reject(new ProviderRpcError(-32600, "invalid method"));
    if (params !== undefined && params !== null && !Array.isArray(params)) return Promise.reject(new ProviderRpcError(-32602, "params must be an array"));
    let body;
    try { body = JSON.parse(JSON.stringify(params ?? [])); } catch { return Promise.reject(new ProviderRpcError(-32602, "params must be JSON")); }
    if (JSON.stringify(body).length > MAX_REQUEST_CHARS) return Promise.reject(new ProviderRpcError(-32602, "request too large"));
    const id = nextId++;
    return new Promise((resolve, reject) => {
      waiting.set(id, {
        resolve: (r) => {
          if (method === "eth_chainId") setChain(r);
          if (method === "eth_accounts" || method === "eth_requestAccounts") setAccounts(r);
          resolve(r);
        },
        reject,
      });
      window.postMessage({ target: TO_CS, id, method, params: body }, location.origin);
    });
  }

  const provider = {
    isPhoneVault: true,
    request,
    on(event, fn) { if (typeof fn === "function") { if (!listeners.has(event)) listeners.set(event, new Set()); listeners.get(event).add(fn); } return provider; },
    once(event, fn) { const w = (...a) => { provider.removeListener(event, w); fn(...a); }; return provider.on(event, w); },
    removeListener(event, fn) { listeners.get(event)?.delete(fn); return provider; },
    off(event, fn) { return provider.removeListener(event, fn); },
    removeAllListeners(event) { if (event) listeners.delete(event); else listeners.clear(); return provider; },
    isConnected() { return true; },
    // Legacy: some older dApps call enable().
    enable() { return request({ method: "eth_requestAccounts" }); },
    get chainId() { return chainId; },
    get selectedAddress() { return accounts[0] ?? null; },
  };
  Object.freeze(provider);
  Object.defineProperty(window, "__phoneVaultProvider", { value: provider, enumerable: false });

  // EIP-6963: announce now and whenever a dApp asks.
  const announce = () => window.dispatchEvent(new CustomEvent("eip6963:announceProvider", { detail: Object.freeze({ info: INFO, provider }) }));
  window.addEventListener("eip6963:requestProvider", announce);
  announce();

  // Legacy window.ethereum, only if no other wallet claimed it. Phone Vault never replaces another wallet.
  if (!("ethereum" in window)) {
    try { Object.defineProperty(window, "ethereum", { value: provider, configurable: true, writable: true, enumerable: false }); } catch { /* another script won */ }
  }
})();
