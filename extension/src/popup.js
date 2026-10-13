// Popup: is the companion reachable, and is the current tab's site connected?
"use strict";
const $ = (id) => document.getElementById(id);
const NAMES = { 1: "Ethereum", 10: "Optimism", 137: "Polygon", 8453: "Base", 42161: "Arbitrum One", 11155111: "Sepolia" };
const STATES = {
  connected: ["ok", "Connected to Phone Vault Companion"],
  not_running: ["warn", "Phone Vault Companion isn't running"],
  not_installed: ["bad", "Browser connection not installed"],
  error: ["bad", "Can't reach Phone Vault Companion"],
  unknown: ["", "Checking the companion…"],
};

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const url = tab?.url ?? "";
  chrome.runtime.sendMessage({ type: "status", url, tabId: tab?.id }, (r) => {
    if (!r) return;
    const [tone, text] = STATES[r.state] ?? STATES.unknown;
    $("dot").className = `dot ${tone}`;
    $("state").textContent = text;
    // The browser cannot start the app; when it runs, it can be asked to come forward.
    $("msg").textContent = r.state === "not_running"
      ? "Open Phone Vault Companion on this Mac (Applications, or Spotlight: ⌘ Space, then type Phone Vault), then try again."
      : (r.message ?? "");
    $("open").hidden = r.state !== "connected";
    $("open").classList.toggle("attn", !!r.waiting);
    $("open").onclick = () => chrome.runtime.sendMessage({ type: "show_window" }, (a) => {
      if (!a?.ok && a?.state !== "connected") $("msg").textContent = "Phone Vault Companion isn't reachable. Open it on this Mac.";
      else window.close();
    });
    if (!r.origin) return;
    $("site").hidden = false;
    $("host").textContent = r.origin.replace(/^https:\/\//, "");
    const s = r.site;
    $("siteState").textContent = !s ? "" : s.connected ? `Connected · ${NAMES[s.chain] ?? `chain ${s.chain}`}` : s.paired ? "Not connected" : "Phone Vault isn't paired with a phone yet";
    $("disconnect").hidden = !s?.connected;
    $("waiting").hidden = !r.waiting;
    $("waiting").textContent = r.waiting === 1 ? "This site is waiting for you. Approve or reject it in Phone Vault Companion on your Mac." : `${r.waiting} requests from this site are waiting in Phone Vault Companion on your Mac.`;
    $("disconnect").onclick = () => chrome.runtime.sendMessage({ type: "disconnect_site", url }, () => refresh());
  });
}
refresh();
