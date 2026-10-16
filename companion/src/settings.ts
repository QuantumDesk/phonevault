// The settings drawer: phone and paired accounts, genuine check, backup card, network and node,
// notifications, incoming-transfer scan status, appearance, WalletConnect, browser extension,
// tools and about.

import { api, appVersion, notify, errText, isTauri } from "./api";
import { deviceSection } from "./attestation";
import { NETWORKS, type Network } from "./networks";
import { h, icon, short, blockRange, copy, focusBack } from "./ui";
import { wcSettingsSection } from "./wc-view";
import { extSettingsSection } from "./extension";
import { backupCardSection } from "./backup-card";
import { btcBusy, btcSettingsSection, type BtcNet } from "./bitcoin";
import { identifyPhone } from "./identity";
import { numberingSection } from "./account-numbering";
import { state, prefs, savePrefs, rpcFor, net, applyTheme, balances, pairedAccounts, type Theme, type View } from "./state";

/** What the drawer needs from the shell (main.ts). */
export interface SettingsHost {
  refreshStatus(): Promise<void>;
  renderHeader(): void;
  render(): void;
  go(v: View): void;
  refreshBalance(n: Network): Promise<void>;
  selectAccount(address: string): Promise<void>;
  accountBusy(): boolean;
  selectBtc(b: BtcNet | null): void;
  /** the Bitcoin networks offered (testnets only when enabled) */
  btcNets(): { id: BtcNet; name: string; test: boolean }[];
  /** start the guided setup over */
  restartSetup(): void;
}
let host: SettingsHost;
let version = "";

export const drawer = h("aside", { class: "drawer", "aria-label": "Settings", "aria-hidden": "true" });

export function initSettings(h0: SettingsHost) {
  host = h0;
  appVersion().then((v) => { version = v; if (state.drawerOpen) renderDrawer(); }).catch(() => {});
}

// ------------------------------------------------------------------ settings drawer

/** Where focus was when the drawer opened (the gear, a badge…); it goes back there on close. */
let returnFocus: HTMLElement | null = null;
export function openDrawer() {
  if (!state.drawerOpen) returnFocus = document.activeElement instanceof HTMLElement && !drawer.contains(document.activeElement) ? document.activeElement : null;
  state.drawerOpen = true; renderDrawer(); document.body.classList.add("drawer-open"); drawer.setAttribute("aria-hidden", "false"); (drawer.querySelector("button") as HTMLElement | null)?.focus();
}
export function closeDrawer() {
  const had = state.drawerOpen && (drawer.contains(document.activeElement) || document.activeElement === document.body);
  state.drawerOpen = false; document.body.classList.remove("drawer-open"); drawer.setAttribute("aria-hidden", "true");
  if (had && returnFocus) focusBack(returnFocus);
  else if (had) (document.activeElement as HTMLElement | null)?.blur();
  returnFocus = null;
}
document.addEventListener("keydown", (e) => { if (e.key === "Escape" && state.drawerOpen) closeDrawer(); });

/** Settings → Incoming transfers: how far back each node let the watcher search token transfers. */
function scanStatusSection() {
  const list = h("div", { class: "att-details" }, h("p", { class: "muted small" }, "…"));
  api.scanStatus().then((rows) => {
    list.replaceChildren(...NETWORKS.map((x) => {
      const r = rows.find((s) => s.chain_id === x.id);
      const text = !r ? "not searched yet" : r.from_block === null ? `not available from this node` : blockRange(r.from_block, r.to_block ?? 0);
      return h("div", { class: "set-row" }, h("span", { class: "muted" }, x.name), h("span", { class: "att-val", title: r?.error ?? "" }, text, r?.error && r.from_block !== null ? " (partial)" : ""));
    }));
  }).catch(() => list.replaceChildren(h("p", { class: "muted small" }, "Unavailable.")));
  return h("section", { class: "set" },
    h("h4", null, "INCOMING TRANSFERS"),
    h("p", { class: "muted small" }, "Token transfers into this wallet are found in Transfer logs on your node for each network, starting from a recent window and then continuously. Some public nodes only serve the last few minutes of logs; a node of your own shows more. Plain ETH transfers are matched from the blocks since the last balance check; anything else that raises the balance is listed without a hash."),
    list,
  );
}

/** Settings → Phone: every paired account; show one, rename it, or forget it. */
function accountsSettings() {
  const rows = pairedAccounts().map((a) => {
    const onPhone = state.phoneAddress?.toLowerCase() === a.address.toLowerCase();
    const name = h("input", { type: "text", class: "acct-name", value: a.label, maxlength: "40", spellcheck: "false", "aria-label": `Name for ${a.checksum}` }) as HTMLInputElement;
    name.addEventListener("change", async () => { const v = name.value.trim(); if (!v) { name.value = a.label; return; } try { await api.renameAccount(a.address, v); await host.refreshStatus(); renderDrawer(); host.renderHeader(); if (state.view === "home") host.render(); } catch (e) { name.value = a.label; state.statusError = errText(e); } });
    return h("div", { class: "acct-row" },
      h("div", { class: "grow" }, name,
        h("button", { class: "link mono small", title: a.checksum, onclick: () => copy(a.checksum) }, short(a.checksum), icon("copy", 12)),
        a.wallet === "passphrase" ? h("span", { class: "tag" }, "passphrase") : null,
        onPhone ? h("span", { class: "tag" }, "on the phone") : null),
      a.active ? h("span", { class: "tag on" }, "Shown") : h("button", { disabled: host.accountBusy(), onclick: async () => { await host.selectAccount(a.address); renderDrawer(); } }, "Show"),
      pairedAccounts().length > 1 ? h("button", { class: "danger-ghost", title: "Unpair this account (its local history stays on disk)", onclick: async (ev: Event) => {
        const b = ev.currentTarget as HTMLButtonElement;
        if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again"; return; }
        try { await api.forgetAccount(a.address); await host.refreshStatus(); renderDrawer(); } catch (e) { b.textContent = errText(e); }
      } }, "Forget") : null,
    );
  });
  return h("div", { class: "acct-list" }, h("p", { class: "muted small" }, "Paired accounts. Sending, signing and the menu bar use the one shown; the phone must be on the same account."), ...rows);
}

export function renderDrawer() {
  const paired = state.status?.paired_checksum;
  const phone = state.status?.phone ?? "none";
  const n = net();
  const rpcInput = h("input", { type: "url", spellcheck: "false", value: rpcFor(n.id), placeholder: n.rpc });
  const rpcMsg = h("p", { class: "field-msg" });
  const saveRpc = () => {
    const v = rpcInput.value.trim();
    if (v && !v.startsWith("https://")) { rpcMsg.textContent = "Use an https:// URL."; rpcMsg.className = "field-msg bad"; return; }
    if (!v || v === n.rpc) delete prefs.rpc[n.id]; else prefs.rpc[n.id] = v;
    savePrefs(); balances.delete(n.id); host.refreshBalance(n);
    rpcMsg.textContent = "Saved."; rpcMsg.className = "field-msg ok";
  };
  const seg = (v: Theme, label: string) => h("button", { class: prefs.theme === v ? "on" : "", onclick: () => { prefs.theme = v; savePrefs(); applyTheme(); renderDrawer(); } }, label);
  drawer.replaceChildren(...[
    h("div", { class: "drawer-head" }, h("h2", null, "Settings"), h("button", { class: "icon-btn", onclick: closeDrawer, "aria-label": "Close settings" }, icon("close", 20))),
    h("section", { class: "set" },
      h("h4", null, "PHONE"),
      h("div", { class: "set-row" }, h("span", null, "USB"), h("span", { class: `chip ${phone}` }, h("i", { class: "dot" }), h("span", { class: "chip-label" }, phone === "accessory" ? "Connected" : phone === "android" ? "On USB" : "Not connected"))),
      paired ? accountsSettings() : h("div", { class: "set-row" }, h("span", null, "Paired address"), h("span", { class: "muted" }, "Not paired")),
      h("div", { class: "row gap" },
        h("button", { onclick: () => { closeDrawer(); state.pair = { s: "idle" }; host.go("pair"); } }, paired ? "Pair another account" : "Pair phone"),
        h("button", { onclick: () => { closeDrawer(); host.restartSetup(); } }, icon("refresh", 15), "Run setup again"),
        paired ? h("button", { class: "danger-ghost", onclick: async (ev: Event) => {
          const b = ev.currentTarget as HTMLButtonElement;
          if (b.dataset.armed !== "1") { b.dataset.armed = "1"; b.textContent = "Click again to forget"; return; }
          try { await api.forgetPairing(); closeDrawer(); await host.refreshStatus(); } catch (e) { b.textContent = errText(e); }
        } }, pairedAccounts().length > 1 ? "Forget all accounts" : "Forget phone") : null,
      ),
      state.status?.pairing_path ? h("p", { class: "muted small" }, "Stored in ", h("span", { class: "mono" }, state.status.pairing_path)) : null,
    ),
    paired ? numberingSection(() => { if (state.drawerOpen) renderDrawer(); }) : null,
    deviceSection(state.device, state.devMode, phone !== "none", () => identifyPhone(), async (on, confirmation) => {
      state.devMode = await api.setDeveloperMode(on, confirmation);
      if (phone !== "none") void identifyPhone();
    }, () => renderDrawer()),
    backupCardSection(),
    h("section", { class: "set" },
      h("h4", null, "NETWORK"),
      h("div", { class: "radio-list" }, NETWORKS.map((x) => h("button", { class: `radio${!prefs.btc && x.id === prefs.chainId ? " on" : ""}`, onclick: () => { if (btcBusy()) return; prefs.btc = null; prefs.chainId = x.id; savePrefs(); host.refreshBalance(x); renderDrawer(); if (state.view === "home" || state.view === "receive") host.render(); } },
        h("i", { class: `net-dot n${x.id}` }), h("span", { class: "grow" }, x.name), x.testnet ? h("span", { class: "tag" }, "testnet") : null, !prefs.btc && x.id === prefs.chainId ? icon("check", 16) : null)),
        host.btcNets().map((b) => h("button", { class: `radio${prefs.btc === b.id ? " on" : ""}`, onclick: () => { host.selectBtc(b.id); renderDrawer(); if (state.view === "home") host.render(); } },
          h("i", { class: `net-dot nbtc-${b.id}` }), h("span", { class: "grow" }, b.name), b.test ? h("span", { class: "tag" }, "test") : null, prefs.btc === b.id ? icon("check", 16) : null))),
    ),
    btcSettingsSection(() => renderDrawer()),
    h("section", { class: "set" },
      h("h4", null, `NODE FOR ${n.name.toUpperCase()}`),
      h("label", { class: "field" }, rpcInput, rpcMsg),
      h("div", { class: "row gap" },
        h("button", { onclick: saveRpc }, "Save"),
        h("button", { class: "ghost", onclick: () => { rpcInput.value = n.rpc; saveRpc(); } }, "Use default"),
      ),
      h("p", { class: "muted small" }, "The node supplies balance, nonce and fees, and passes on what you send to the network. It can't change what the phone signs: every field is shown to you and on the phone first."),
    ),
    h("section", { class: "set" },
      h("h4", null, "NOTIFICATIONS"),
      h("label", { class: "toggle" }, h("span", null, "Tell me when funds arrive"),
        (() => { const t = h("input", { type: "checkbox", role: "switch", checked: prefs.notify }); t.addEventListener("change", () => { prefs.notify = t.checked; savePrefs(); if (t.checked) notify("Notifications are on."); }); return t; })(), h("i", { class: "knob" })),
      h("p", { class: "muted small" }, isTauri ? "Checked in the background on your nodes, also when the window is closed: Phone Vault stays in the menu bar (Quit from its menu)." : "Checked in the background on your nodes."),
    ),
    scanStatusSection(),
    h("section", { class: "set" },
      h("h4", null, "APPEARANCE"),
      h("div", { class: "segmented" }, seg("dark", "Dark"), seg("light", "Light"), seg("system", "System")),
    ),
    wcSettingsSection(),
    extSettingsSection(),
    h("section", { class: "set" },
      h("h4", null, "TOOLS"),
      h("button", { class: "radio", onclick: () => { closeDrawer(); host.go("tool"); } }, icon("pen", 16), h("span", { class: "grow" }, "Sign a message"), icon("back", 14)),
    ),
    h("section", { class: "set about" },
      h("h4", null, "ABOUT"),
      h("div", { class: "set-row" }, h("span", null, "Phone Vault Companion"), h("span", { class: "mono muted" }, version || "…")),
      h("p", { class: "muted small" }, "This Mac never sees a key. It quotes, verifies and sends to the network. The phone decides."),
      h("p", { class: "muted small" }, "Prices from Coinbase, for display only. Bitcoin data from the Esplora server in Settings → Bitcoin. No analytics, no accounts."),
    ),
  ].filter((x): x is HTMLElement => !!x));
}
