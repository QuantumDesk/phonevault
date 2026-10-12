// Simulation before anything goes to the phone (sim.rs, vault-os/docs/simulation.md).
//
// Every review card (Send, token send, speed-up/cancel, WalletConnect and browser-extension
// transactions) shows the result of simulating the exact transaction on the user's node:
//   ok          "Your balance changes: −100 USDC, −0.00007 ETH (simulated)"   → Send to phone
//   no_changes  "Balance changes unavailable on this node" (eth_call: no revert) → Send to phone
//   unavailable "Couldn't simulate: …"                                         → Send anyway
//   reverts     "Reverts: <reason>"                                            → blocked (no override)
// The Rust side enforces the revert block as well (send::sign_start), so a revert can't be sent
// from any card. The numbers are the node's: the phone shows them as the Mac's unverified claim.

import { api, errText, type Quote, type Simulation } from "./api";
import { h, icon } from "./ui";

export type SimState = { s: "loading" } | { s: "done"; r: Simulation } | { s: "failed"; message: string };

const states = new Map<string, SimState>();
/** The paired account shown (the Rust side simulates from it): a result for one account never stands in for another. */
let account = "";
export function setSimulationAccount(address: string | null) { account = (address ?? "").toLowerCase(); }
const keyOf = (rpcUrl: string, q: Quote) => [account, rpcUrl, q.chain_id, q.to.toLowerCase(), q.value, q.data.toLowerCase(), q.gas_limit, q.nonce, q.max_fee_per_gas].join("|");

/** The simulation of this quote: cached, or started now (`onChange` runs when it finishes). */
export function simulationFor(rpcUrl: string, quote: Quote, onChange: () => void): SimState {
  const key = keyOf(rpcUrl, quote);
  const known = states.get(key);
  if (known) return known;
  return start(key, rpcUrl, quote, onChange);
}

/** Run it again (the user asked, e.g. after funding the wallet). */
export function resimulate(rpcUrl: string, quote: Quote, onChange: () => void): SimState {
  return start(keyOf(rpcUrl, quote), rpcUrl, quote, onChange);
}

function start(key: string, rpcUrl: string, quote: Quote, onChange: () => void): SimState {
  const loading: SimState = { s: "loading" };
  states.set(key, loading);
  if (states.size > 50) states.delete(states.keys().next().value as string);
  api.simulate(rpcUrl, quote)
    .then((r) => { if (states.get(key) === loading) states.set(key, { s: "done", r }); })
    .catch((e) => { if (states.get(key) === loading) states.set(key, { s: "failed", message: errText(e) }); })
    .finally(onChange);
  return loading;
}

/** What the send button may do for this simulation state. */
export interface Gate { allow: boolean; anyway: boolean; busy: boolean }
export function gate(st: SimState): Gate {
  if (st.s === "loading") return { allow: false, anyway: false, busy: true };
  if (st.s === "failed") return { allow: true, anyway: true, busy: false };
  switch (st.r.status) {
    case "reverts": return { allow: false, anyway: false, busy: false };
    case "unavailable": return { allow: true, anyway: true, busy: false };
    default: return { allow: true, anyway: false, busy: false };
  }
}

/** The send button for a review card, gated by the simulation. */
export function gatedSendButton(st: SimState, label: string, onSend: () => void, extraClass = "big primary"): HTMLButtonElement {
  const g = gate(st);
  if (g.busy) return h("button", { class: extraClass, disabled: true }, h("i", { class: "mini-spin" }), "Simulating…");
  if (!g.allow) return h("button", { class: extraClass, disabled: true, title: "This transaction would revert; it is not sent to the phone" }, icon("x", 16), "Blocked: it would revert");
  return h("button", { class: g.anyway ? "big warn-btn" : extraClass, onclick: onSend }, icon("phone", 18), g.anyway ? "Send anyway" : label);
}

const signClass = (d: string) => (d.startsWith("-") ? "neg" : "pos");

/** The simulation box shown on every transaction review. */
export function simPanel(st: SimState, retry: () => void): HTMLElement {
  if (st.s === "loading") {
    return h("div", { class: "sim-box" }, h("p", { class: "sim-head" }, h("i", { class: "mini-spin" }), "Simulating on your node…"),
      h("p", { class: "muted small" }, "Running this exact transaction on top of the latest block, to see what it would do to your balances."));
  }
  if (st.s === "failed") {
    return h("div", { class: "sim-box warn" }, h("p", { class: "sim-head" }, icon("alert", 15), "Couldn't simulate"),
      h("p", { class: "small" }, st.message),
      h("p", { class: "muted small" }, "You can still send it: your phone reviews it on its own. Check the result on the phone carefully."),
      h("button", { class: "link small", onclick: retry }, icon("refresh", 13), "Try again"));
  }
  const r = st.r;
  const where = `${r.method === "none" ? "" : r.method + " on "}${r.node}${r.block !== null ? ` · block ${r.block.toLocaleString("en-US")}` : ""}`;
  switch (r.status) {
    case "ok":
      return h("div", { class: "sim-box ok" },
        h("p", { class: "sim-head" }, icon("check", 15), "Your balance changes (simulated)"),
        r.changes.length
          ? h("ul", { class: "sim-changes" }, r.changes.map((c) => h("li", { class: signClass(c.delta) }, h("span", { class: "mono" }, c.display),
              c.symbol === null && c.token_id === null ? h("span", { class: "muted small" }, " unknown token") : null)))
          : h("p", { class: "small" }, "No balance changes, not even a fee."),
        r.note ? h("p", { class: "muted small" }, r.note) : null,
        h("p", { class: "muted small" }, `Simulated with ${where}. These are your node's numbers; ${r.for_phone ? "your phone shows them as this Mac's claim, unverified, and checks them against its own decoding." : "your phone reviews the transaction on its own."}`));
    case "reverts":
      return h("div", { class: "sim-box bad", role: "alert" },
        h("p", { class: "sim-head" }, icon("alert", 15), "Reverts: ", h("span", { class: "sim-reason" }, r.reason ?? "no reason given")),
        h("p", { class: "small" }, "This transaction would fail on-chain, and a failed transaction still costs its fee. It was not sent to your phone, and it can't be sent as it is."),
        h("p", { class: "muted small" }, `Simulated with ${where}.`),
        h("button", { class: "link small", onclick: retry }, icon("refresh", 13), "Simulate again"));
    case "no_changes":
      return h("div", { class: "sim-box" },
        h("p", { class: "sim-head" }, icon("check", 15), "Balance changes unavailable on this node"),
        h("p", { class: "small" }, `It does not revert (eth_call${r.gas_used ? `, about ${Number(r.gas_used).toLocaleString("en-US")} gas` : ""}).`),
        r.note ? h("p", { class: "muted small" }, r.note) : null,
        h("p", { class: "muted small" }, "A node that supports eth_simulateV1 shows the balance changes too (Settings → Nodes)."));
    default:
      return h("div", { class: "sim-box warn" },
        h("p", { class: "sim-head" }, icon("alert", 15), "Couldn't simulate"),
        h("p", { class: "small" }, r.reason ?? "The node didn't run it."),
        h("p", { class: "muted small" }, "You can still send it: your phone reviews it on its own. Check the result on the phone carefully."),
        h("button", { class: "link small", onclick: retry }, icon("refresh", 13), "Try again"));
  }
}
