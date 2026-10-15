// Activity: everything in the local history (sent from this Mac, transfers into the wallet found
// by the background watcher, balance increases it could not attribute), with filters, and Speed up
// / Cancel on a transaction that is stuck pending. A replacement is a complete new transaction that
// goes through the normal Send pipeline (phone review → verify → Broadcast); this only starts it.

import type { HistoryEntry } from "./api";
import { openExternal } from "./api";
import { byId } from "./networks";
import { h, icon, short, shortHash, fmtAmount, ago } from "./ui";
import { fmtExact } from "./tokens";

export type KindFilter = "all" | "out" | "in" | "pending";
export interface ActivityFilter { kind: KindFilter; thisNetwork: boolean }

export interface ActivityHost {
  history: () => HistoryEntry[];
  chainId: () => number;
  address: () => string | null;
  filter: ActivityFilter;
  saveFilter: () => void;
  rerender: () => void;
  replace: (e: HistoryEntry, kind: "speedup" | "cancel") => void;
}

const sameGroup = (a: HistoryEntry, b: HistoryEntry) => a.kind === "out" && b.kind === "out" && a.chain_id === b.chain_id && a.nonce !== null && a.nonce === b.nonce;

/** The newest pending transaction of its nonce group gets the Speed up / Cancel buttons. */
function isActionable(e: HistoryEntry, all: HistoryEntry[]): boolean {
  if (e.kind !== "out" || e.status !== "pending" || !e.hash || e.nonce === null) return false;
  return !all.some((x) => x !== e && sameGroup(x, e) && x.status === "pending" && x.time > e.time);
}

function statusBadge(e: HistoryEntry, all: HistoryEntry[]) {
  switch (e.status) {
    case "pending": return h("span", { class: "badge pending" }, h("i", { class: "mini-spin" }), "Pending");
    case "failed": return h("span", { class: "badge failed" }, "Failed");
    case "confirmed": return h("span", { class: "badge ok" }, e.replacement_kind === "cancel" ? "Cancelled it" : "Confirmed");
    case "dropped": {
      const winner = all.find((x) => x !== e && sameGroup(x, e) && (x.status === "confirmed" || x.status === "failed"));
      return h("span", { class: "badge dropped", title: winner?.hash ? `Replaced by ${winner.hash}` : "A transaction that replaces it was included instead" },
        winner ? (winner.replacement_kind === "cancel" && winner.replaces?.toLowerCase() === e.hash?.toLowerCase() ? "Cancelled" : "Replaced") : "Dropped");
    }
    default: return null;
  }
}

function title(e: HistoryEntry): string {
  const n = byId(e.chain_id);
  const amount = e.token_symbol ? `${fmtExact(e.token_amount ?? "?")} ${e.token_symbol}` : `${fmtAmount(e.amount_eth)} ${n.symbol}`;
  if (e.replacement_kind === "cancel") return "Cancel";
  if (e.kind === "out") return `${e.replacement_kind === "speedup" ? "Sped up · sent" : "Sent"} ${amount}`;
  return `Received ${amount}`;
}

function sub(e: HistoryEntry, me: string | null): string {
  const n = byId(e.chain_id);
  const parts: (string | null)[] = [];
  if (e.replaces) parts.push(`replaces ${shortHash(e.replaces)}`);
  else if (e.kind === "out" && e.counterparty) parts.push(me && e.counterparty.toLowerCase() === me.toLowerCase() ? "to yourself" : `to ${short(e.counterparty)}`);
  else if (e.kind === "in" && e.counterparty) parts.push(`from ${short(e.counterparty)}`);
  else if (e.kind === "in" && !e.hash) parts.push("balance increase");
  parts.push(n.name, ago(e.time));
  return parts.filter(Boolean).join(" · ");
}

function row(e: HistoryEntry, all: HistoryEntry[], host: ActivityHost) {
  const n = byId(e.chain_id);
  const out = e.kind === "out";
  const url = e.hash ? `${n.explorer}/tx/${e.hash}` : `${n.explorer}/address/${host.address() ?? ""}`;
  const main = h("button", { class: "act-row", onclick: () => openExternal(url), title: e.hash ? `${e.hash}\nOpen in explorer` : "No transaction hash: the balance went up without a transfer this app could find (for example a payout from a contract). Opens the address in the explorer." },
    h("span", { class: `act-ic ${out ? (e.replacement_kind === "cancel" ? "cx" : "out") : "in"}` }, icon(e.replacement_kind === "cancel" ? "x" : out ? "up" : "down", 16)),
    h("span", { class: "grow" },
      h("span", { class: "act-title" }, title(e)),
      h("span", { class: "act-sub" }, sub(e, host.address())),
    ),
    statusBadge(e, all),
    h("span", { class: "muted ext" }, icon("external", 15)),
  );
  if (!isActionable(e, all)) return h("li", null, main);
  const stuck = Date.now() / 1000 - e.time > 60;
  return h("li", { class: "act-stuck" }, main,
    h("div", { class: "act-actions" },
      h("span", { class: "muted small grow" }, stuck ? "Still pending. You can pay a higher fee, or cancel it." : "Waiting to be included…"),
      e.tx && e.replacement_kind !== "cancel" ? h("button", { class: "chip-btn", onclick: () => host.replace(e, "speedup"), title: "Send the same transaction again with a higher fee; it replaces the original transaction. Your phone reviews it." }, icon("up", 13), "Speed up") : null,
      h("button", { class: "chip-btn", onclick: () => host.replace(e, "cancel"), title: "Send 0 to yourself with a higher fee; it replaces the original transaction, so the original can never be included. Your phone reviews it." }, icon("x", 13), e.replacement_kind === "cancel" ? "Cancel faster" : "Cancel"),
    ));
}

function applyFilter(all: HistoryEntry[], f: ActivityFilter, chainId: number): HistoryEntry[] {
  return all.filter((e) => (!f.thisNetwork || e.chain_id === chainId) && (
    f.kind === "all" || (f.kind === "pending" ? e.status === "pending" : e.kind === f.kind)));
}

export function activitySection(host: ActivityHost): HTMLElement {
  const all = host.history();
  const f = host.filter;
  const shown = applyFilter(all, f, host.chainId());
  const pending = all.filter((e) => e.status === "pending").length;
  const seg = (k: KindFilter, label: string) => h("button", { class: f.kind === k ? "on" : "", onclick: () => { f.kind = k; host.saveFilter(); host.rerender(); } }, label);
  const netToggle = h("button", { class: `chip-btn${f.thisNetwork ? " on" : ""}`, onclick: () => { f.thisNetwork = !f.thisNetwork; host.saveFilter(); host.rerender(); }, title: "Show only the selected network" },
    h("i", { class: `net-dot n${host.chainId()}` }), f.thisNetwork ? `${byId(host.chainId()).name} only` : "All networks");
  return h("section", { class: "section" },
    h("div", { class: "act-filters" },
      h("div", { class: "segmented four" }, seg("all", "All"), seg("out", "Sent"), seg("in", "Received"), seg("pending", pending ? `Pending · ${pending}` : "Pending")),
      netToggle,
    ),
    shown.length ? h("ul", { class: "list activity" }, shown.slice(0, 60).map((e) => row(e, all, host)))
      : h("p", { class: "empty" }, all.length ? "Nothing matches this filter." : "Nothing yet. Transactions you send from this Mac, and transfers into this wallet, show up here."),
    all.length ? h("p", { class: "muted small" }, "Incoming transfers are found by this app's background check on your nodes, within a recent block window. A balance increase it can't match to a transaction (for example a payout from a contract) is listed without a hash.") : null,
  );
}
