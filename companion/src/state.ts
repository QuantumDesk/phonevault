// State shared by the companion's screens (main.ts, send.ts, identity.ts, settings.ts): the
// preferences, the live data from Rust, and one `state` object for everything they read and change.
// Nothing here renders; whoever changes a field redraws what it affects.

import { api, isTauri } from "./api";
import type { Status, HistoryEntry, PairedAccount } from "./api";
import type { DeviceCheck } from "./attestation";
import type { ActivityFilter } from "./activity";
import { NETWORKS, DEFAULT_CHAIN, byId, type Network } from "./networks";
import type { BtcNet } from "./bitcoin";

// ------------------------------------------------------------------ preferences (non-sensitive)

export type Theme = "dark" | "light" | "system";
export type HomeTab = "assets" | "nfts" | "activity";
interface Prefs { chainId: number; rpc: Record<string, string>; notify: boolean; theme: Theme; activity: ActivityFilter; tab: HomeTab; setupDone: boolean;
  /** a Bitcoin network is shown instead of an EVM one (null: EVM) */
  btc: BtcNet | null; btcTestnets: boolean }
const PREFS_KEY = "phonevault.prefs.v1";
function loadPrefs(): Prefs {
  const d: Prefs = { chainId: DEFAULT_CHAIN, rpc: {}, notify: true, theme: "dark", activity: { kind: "all", thisNetwork: false }, tab: "assets", setupDone: false, btc: null, btcTestnets: false };
  try {
    const p = JSON.parse(localStorage.getItem(PREFS_KEY) ?? "{}");
    const a = p.activity && typeof p.activity === "object" ? p.activity : {};
    return { chainId: NETWORKS.some((n) => n.id === p.chainId) ? p.chainId : d.chainId, rpc: p.rpc && typeof p.rpc === "object" ? p.rpc : {}, notify: p.notify !== false, theme: ["dark", "light", "system"].includes(p.theme) ? p.theme : d.theme,
      activity: { kind: ["all", "out", "in", "pending"].includes(a.kind) ? a.kind : "all", thisNetwork: a.thisNetwork === true },
      tab: ["assets", "nfts", "activity"].includes(p.tab) ? p.tab : d.tab, setupDone: p.setupDone === true,
      btcTestnets: p.btcTestnets === true, btc: ["bitcoin", "testnet", "signet"].includes(p.btc) && (p.btc === "bitcoin" || p.btcTestnets === true) ? p.btc : null };
  } catch { return d; }
}
export const prefs = loadPrefs();
export function savePrefs() { try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); } catch { /* preferences are a convenience */ } pushWatchConfig(); }
export const rpcFor = (id: number) => prefs.rpc[id] || byId(id).rpc;
export const net = () => byId(prefs.chainId);
export function applyTheme() {
  if (prefs.theme === "system") document.documentElement.removeAttribute("data-theme");
  else document.documentElement.setAttribute("data-theme", prefs.theme);
}

/** The watcher runs in Rust with the UI's settings (custom nodes, notifications, selected network). */
export function pushWatchConfig() { if (isTauri) api.watchConfigure(prefs.rpc, prefs.notify, prefs.chainId).catch(() => {}); }

// ------------------------------------------------------------------ shared state

export type View = "home" | "send" | "receive" | "pair" | "tool" | "setup";
export type PairState = { s: "idle"; error?: string } | { s: "reading" } | { s: "compare"; address: string; label?: string; account?: number | null; wallet?: string | null } | { s: "mismatch" };
/** Where the phone on USB stands against this Mac's pairing (identity.ts). */
export type Identity = { s: "unknown" } | { s: "checking" } | { s: "match" }
  | { s: "other"; address: string; label: string; dismissed: boolean }
  | { s: "different"; address: string; dismissed: boolean } | { s: "unreadable"; error: string };

export const state: {
  status: Status | null;
  statusError: string | null;
  history: HistoryEntry[];
  view: View;
  drawerOpen: boolean;
  pair: PairState;
  identity: Identity;
  /** The account the phone on USB said it is using (attestation), until it leaves the bus. */
  phoneAddress: string | null;
  /** a device check started by identifyPhone() is in flight */
  identifying: boolean;
  /** Run on every identify/pair and (in Rust) before every send; cached per USB connection there. */
  device: DeviceCheck;
  /** Developer mode as Rust stores it (Settings → Device, typed confirmation); shown only. */
  devMode: boolean;
  failDismissed: boolean;
} = {
  status: null,
  statusError: null,
  history: [],
  view: "home",
  drawerOpen: false,
  pair: { s: "idle" },
  identity: { s: "unknown" },
  phoneAddress: null,
  identifying: false,
  device: { report: null, checking: false, error: null },
  devMode: false,
  failDismissed: false,
};

interface Bal { eth: string; wei: bigint; at: number }
export const balances = new Map<number, Bal>();
export const balErrors = new Map<number, string>();
export const prices: Record<string, number | null> = {};
export const price = (n: Network) => prices[n.symbol] ?? null;

/** The paired accounts. Shows which one the phone is using; switching pins new requests to it. */
export const activeLabel = () => state.status?.paired_label ?? "Account 1";
export const pairedAccounts = (): PairedAccount[] => state.status?.accounts ?? [];
