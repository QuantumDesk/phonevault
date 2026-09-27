// Typed bridge to the Rust side. In a plain browser (vite dev without Tauri) every call goes to
// the preview mock instead, so the UI can be looked at without a phone. The mock is never used
// inside the app: it is chosen once, by the absence of the Tauri runtime.

import type { Mock } from "./mock";

export type Presence = "none" | "android" | "accessory";
export interface Status { phone: Presence; paired: string | null; paired_checksum: string | null; pairing_path: string }
export interface Wallet { address: string; balance_wei: string; balance_eth: string; chain_id: number; block: number }
export interface Quote {
  chain_id: string; nonce: string; max_priority_fee_per_gas: string; max_fee_per_gas: string; gas_limit: string;
  to: string; value: string; data: string; amount_eth: string; max_fee_eth: string; total_eth: string; balance_eth: string; network: string;
}
export interface Signed { hash: string; signer: string }
export interface Receipt { mined: boolean; success: boolean; block: number }
export interface FeeEstimate { chain_id: number; gas: number; typical_fee_wei: string; typical_fee_eth: string; max_fee_wei: string; max_fee_eth: string }
export interface MaxAmount { amount_eth: string; amount_wei: string }
export interface AddressCheck { ok: boolean; checksum: string | null; error: string | null }
export interface HistoryEntry {
  kind: "out" | "in"; hash: string | null; chain_id: number; counterparty: string | null; amount_eth: string;
  fee_max_eth: string | null; nonce: number | null; time: number; status: "pending" | "confirmed" | "failed" | "received"; block: number | null;
}
/** Typed failure from sign_start. */
export interface SendError { kind: string; message: string; delivered: boolean }
export type Stage = "connecting" | "delivered" | "verifying";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

let mockPromise: Promise<Mock> | null = null;
const mock = () => (mockPromise ??= import("./mock").then((m) => m.createMock()));

async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) return (await mock()).invoke<T>(cmd, args);
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export const api = {
  status: () => call<Status>("device_status"),
  readAddress: () => call<string>("read_address"),
  confirmPairing: (address: string) => call<string>("confirm_pairing", { address }),
  forgetPairing: () => call<void>("forget_pairing"),
  wallet: (rpcUrl: string) => call<Wallet>("wallet", { rpcUrl }),
  quote: (rpcUrl: string, to: string, amountEth: string) => call<Quote>("quote", { rpcUrl, to, amountEth }),
  signStart: (ticket: string, quote: Quote) => call<Signed>("sign_start", { ticket, quote }),
  signCancel: () => call<void>("sign_cancel"),
  broadcast: (rpcUrl: string, hash: string) => call<string>("broadcast_verified", { rpcUrl, hash }),
  receipt: (rpcUrl: string, hash: string) => call<Receipt>("receipt", { rpcUrl, hash }),
  feeEstimate: (rpcUrl: string) => call<FeeEstimate>("fee_estimate", { rpcUrl }),
  maxSendable: (rpcUrl: string, to: string | null) => call<MaxAmount>("max_sendable", { rpcUrl, to }),
  checkAddress: (address: string) => call<AddressCheck>("check_address", { address }),
  history: () => call<HistoryEntry[]>("history_list"),
  historyMark: (hash: string, status: string, block: number | null) => call<HistoryEntry[]>("history_mark", { hash, status, block }),
  historyAddIncoming: (chainId: number, amountWei: string) => call<HistoryEntry[]>("history_add_incoming", { chainId, amountWei }),
  spotUsd: (symbol: string) => call<number>("spot_usd", { symbol }),
};

/** Subscribe to send-progress events. Returns an unsubscribe function. */
export async function onProgress(cb: (ticket: string, stage: Stage) => void): Promise<() => void> {
  if (!isTauri) return (await mock()).onProgress(cb);
  const { listen } = await import("@tauri-apps/api/event");
  return listen<{ ticket: string; stage: Stage }>("send-progress", (e) => cb(e.payload.ticket, e.payload.stage));
}

export async function openExternal(url: string) {
  if (!isTauri) { window.open(url, "_blank", "noopener"); return; }
  const { openUrl } = await import("@tauri-apps/plugin-opener");
  await openUrl(url);
}

export async function appVersion(): Promise<string> {
  if (!isTauri) return "0.1.0 (preview)";
  const { getVersion } = await import("@tauri-apps/api/app");
  return getVersion();
}

export async function notify(body: string) {
  if (!isTauri) { console.info("[preview notification]", body); return; }
  try {
    const n = await import("@tauri-apps/plugin-notification");
    let ok = await n.isPermissionGranted();
    if (!ok) ok = (await n.requestPermission()) === "granted";
    if (ok) n.sendNotification({ title: "Phone Vault", body });
  } catch { /* notifications are a convenience only */ }
}

/** A thrown value from invoke as display text. */
export function errText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object" && "message" in e) return String((e as { message: unknown }).message);
  return String(e);
}
