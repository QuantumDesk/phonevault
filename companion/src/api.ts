// Typed bridge to the Rust side. In a plain browser (vite dev without Tauri) every call goes to
// the preview mock instead, so the UI can be looked at without a phone. The mock is never used
// inside the app: it is chosen once, by the absence of the Tauri runtime.

import type { Mock } from "./mock";

export type Presence = "none" | "android" | "accessory";
/** One paired account (a phone can have several, plus passphrase wallets). */
export interface PairedAccount { address: string; checksum: string; label: string; wallet: "standard" | "passphrase" | null; account: number | null; active: boolean }
/** `paired` is the ACTIVE account: the one the UI shows and every request is pinned to. */
export interface Status { phone: Presence; paired: string | null; paired_checksum: string | null; paired_label: string | null; accounts: PairedAccount[]; pairing_path: string }
/** The phone's active account as getAddress reports it (account/wallet are null for older phone apps;
 *  scheme is the phone's account numbering, "standard" unless the phone says "ledger-live"). */
export interface PhoneAccount { address: string; account: number | null; wallet: "standard" | "passphrase" | null; scheme?: "standard" | "ledger-live"; label: string }
export interface Wallet { address: string; balance_wei: string; balance_eth: string; chain_id: number; block: number }
export interface Quote {
  chain_id: string; nonce: string; max_priority_fee_per_gas: string; max_fee_per_gas: string; gas_limit: string;
  to: string; value: string; data: string; amount_eth: string; max_fee_eth: string; total_eth: string; balance_eth: string; network: string;
  /** ERC-20 transfer (from token_quote); the Rust side re-checks it against the built-in list. */
  token?: TokenIntent | null;
  /** Speed-up/cancel of a pending transaction (replacement_quote); re-checked in Rust before signing. */
  replaces?: Replacement | null;
}
export interface Replacement { hash: string; kind: "speedup" | "cancel"; previous_max_fee_per_gas: string | null; previous_max_priority_fee_per_gas: string | null }
export interface TxParams { to: string; value: string; data: string; gas_limit: string; max_fee_per_gas: string; max_priority_fee_per_gas: string }
/** One entry of the built-in token list (app/src/main/res/raw/tokens.json, shared with the phone). */
export interface TokenInfo { chainId: number; address: string; symbol: string; name: string; decimals: number }
export interface TokenIntent { contract: string; symbol: string; name: string; decimals: number; recipient: string; amount_raw: string; amount: string }
export interface TokenBalance { address: string; symbol: string; name: string; decimals: number; raw: string | null; amount: string | null; error: string | null }
export interface TokenBalances { chain_id: number; balances: TokenBalance[] }
export interface Signed { hash: string; signer: string }
export interface Receipt { mined: boolean; success: boolean; block: number }
export interface FeeEstimate { chain_id: number; gas: number; typical_fee_wei: string; typical_fee_eth: string; max_fee_wei: string; max_fee_eth: string }
export interface MaxAmount { amount_eth: string; amount_wei: string }
export interface AddressCheck { ok: boolean; checksum: string | null; error: string | null }
export interface HistoryEntry {
  kind: "out" | "in"; hash: string | null; chain_id: number; counterparty: string | null; amount_eth: string;
  fee_max_eth: string | null; nonce: number | null; time: number; status: "pending" | "confirmed" | "failed" | "received" | "dropped"; block: number | null;
  token_symbol?: string | null; token_amount?: string | null; token_contract?: string | null;
  /** sent from here: the signed fields (speed-up / cancel need them) */
  tx?: TxParams | null;
  replaces?: string | null; replacement_kind?: "speedup" | "cancel" | null; log_index?: number | null;
}
/** USD per unit for the coins whose price the app knows (Coinbase spot; null when unavailable). */
export interface Prices { ETH: number | null; POL: number | null; BTC: number | null }
/** Pushed by the background watcher (Rust) whenever it reads a native balance. */
export interface WatchBalance { owner?: string; chain_id: number; balance_wei: string; balance_eth: string; block: number }
/** How far back the watcher could search transfer logs on a network, or why it couldn't. */
export interface ScanStatus { chain_id: number; from_block: number | null; to_block: number | null; error: string | null }
export interface Nft { chain_id: number; contract: string; token_id: string; name: string | null; symbol: string | null; owned: boolean | null; checked_at: number }
export interface NftScan { chain_id: number; nfts: Nft[]; from_block: number | null; to_block: number | null; error: string | null }
export interface NftMeta { name: string | null; description: string | null; image: string | null; error: string | null }
/** Device attestation report (src-tauri/src/attest, vault-os/docs/device-attestation.md). */
export type Verdict = "genuine" | "development" | "fail";
export interface AttestationDetails {
  phone_security_level: string; attestation_security_level: string; keymint_security_level: string;
  attestation_version: number; keymint_version: number;
  device_locked: boolean | null; verified_boot_state: string | null; verified_boot_key: string | null; verified_boot_key_known: boolean;
  verified_boot_hash: string | null; os_version: string | null; os_patch_level: string | null; vendor_patch_level: string | null; boot_patch_level: string | null;
  app_package: string | null; app_version: number | null; app_signer: string | null; app_signer_kind: "release" | "development" | "unknown";
  root: string; provisioning: string; chain_length: number; revocation: string;
}
export interface Attestation {
  verdict: Verdict; headline: string; problems: string[]; cautions: string[]; notes: string[];
  details: AttestationDetails | null; address: string | null; checked_at: number; dev_mode: boolean;
}
/** One balance change of the paired wallet in a simulation (sim.rs). */
export interface SimChange { asset: string; token_id: string | null; delta: string; symbol: string | null; decimals: number | null; display: string }
/** Simulation on the user's node before anything goes to the phone (sim.rs, vault-os/docs/simulation.md). */
export interface Simulation {
  /** ok: changes known · reverts: blocked · no_changes: eth_call fallback (no revert, changes unknown) · unavailable: could not simulate */
  status: "ok" | "reverts" | "no_changes" | "unavailable";
  method: "eth_simulateV1" | "eth_call" | "none";
  changes: SimChange[]; fee_wei: string | null; gas_used: string | null;
  reason: string | null; note: string | null; node: string; block: number | null;
  /** the phone is shown these numbers as the Mac's (unverified) claim */
  for_phone: boolean;
}
/** Typed failure from sign_start. */
export interface SendError { kind: string; message: string; delivered: boolean }
export type Stage = "waiting" | "connecting" | "delivered" | "verifying";

export const isTauri = typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;

/** How long the phone review may take before Rust gives up on it (sign_start, sign_message: 300 s). */
export const REVIEW_LIMIT_MS = 300_000;

let mockPromise: Promise<Mock> | null = null;
const mock = () => (mockPromise ??= import("./mock").then((m) => m.createMock()));

/** A module's own preview stand-in for the commands it owns (WalletConnect, browser extension). */
export type PreviewInvoke = (cmd: string, args: Record<string, unknown>) => Promise<unknown>;
const previews: { owns: (cmd: string) => boolean; load: () => Promise<PreviewInvoke> }[] = [];

/** In the browser preview, send the commands `owns` accepts to `load()`'s mock instead of mock.ts.
 *  Does nothing inside the app. */
export function registerPreview(owns: (cmd: string) => boolean, load: () => Promise<PreviewInvoke>) {
  if (!isTauri) previews.push({ owns, load });
}

export async function call<T>(cmd: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri) {
    const p = previews.find((x) => x.owns(cmd));
    return p ? (await (await p.load())(cmd, args ?? {})) as T : (await mock()).invoke<T>(cmd, args);
  }
  const { invoke } = await import("@tauri-apps/api/core");
  return invoke<T>(cmd, args);
}

export const api = {
  status: () => call<Status>("device_status"),
  readAddress: () => call<PhoneAccount>("read_address"),
  /** scheme: the account numbering the phone reported (names "Account 2 · Ledger Live" when no label is typed) */
  confirmPairing: (address: string, label?: string | null, account?: number | null, wallet?: string | null, scheme?: string | null) =>
    call<string>("confirm_pairing", { address, label: label ?? null, account: account ?? null, wallet: wallet ?? null, scheme: scheme ?? null }),
  /** Show (and pin new requests to) another paired account. */
  selectAccount: (address: string) => call<void>("select_account", { address }),
  renameAccount: (address: string, label: string) => call<void>("rename_account", { address, label }),
  forgetAccount: (address: string) => call<void>("forget_account", { address }),
  forgetPairing: () => call<void>("forget_pairing"),
  /** Open the bundled blank backup card (PDF) in the system viewer for printing. */
  openBackupCard: (paper: "a4" | "letter", grid: "compact" | "standard") => call<void>("open_backup_card", { paper, grid }),
  wallet: (rpcUrl: string) => call<Wallet>("wallet", { rpcUrl }),
  quote: (rpcUrl: string, to: string, amountEth: string) => call<Quote>("quote", { rpcUrl, to, amountEth }),
  /** Simulate on the user's node; sign_start refuses a quote whose latest simulation reverted. */
  simulate: (rpcUrl: string, quote: Quote) => call<Simulation>("simulate", { rpcUrl, quote }),
  signStart: (ticket: string, quote: Quote) => call<Signed>("sign_start", { ticket, quote }),
  /** Cancel one request by ticket, or every request in flight. */
  signCancel: (ticket?: string) => call<void>("sign_cancel", { ticket: ticket ?? null }),
  broadcast: (rpcUrl: string, hash: string) => call<string>("broadcast_verified", { rpcUrl, hash }),
  receipt: (rpcUrl: string, hash: string) => call<Receipt>("receipt", { rpcUrl, hash }),
  feeEstimate: (rpcUrl: string) => call<FeeEstimate>("fee_estimate", { rpcUrl }),
  maxSendable: (rpcUrl: string, to: string | null) => call<MaxAmount>("max_sendable", { rpcUrl, to }),
  checkAddress: (address: string) => call<AddressCheck>("check_address", { address }),
  history: () => call<HistoryEntry[]>("history_list"),
  historyMark: (hash: string, status: string, block: number | null) => call<HistoryEntry[]>("history_mark", { hash, status, block }),
  prices: () => call<Prices>("prices_usd"),
  historyReconcile: (rpcUrl: string) => call<HistoryEntry[]>("history_reconcile", { rpcUrl }),
  /** Speed up (same transaction, higher fees) or cancel (0 to yourself, higher fees) a pending transaction. */
  replacementQuote: (rpcUrl: string, hash: string, kind: "speedup" | "cancel") => call<Quote>("replacement_quote", { rpcUrl, hash, kind }),
  /** Background watcher settings (nodes, notifications, selected network). */
  watchConfigure: (rpcs: Record<string, string>, notify: boolean, chainId: number) => call<void>("watch_configure", { rpcs, notify, chainId }),
  scanStatus: () => call<ScanStatus[]>("watch_scan_status"),
  nftList: (chainId: number) => call<Nft[]>("nft_list", { chainId }),
  nftScan: (rpcUrl: string) => call<NftScan>("nft_scan", { rpcUrl }),
  nftAddContract: (rpcUrl: string, contract: string) => call<NftScan>("nft_add_contract", { rpcUrl, contract }),
  nftMetadata: (rpcUrl: string, contract: string, tokenId: string) => call<NftMeta>("nft_metadata", { rpcUrl, contract, tokenId }),
  tokenList: () => call<TokenInfo[]>("token_list"),
  tokenBalances: (rpcUrl: string) => call<TokenBalances>("token_balances", { rpcUrl }),
  tokenQuote: (rpcUrl: string, token: string, to: string, amount: string) => call<Quote>("token_quote", { rpcUrl, token, to, amount }),
  /** Fresh device check over USB (the phone attests a new challenge). */
  attest: () => call<Attestation>("attest_phone"),
  /** Developer mode lives in Rust (a 0600 file on this Mac); turning it on needs the typed phrase. */
  developerMode: () => call<boolean>("developer_mode"),
  setDeveloperMode: (on: boolean, confirmation: string | null) => call<boolean>("set_developer_mode", { on, confirmation }),
  attestationCached: () => call<Attestation | null>("attestation_cached"),
};

/** Subscribe to send-progress events. Returns an unsubscribe function. */
export async function onProgress(cb: (ticket: string, stage: Stage) => void): Promise<() => void> {
  if (!isTauri) return (await mock()).onProgress(cb);
  const { listen } = await import("@tauri-apps/api/event");
  return listen<{ ticket: string; stage: Stage }>("send-progress", (e) => cb(e.payload.ticket, e.payload.stage));
}

/** Subscribe to an app event from Rust (the background watcher). In the preview, the mock emits them. */
export async function onEvent<T>(name: string, cb: (payload: T) => void): Promise<() => void> {
  if (!isTauri) return (await mock()).onEvent(name, cb as (p: unknown) => void);
  const { listen } = await import("@tauri-apps/api/event");
  return listen<T>(name, (e) => cb(e.payload));
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
