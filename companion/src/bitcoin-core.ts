// Bitcoin pieces shared by the Bitcoin screens (bitcoin.ts) and the Bitcoin send flow
// (bitcoin-send.ts): the Rust commands, the types they return, formatting, and the little state
// both read (the host hooks and which Bitcoin screen is showing).

import { call } from "./api";
import { fmtInt, fmtUsd } from "./ui";

export type BtcNet = "bitcoin" | "testnet" | "signet";
export const BTC_NETS: { id: BtcNet; name: string; unit: string; test: boolean }[] = [
  { id: "bitcoin", name: "Bitcoin", unit: "BTC", test: false },
  { id: "testnet", name: "Bitcoin Testnet", unit: "tBTC", test: true },
  { id: "signet", name: "Bitcoin Signet", unit: "sBTC", test: true },
];
export const btcNet = (id: BtcNet) => BTC_NETS.find((n) => n.id === id) ?? BTC_NETS[0];

/** The phone's address types (USB "type"). Nested SegWit and Legacy reach coins of a restored Ledger/Trezor-era wallet. */
export type BtcKind = "p2wpkh" | "p2tr" | "p2sh-p2wpkh" | "p2pkh";
export const BTC_KINDS: { id: BtcKind; name: string; bip: string; prefix: string; testPrefix: string; older: boolean; note: string; vbytes: number }[] = [
  { id: "p2wpkh", name: "Native SegWit", bip: "BIP-84", prefix: "bc1q", testPrefix: "tb1q", older: false, vbytes: 141,
    note: "Native SegWit (BIP-84): works with every wallet and exchange. The default." },
  { id: "p2tr", name: "Taproot", bip: "BIP-86", prefix: "bc1p", testPrefix: "tb1p", older: false, vbytes: 154,
    note: "Taproot (BIP-86): a little cheaper to spend. A few older exchanges can't send to bc1p addresses yet." },
  { id: "p2sh-p2wpkh", name: "Nested SegWit", bip: "BIP-49", prefix: "3…", testPrefix: "2…", older: true, vbytes: 166,
    note: "Nested SegWit (BIP-49, P2SH-P2WPKH): the \"SegWit\" accounts of older Ledger, Trezor and other wallets. Add it to reach coins you received there with the same recovery phrase. Native SegWit is recommended for new coins: spending from here costs about a third more in fees." },
  { id: "p2pkh", name: "Legacy", bip: "BIP-44", prefix: "1…", testPrefix: "m… / n…", older: true, vbytes: 226,
    note: "Legacy (BIP-44, P2PKH): the original address type of older Ledger, Trezor and other wallets. Add it to reach coins you received there with the same recovery phrase. Native SegWit is recommended for new coins: spending from here costs about twice as much in fees." },
];
export const btcKind = (id: string) => BTC_KINDS.find((k) => k.id === id) ?? BTC_KINDS[0];

export interface BtcAccount { id: string; network: BtcNet; kind: BtcKind; kind_name: string; account: number; label: string; fingerprint: string; path: string; xpub: string; descriptor: string; active: boolean; unit: string; network_name: string }
export interface Accounts { accounts: BtcAccount[]; servers: Record<string, string>; defaults: Record<string, string[]> }
export interface Candidate { id: string; network: BtcNet; kind: string; account: number; fingerprint: string; path: string; xpub: string; descriptor: string; first_address: string; already_paired: boolean; label: string }
export interface Shown { address: string; expected: string; matches: boolean }
export interface BtcHistory { txid: string; net_sats: number; fee_sats: number | null; status: "pending" | "confirmed" | "dropped"; confirmations: number; time: number; counterparty: string | null; explorer: string; can_bump: boolean; sent_here: boolean }
export interface BtcWallet { id: string; network: BtcNet; unit: string; confirmed_sats: number; unconfirmed_sats: number; receive_address: string; receive_index: number; receive_verified: boolean; history: BtcHistory[]; scanned_at: number; error: string | null; server: string; used_addresses: number }
export interface AddrCheck { ok: boolean; error: string | null; own: boolean; kind: string | null }
export interface Fees { fast: number; normal: number; slow: number; server: string }
export interface BtcQuote {
  quote_id: string; network: BtcNet; unit: string; recipient: string; amount_sats: number; fee_sats: number; vsize: number; rate: string; total_sats: number; change_sats: number;
  inputs: { outpoint: string; sats: number; address: string; confirmed: boolean }[]; outputs: { address: string; sats: number; change: boolean; path: string | null }[];
  replaces: string | null; own_recipient: boolean; unconfirmed_inputs: boolean; balance_sats: number; sequence: string;
}
export interface Signed { txid: string; fee_sats: number; vsize: number; rate: string; amount_sats: number; recipient: string; explorer: string; checks: string[] }
export interface TxState { confirmed: boolean; confirmations: number; height: number | null }
export interface Export { descriptor: string; receive: string; change: string; fingerprint: string; path: string; xpub: string; text: string }

export const btcApi = {
  accounts: () => call<Accounts>("btc_accounts"),
  readAccount: (network: BtcNet, kind: string, account: number) => call<Candidate>("btc_read_account", { network, kind, account }),
  showAddress: (id: string, change: number, index: number) => call<Shown>("btc_show_address", { id, change, index }),
  confirmAccount: (id: string, label: string | null) => call<BtcAccount>("btc_confirm_account", { id, label }),
  select: (id: string) => call<void>("btc_select", { id }),
  rename: (id: string, label: string) => call<void>("btc_rename", { id, label }),
  forget: (id: string) => call<void>("btc_forget", { id }),
  setServer: (network: BtcNet, url: string | null) => call<void>("btc_set_server", { network, url }),
  wallet: (id: string) => call<BtcWallet>("btc_wallet", { id }),
  refresh: (id: string, full: boolean) => call<BtcWallet>("btc_refresh", { id, full }),
  checkAddress: (id: string, address: string) => call<AddrCheck>("btc_check_address", { id, address }),
  fees: (id: string) => call<Fees>("btc_fees", { id }),
  quote: (id: string, to: string, amount: string | null, max: boolean, feeRate: string) => call<BtcQuote>("btc_quote", { id, to, amount, max, feeRate }),
  bumpQuote: (id: string, txid: string, feeRate: string) => call<BtcQuote>("btc_bump_quote", { id, txid, feeRate }),
  signStart: (ticket: string, quoteId: string) => call<Signed>("btc_sign_start", { ticket, quoteId }),
  signCancel: (ticket?: string) => call<void>("btc_sign_cancel", { ticket: ticket ?? null }),
  broadcast: (txid: string) => call<string>("btc_broadcast", { txid }),
  txStatus: (id: string, txid: string) => call<TxState>("btc_tx_status", { id, txid }),
  export: (id: string) => call<Export>("btc_export", { id }),
  saveExport: (id: string) => call<string>("btc_save_export", { id }),
};

export interface BtcHost {
  net(): BtcNet;
  showTestnets(): boolean;
  setShowTestnets(on: boolean): void;
  price(): number | null;
  /** redraw soon (background data; waits while the user is typing) */
  rerender(): void;
  /** redraw now (the user's own action or a flow step) */
  renderNow(): void;
  topbar(title: string, back: (() => void) | null): HTMLElement;
  networkSelect(): HTMLElement;
  /** why the phone can't take a request right now (device check failed, …), or null */
  phoneBlocked(): string | null;
  /** a request from another screen (EVM send, dApp) is on the phone */
  phoneBusy(): boolean;
}

// ------------------------------------------------------------------ formatting

/** Exact BTC from sats (string math, never floats for what is signed). */
export function fmtBtc(sats: number, trim = true): string {
  const neg = sats < 0; const s = Math.abs(Math.trunc(sats));
  const whole = Math.floor(s / 1e8); const frac = String(s % 1e8).padStart(8, "0");
  const f = trim ? frac.replace(/0+$/, "") : frac;
  return `${neg ? "−" : ""}${fmtInt(whole)}${f ? "." + f : ""}`;
}
export const fmtSats = (n: number) => `${fmtInt(Math.abs(n))} sat`;
export function usd(sats: number, price: number | null, test: boolean): string | null {
  if (price === null || test) return null;
  return fmtUsd(Math.abs(sats) / 1e8, price);
}
/** bc1q xxxx xxxx … in groups of four, for comparing by eye. */
export const groupedBtc = (a: string) => a.match(/.{1,4}/g)?.join(" ") ?? a;
/** "0.0005" BTC → sats, exactly; null when not a valid amount. */
export function btcToSats(s: string): number | null {
  const m = /^(\d{0,8})(?:\.(\d{0,8}))?$/.exec(s.trim());
  if (!m || (!m[1] && !m[2])) return null;
  return Number(m[1] || "0") * 1e8 + Number((m[2] ?? "").padEnd(8, "0"));
}
export const satsToBtcStr = (n: number) => `${Math.floor(n / 1e8)}.${String(n % 1e8).padStart(8, "0")}`.replace(/\.?0+$/, "") || "0";

// ------------------------------------------------------------------ shared state

export type Sub = "home" | "receive" | "send" | "pair";
/** `host` is set once by btcInit(); `sub` is the Bitcoin screen shown when a Bitcoin network is selected. */
export const btcState: { host: BtcHost; sub: Sub } = { host: undefined as unknown as BtcHost, sub: "home" };
export const wallets = new Map<string, BtcWallet>();

export function go(s: Sub) { btcState.sub = s; window.scrollTo(0, 0); btcState.host.renderNow(); }
