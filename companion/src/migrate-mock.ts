// Browser preview only (no Tauri): stand-in for the migrate_* commands (src-tauri/src/migrate), so
// the "Move from another wallet" screen can be looked at without a node. Loaded on demand by
// migrate.ts through registerPreview; never part of the app's command path. The first scan finds
// an old wallet with coins, tokens, an NFT, approvals and bitcoin; each re-scan ticks more off.
// ?migrate=1 starts with a saved session.

import { call } from "./api";
import type { Status } from "./api";
import { checksumAddress } from "./checksum";
import { NETWORKS } from "./networks";
import type { MSource, MSession, EvmReport, BtcReport, Destinations, MItem, MStatus } from "./migrate";

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const params = new URLSearchParams(location.search);
const OLD_EVM = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
const OLD_ZPUB = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";
const PHRASE = "That looks like a recovery phrase. Never type it into a computer. Phone Vault never asks for it: you move funds by sending from your old wallet. Paste an address or the account's public key (xpub) instead.";
const PRIVATE = "That is a PRIVATE key. Don't paste it anywhere, and treat it as exposed if you shared it. Phone Vault never needs it: you move funds by sending from your old wallet. Paste the account's public key (xpub) or an address instead.";

let session: MSession | null = params.get("migrate") === "1" ? { sources: [check(OLD_EVM), check(OLD_ZPUB)], started_at: Math.floor(Date.now() / 1000) - 3600, scanned_at: 0, path: "~/Library/Application Support/PhoneVault/migration.json" } : null;
const rounds = new Map<string, number>();

function check(input: string): MSource {
  const s = input.trim();
  if (s.split(/\s+/).length >= 11) throw PHRASE;
  if (/^(0x)?[0-9a-fA-F]{64}$/.test(s) || /^[xyztuv]prv/.test(s) || /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/.test(s)) throw PRIVATE;
  if (/^0x/i.test(s)) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(s)) throw "An Ethereum address is 0x followed by 40 hex characters.";
    const mixed = /[a-f]/.test(s.slice(2)) && /[A-F]/.test(s.slice(2));
    if (mixed && checksumAddress(s) !== s) throw "This address fails its checksum (EIP-55): one character is probably wrong. Copy it again from the old wallet.";
    return { kind: "evm", id: s.toLowerCase(), address: checksumAddress(s) };
  }
  const x = /^([xyztuv])pub[1-9A-HJ-NP-Za-km-z]{100,108}$/.exec(s);
  if (x) {
    const test = "tuv".includes(x[1]);
    const types = x[1] === "z" || x[1] === "v" ? ["native" as const] : x[1] === "y" || x[1] === "u" ? ["nested" as const] : ["native" as const, "taproot" as const, "legacy" as const, "nested" as const];
    return { kind: "xpub", id: s, prefix: `${x[1]}pub`, network: test ? "testnet" : "bitcoin", types,
      note: types.length > 1 ? "An xpub doesn't say which address type it was used for, so every type is checked (Native SegWit, Taproot, Legacy, Nested SegWit)." : null };
  }
  if (/^(bc1q|tb1q)[02-9ac-hj-np-z]{38,58}$/i.test(s)) return { kind: "btc_address", id: s.toLowerCase(), network: /^tb/i.test(s) ? "testnet" : "bitcoin", btc_type: "native" };
  if (/^(bc1p|tb1p)[02-9ac-hj-np-z]{58}$/i.test(s)) return { kind: "btc_address", id: s.toLowerCase(), network: /^tb/i.test(s) ? "testnet" : "bitcoin", btc_type: "taproot" };
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/.test(s)) return { kind: "btc_address", id: s, network: "bitcoin", btc_type: s.startsWith("1") ? "legacy" : "nested" };
  throw "That isn't an Ethereum address (0x…), a Bitcoin address, or an extended public key (xpub, ypub, zpub).";
}

const item = (key: string, symbol: string, name: string, amount: string, status: MStatus, dest: string, contract: string | null = null, decimals = 18): MItem =>
  ({ key, symbol, name, contract, decimals, raw: "0", amount, destination_amount: dest, status });

function evmReport(chain: number, address: string, dest: string, round: number): EvmReport {
  const n = NETWORKS.find((x) => x.id === chain) ?? NETWORKS[0];
  const k = (s: string) => `evm:${chain}:${address}:${s}`;
  const empty: EvmReport = {
    chain_id: chain, network: n.name, address: checksumAddress(address), destination: dest,
    native: item(k("native"), n.symbol, n.symbol, "0", "empty", "0"), tokens: [], unreadable_tokens: [], nfts: [],
    nft_window: { searched: true, from_block: 20_431_234, to_block: 20_511_233, error: null, capped: false }, approvals: [], approval_window: { searched: true, from_block: 20_431_234, to_block: 20_511_233, error: null, capped: false },
  };
  const later = round > 1;
  if (chain === 8453) return { ...empty,
    native: item(k("native"), "ETH", "ETH", "0.4213", "move", "0.04213377"),
    tokens: [
      later ? item(k("usdc"), "USDC", "USD Coin", "0", "moved", "1250", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6) : item(k("usdc"), "USDC", "USD Coin", "1250", "move", "0", "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", 6),
      item(k("dai"), "DAI", "Dai Stablecoin (bridged from Ethereum)", "3.17", "move", "0", "0x50c5725949A6F0c72E6C4a641F24049A917DB0Cb"),
    ],
    nfts: [{ key: k("nft:1"), contract: "0x6F2A1b3c4d5e6F708192a3b4C5d6E7F8091a2b3C", token_id: "4211", name: "Base Pixels", symbol: "BPX", status: later ? "moved" : "move", on_phone_vault: later }],
    approvals: [
      { key: k("ap:1"), kind: "token", contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", spender: "0x000000000022D473030F116dDEE9F6B43aC78BA3", amount: "unlimited", status: later ? "moved" : "move" },
      { key: k("ap:2"), kind: "collection", contract: "0x6F2A1b3c4d5e6F708192a3b4C5d6E7F8091a2b3C", symbol: "BPX", spender: "0x1E0049783F008A0085193E00003D00cd54003c71", amount: "all NFTs", status: "move" },
    ],
  };
  if (chain === 1) return { ...empty,
    native: item(k("native"), "ETH", "ETH", later ? "0.00000412" : "0.0518", later ? "moved" : "move", later ? "0.1802" : "0.1284"),
    nft_window: { searched: true, from_block: 21_201_000, to_block: 21_210_000, error: "searched as far back as the node allows", capped: false },
  };
  if (chain === 137) return { ...empty, unreadable_tokens: ["WETH"] };
  return empty;
}

export async function migrateMock(cmd: string, a: Record<string, unknown>): Promise<unknown> {
  switch (cmd) {
    case "migrate_check": await sleep(40); return check(String(a.input ?? ""));
    case "migrate_session": return session;
    case "migrate_save": {
      await sleep(250);
      const list = (a.sources as string[]).map((s, i) => { try { return check(s); } catch (e) { throw `Line ${i + 1}: ${e}`; } });
      const uniq = list.filter((s, i) => list.findIndex((x) => x.id === s.id) === i);
      session = { sources: uniq, started_at: session?.started_at ?? Math.floor(Date.now() / 1000), scanned_at: session?.scanned_at ?? 0, path: "~/Library/Application Support/PhoneVault/migration.json" };
      return session;
    }
    case "migrate_forget": session = null; rounds.clear(); return undefined;
    case "migrate_destinations": {
      const s = await call<Status>("device_status");
      const accounts = await call<{ accounts: { id: string; label: string; kind_name: string }[] }>("btc_accounts");
      const w = accounts.accounts[0] ? await call<{ receive_address: string; receive_index: number; receive_verified: boolean; confirmed_sats: number }>("btc_wallet", { id: accounts.accounts[0].id }) : null;
      const d: Destinations = {
        evm: s.paired_checksum ? { address: s.paired_checksum, label: s.paired_label ?? "Account 1" } : null,
        btc: w && accounts.accounts[0] ? [{ network: "bitcoin", network_name: "Bitcoin", unit: "BTC", id: accounts.accounts[0].id, label: accounts.accounts[0].label, kind_name: "Native SegWit", native_segwit: true,
          address: w.receive_address, index: w.receive_index, path: `m/84h/0h/0h/0/${w.receive_index}`, verified: w.receive_verified, balance_sats: w.confirmed_sats }] : [],
      };
      return d;
    }
    case "migrate_scan_evm": {
      const chain = NETWORKS.find((n) => n.rpc === a.rpcUrl)?.id ?? 8453;
      const id = String(a.address).toLowerCase();
      const r = (rounds.get(`${id}:${chain}`) ?? 0) + 1; rounds.set(`${id}:${chain}`, r);
      await sleep(a.deep ? 700 + Math.random() * 1600 : 400 + Math.random() * 500);
      if (chain === 42161 && r === 1) throw "the network node is unreachable (it timed out)";
      const s = await call<Status>("device_status");
      if (session) session.scanned_at = Math.floor(Date.now() / 1000);
      return evmReport(chain, id, s.paired_checksum ?? "", r);
    }
    case "migrate_scan_btc": {
      const id = String(a.source);
      const r = (rounds.get(id) ?? 0) + 1; rounds.set(id, r);
      await sleep(1200);
      const later = r > 2;
      const sending = r === 2; // the second scan sees the transfer in the mempool, the third confirmed
      const kind = session?.sources.find((s) => s.id === id);
      const report: BtcReport = { source: id, network: "bitcoin", network_name: "Bitcoin", unit: "BTC", server: "mempool.space",
        types: kind?.kind === "xpub" ? [{ btc_type: "native", name: "Native SegWit", looks: "bc1q…", confirmed_sats: later ? 0 : 1_234_500, unconfirmed_sats: 0, used_addresses: 6, checked_addresses: 47, first_address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu" }] : [],
        confirmed_sats: later ? 0 : 1_234_500, unconfirmed_sats: sending ? -1_234_500 : 0, status: later ? "moved" : sending ? "pending" : "move" };
      return report;
    }
    default: throw `preview: no mock for ${cmd}`;
  }
}
