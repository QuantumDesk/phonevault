// PREVIEW DATA ONLY. Loaded when the page runs in a plain browser (no Tauri runtime) so the UI
// can be designed and screenshotted without a phone. Nothing here is ever used by the app.
//
// URL knobs: ?paired=0  ?phone=none|android|accessory  ?outcome=approve|reject|timeout|verify|nophone|broadcastfail
//            ?attest=development|genuine|fail|oldapp   (device check; "development" = today's dev phones: FAIL until Developer mode is on)
//            ?phonebusy=1   Send queues behind another request on the phone ("Waiting for your phone")
//            ?deposit=N     a deposit arrives N seconds after load (setup step 4, notifications)
//            ?history=0     empty activity (default: a stuck pending send, a speed-up pair, incoming ETH/USDC)
//            ?accounts=3    three paired accounts (Account 1, Account 2, Account 1 · passphrase)
//            ?phoneacct=2|pp|new  the phone is on Account 2 / the passphrase wallet / an unpaired account
// With ?paired=0 the guided setup opens. NFTs: three on Base; on Ethereum the scan is refused like on
// public nodes. The stuck transaction stays pending, so Speed up / Cancel can be walked through.

import type { Attestation, AttestationDetails, HistoryEntry, Stage, Quote, TxParams, Nft } from "./api";

const params = new URLSearchParams(location.search);
const ADDRESS = "0x7A3b9C1d2E4f5061728394A5b6C7d8E9f0A1B2c3";
const ADDRESS2 = "0x51eA0b8F1a0C6f3F0c1B2e5A6d7C8b9A0e1F2d3C";
const ADDRESS_PP = "0x9F3e2D1c0B9a8F7e6D5c4B3a2F1e0D9c8B7a6F5e";
const ADDRESS_NEW = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
/** The address the mock phone is on (its active account). */
const PHONE_ADDRESS = ({ "2": ADDRESS2, pp: ADDRESS_PP, new: ADDRESS_NEW } as Record<string, string>)[params.get("phoneacct") ?? ""] ?? ADDRESS;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const BAL: Record<number, string> = { 8453: "0.04213377", 1: "0.1284", 10: "0.0", 42161: "0.0031", 137: "12.5", 11155111: "1.9" };
const RPC_CHAIN: Record<string, number> = {
  "https://mainnet.base.org": 8453, "https://ethereum-rpc.publicnode.com": 1, "https://optimism-rpc.publicnode.com": 10,
  "https://arbitrum-one-rpc.publicnode.com": 42161, "https://polygon-bor-rpc.publicnode.com": 137, "https://ethereum-sepolia-rpc.publicnode.com": 11155111,
};
const toWei = (eth: string) => { const [w, f = ""] = eth.split("."); return (BigInt(w || "0") * 10n ** 18n + BigInt((f + "0".repeat(18)).slice(0, 18))).toString(); };

const MOCK_TOKENS = [
  { chainId: 8453, address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", symbol: "USDC", name: "USD Coin", decimals: 6 },
  { chainId: 8453, address: "0x4200000000000000000000000000000000000006", symbol: "WETH", name: "Wrapped Ether", decimals: 18 },
  { chainId: 1, address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", symbol: "USDC", name: "USD Coin", decimals: 6 },
];

/** Device-check reports shaped like the Rust side's, for each verdict. */
function mockAttestation(kind: string, allowDev: boolean): Attestation {
  const base: AttestationDetails = {
    phone_security_level: "StrongBox", attestation_security_level: "StrongBox", keymint_security_level: "StrongBox",
    attestation_version: 3, keymint_version: 4, device_locked: false, verified_boot_state: "Unverified (orange: bootloader unlocked)",
    verified_boot_key: "0000000000000000000000000000000000000000000000000000000000000000", verified_boot_key_known: false,
    verified_boot_hash: "6e9d0c5bea2cda99f3e5c76fb2740cdf8793d1d363422cd065d22bf0a2bb5bad", os_version: "15.0.0", os_patch_level: "2026-09",
    vendor_patch_level: "2022-01-05", boot_patch_level: "2026-09-05", app_package: "dev.phonevault.signer", app_version: 3,
    app_signer: "d8eab12db9f77634d1663d66df9928c184a2c91df03e3ea78abcddd64f114b53", app_signer_kind: "development",
    root: "Google Hardware Attestation Root (RSA)", provisioning: "factory", chain_length: 4, revocation: "Not revoked (Google status list of 2026-10-10)",
  };
  const now = Math.floor(Date.now() / 1000);
  const r = (a: Partial<Attestation>): Attestation => ({ verdict: "development", headline: "", problems: [], cautions: [], notes: [], details: base, address: PHONE_ADDRESS, checked_at: now, dev_mode: allowDev, ...a });
  switch (kind) {
    case "genuine": return r({ verdict: "genuine", headline: "Genuine Phone Vault: locked Phone Vault firmware, Phone Vault app, keys in the Titan M",
      details: { ...base, device_locked: true, verified_boot_state: "Self-signed (yellow)", verified_boot_key: "4f1c2a9e0b7d3c5a8e6f1b2d4c7a9e0f3b5d8c1a2e4f6b8d0c3a5e7f9b1d2c4e", verified_boot_key_known: true,
        app_signer: "7a1e3c5b9d2f4e6a8c0b1d3f5e7a9c2b4d6f8e0a1c3e5b7d9f2a4c6e8b0d1f3a", app_signer_kind: "release" } });
    case "fail": return r({ verdict: "fail", headline: "Not genuine: this phone failed the device check",
      problems: ["The phone boots firmware signed by a key that is not Phone Vault's (verified boot key 9c2e41d07a3b55e8…)."],
      details: { ...base, device_locked: true, verified_boot_state: "Self-signed (yellow)", verified_boot_key: "9c2e41d07a3b55e8f1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5e6f708192", app_signer_kind: "development" } });
    case "oldapp": return r({ verdict: "fail", headline: "Not genuine: this phone failed the device check", address: null, details: null,
      problems: ["The phone did not attest (Request fields do not match schema; missing=[nonce, …]). A Phone Vault app without device attestation cannot prove it is genuine; update the app."] });
    default:
      if (!allowDev) return r({ verdict: "fail", headline: "Not genuine: this phone failed the device check",
        problems: ["The Phone Vault app is signed with the development key, not the release key. Turn on Developer mode in Settings → Device only for a development phone."],
        cautions: ["Development firmware: bootloader unlocked — not safe for real funds"] });
      return r({ verdict: "development", headline: "Development firmware: bootloader unlocked — not safe for real funds",
        cautions: ["Development firmware: bootloader unlocked — not safe for real funds", "The Phone Vault app is signed with the development key (Developer mode is on on this Mac)."] });
  }
}

export interface Mock {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  onProgress(cb: (ticket: string, stage: Stage) => void): () => void;
  onEvent(name: string, cb: (payload: unknown) => void): () => void;
}

const SENDER = "0x51eA0B8f1a0C6f3F0c1B2E5A6d7C8b9A0e1F2d3C";
const rndHash = () => "0x" + Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
/** A recorded signed transaction (what broadcast_verified keeps for speed-up / cancel). */
const txp = (to: string, value: string, maxFee = "0x3b9aca00", prio = "0xf4240"): TxParams => ({ to: to.toLowerCase(), value, data: "0x", gas_limit: "0x5208", max_fee_per_gas: maxFee, max_priority_fee_per_gas: prio });
/** A small inline SVG standing in for an NFT image (the app fetches real ones only on request). */
const art = (hue: number, label: string) => "data:image/svg+xml;base64," + btoa(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8" shape-rendering="crispEdges"><rect width="8" height="8" fill="hsl(${hue} 55% 18%)"/><rect x="2" y="1" width="4" height="1" fill="hsl(${hue} 80% 70%)"/><rect x="1" y="2" width="1" height="2" fill="hsl(${hue} 80% 70%)"/><rect x="6" y="2" width="1" height="2" fill="hsl(${hue} 80% 70%)"/><rect x="1" y="4" width="6" height="3" fill="hsl(${hue} 80% 70%)"/><title>${label}</title></svg>`);

export function createMock(): Mock {
  type Acct = { address: string; label: string; wallet: "standard" | "passphrase" | null; account: number | null };
  const accounts: Acct[] = params.get("paired") === "0" ? [] : [{ address: ADDRESS, label: "Account 1", wallet: "standard", account: 1 }];
  if (accounts.length && Number(params.get("accounts") ?? "1") >= 2) accounts.push({ address: ADDRESS2, label: "Account 2", wallet: "standard", account: 2 });
  if (accounts.length && Number(params.get("accounts") ?? "1") >= 3) accounts.push({ address: ADDRESS_PP, label: "Account 1 · passphrase", wallet: "passphrase", account: 1 });
  let paired: string | null = accounts.length ? ADDRESS.toLowerCase() : null;
  const activeAcct = () => accounts.find((x) => x.address.toLowerCase() === paired) ?? null;
  const phoneAcct = (): { account: number | null; wallet: "standard" | "passphrase" | null } =>
    PHONE_ADDRESS === ADDRESS2 ? { account: 2, wallet: "standard" } : PHONE_ADDRESS === ADDRESS_PP ? { account: 1, wallet: "passphrase" } : PHONE_ADDRESS === ADDRESS_NEW ? { account: 3, wallet: "standard" } : { account: 1, wallet: "standard" };
  const phone = params.get("phone") ?? "accessory";
  const outcome = params.get("outcome") ?? "approve";
  let cancelled = false;
  const listeners = new Set<(t: string, s: Stage) => void>();
  const emit = (t: string, s: Stage) => listeners.forEach((l) => l(t, s));
  const events = new Map<string, Set<(p: unknown) => void>>();
  const fire = (name: string, p: unknown) => events.get(name)?.forEach((l) => l(p));
  const now = Math.floor(Date.now() / 1000);
  const base = (e: Partial<HistoryEntry>): HistoryEntry => ({ kind: "out", hash: null, chain_id: 8453, counterparty: null, amount_eth: "0", fee_max_eth: null, nonce: null, time: now, status: "received", block: null, ...e });
  const STUCK = "0x3c7e1f5a9b2d4e6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f";
  const SPED_ORIG = "0x71aa3e5c7b9d1f2a4c6e8b0d3f5a7c9e1b2d4f6a8c0e3b5d7f9a1c2e4b6d8f0a";
  let history: HistoryEntry[] = params.get("history") === "0" ? [] : [
    base({ kind: "out", hash: STUCK, counterparty: SENDER, amount_eth: "0.0125", fee_max_eth: "0.0000213", nonce: 6, time: now - 60 * 14, status: "pending", tx: txp(SENDER, "0x2c68af0bb140000") }),
    base({ kind: "in", hash: "0xa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", counterparty: SENDER, token_symbol: "USDC", token_amount: "125.5", token_contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", time: now - 3600 * 2, block: 20511100, log_index: 3 }),
    base({ kind: "out", hash: "0x5f1c9a7e3b2d4c6f8a0e1b3d5c7f9a2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a", counterparty: SENDER, amount_eth: "0.005", fee_max_eth: "0.00000412", nonce: 5, time: now - 3600 * 5, status: "confirmed", block: 20511233, replaces: SPED_ORIG, replacement_kind: "speedup", tx: txp(SENDER, "0x11c37937e08000", "0x59682f00") }),
    base({ kind: "out", hash: SPED_ORIG, counterparty: SENDER, amount_eth: "0.005", fee_max_eth: "0.00000210", nonce: 5, time: now - 3600 * 5 - 600, status: "dropped", tx: txp(SENDER, "0x11c37937e08000") }),
    base({ kind: "in", hash: "0x0f9e8d7c6b5a49382716051f2e3d4c5b6a79880f9e8d7c6b5a49382716051f2e", counterparty: SENDER, amount_eth: "0.02", time: now - 86400, block: 20480000 }),
    base({ kind: "in", amount_eth: "0.025", time: now - 86400 * 2 }),
    base({ kind: "out", hash: "0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", chain_id: 1, counterparty: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount_eth: "0.01", fee_max_eth: "0.00042", nonce: 11, time: now - 86400 * 9, status: "failed", block: 20111000 }),
  ];
  // ?deposit=1: the onboarding "waiting for a deposit" step sees funds arrive after a few seconds
  if (params.get("deposit")) setTimeout(() => { BAL[8453] = "0.05213377"; fire("watch-balance", { chain_id: 8453, balance_wei: toWei(BAL[8453]), balance_eth: BAL[8453], block: 20511300 }); }, Number(params.get("deposit")) * 1000 || 6000);
  let pending: { hash: string; to: string; amount: string; chain: number; polls: number; quote: Quote } | null = null;
  let lastAttestation: Attestation | null = null;
  let nfts: Nft[] = [
    { chain_id: 8453, contract: "0x6f2A1b3C4d5E6f708192a3B4c5D6e7F8091a2B3c", token_id: "4211", name: "Base Pixels", symbol: "BPX", owned: true, checked_at: now },
    { chain_id: 8453, contract: "0x6f2A1b3C4d5E6f708192a3B4c5D6e7F8091a2B3c", token_id: "88", name: "Base Pixels", symbol: "BPX", owned: true, checked_at: now },
    { chain_id: 8453, contract: "0x9a8B7c6D5e4F3a2B1c0D9e8F7a6B5c4D3e2F1a0B", token_id: "3", name: "Onchain Summer Pass", symbol: "OSP", owned: true, checked_at: now },
  ];

  async function invoke<T>(cmd: string, a: Record<string, unknown> = {}): Promise<T> {
    const chainOf = (url: unknown) => RPC_CHAIN[String(url)] ?? 8453;
    switch (cmd) {
      case "device_status": return { phone, paired, paired_checksum: activeAcct()?.address ?? null, paired_label: activeAcct()?.label ?? null,
        accounts: accounts.map((x) => ({ address: x.address.toLowerCase(), checksum: x.address, label: x.label, wallet: x.wallet, account: x.account, active: x.address.toLowerCase() === paired })),
        pairing_path: "~/Library/Application Support/PhoneVault/paired-accounts.json" } as T;
      case "read_address": {
        await sleep(1200); if (phone === "none") throw "no Android device on USB";
        const p = phoneAcct(); const known = accounts.find((x) => x.address === PHONE_ADDRESS);
        return { address: PHONE_ADDRESS, ...p, label: known?.label ?? (p.wallet === "passphrase" ? `Account ${p.account} · passphrase` : `Account ${p.account}`) } as T;
      }
      case "select_account": { const x = accounts.find((y) => y.address.toLowerCase() === String(a.address).toLowerCase()); if (!x) throw "that address is not paired with this Mac"; paired = x.address.toLowerCase(); return undefined as T; }
      case "rename_account": { const x = accounts.find((y) => y.address.toLowerCase() === String(a.address).toLowerCase()); if (x) x.label = String(a.label).trim() || x.label; return undefined as T; }
      case "forget_account": {
        const i = accounts.findIndex((y) => y.address.toLowerCase() === String(a.address).toLowerCase()); if (i >= 0) accounts.splice(i, 1);
        if (!activeAcct()) paired = accounts[0]?.address.toLowerCase() ?? null; return undefined as T;
      }
      case "attest_phone": {
        await sleep(1500); if (phone === "none") throw "no Android device on USB";
        lastAttestation = mockAttestation(params.get("attest") ?? "development", Boolean(a.allowDev)); return lastAttestation as T;
      }
      case "attestation_cached": return lastAttestation as T;
      case "confirm_pairing": {
        const addr = String(a.address); const known = accounts.find((x) => x.address.toLowerCase() === addr.toLowerCase());
        const label = (a.label as string | null) ?? `Account ${accounts.length + 1}`;
        if (known) known.label = label; else accounts.push({ address: addr, label, wallet: (a.wallet as Acct["wallet"]) ?? null, account: (a.account as number | null) ?? null });
        paired = addr.toLowerCase(); return "" as T;
      }
      case "forget_pairing": paired = null; accounts.length = 0; return undefined as T;
      case "wallet": {
        await sleep(300 + Math.random() * 500);
        if (!paired) throw "not paired yet";
        const c = chainOf(a.rpcUrl); const eth = BAL[c] ?? "0";
        return { address: activeAcct()?.address ?? ADDRESS, balance_wei: toWei(eth), balance_eth: eth, chain_id: c, block: 20511298 } as T;
      }
      case "fee_estimate": await sleep(250); return { chain_id: chainOf(a.rpcUrl), gas: 21000, typical_fee_wei: "1260000000000", typical_fee_eth: "0.00000126", max_fee_wei: "4200000000000", max_fee_eth: "0.0000042" } as T;
      case "max_sendable": await sleep(250); return { amount_eth: "0.04203377", amount_wei: toWei("0.04203377") } as T;
      case "check_address": {
        const s = String(a.address).trim();
        if (!s.startsWith("0x")) return { ok: false, checksum: null, error: "An address starts with 0x" } as T;
        if (!/^0x[0-9a-fA-F]{40}$/.test(s)) return { ok: false, checksum: null, error: "An address is 0x followed by 40 hex characters" } as T;
        if (/[A-F]/.test(s) && /[a-f]/.test(s) && s.endsWith("0")) return { ok: false, checksum: null, error: "Checksum mismatch: one character is probably wrong" } as T;
        return { ok: true, checksum: s, error: null } as T;
      }
      case "quote": {
        await sleep(700);
        const amt = String(a.amountEth);
        if (!amt || Number(amt) <= 0) throw "amount must be more than zero";
        const c = chainOf(a.rpcUrl);
        return { chain_id: "0x" + c.toString(16), nonce: "0x4", max_priority_fee_per_gas: "0xf4240", max_fee_per_gas: "0xc3500", gas_limit: "0x5208", to: String(a.to).toLowerCase(), value: "0x1", data: "0x", amount_eth: amt, max_fee_eth: "0.0000042", total_eth: (Number(amt) + 0.0000042).toFixed(8), balance_eth: BAL[c] ?? "0", network: c === 8453 ? "Base" : "Ethereum Mainnet" } as T;
      }
      case "sign_start": {
        const t = String(a.ticket); cancelled = false;
        const q = a.quote as { to: string; amount_eth: string; chain_id: string };
        // ?phonebusy=1: the phone is answering another request first (queued, not an error)
        if (params.get("phonebusy")) { await sleep(50); emit(t, "waiting"); for (let i = 0; i < 60; i++) { await sleep(100); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: false }; } }
        emit(t, "connecting"); await sleep(900);
        if (outcome === "nophone") throw { kind: "no_phone", message: "no Android device on USB", delivered: false };
        emit(t, "delivered");
        for (let i = 0; i < 40; i++) { await sleep(100); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: true }; }
        if (outcome === "reject") throw { kind: "rejected", message: "rejected on the phone", delivered: true };
        if (outcome === "timeout") throw { kind: "timeout", message: "the phone did not answer within 300 s", delivered: true };
        if (outcome === "verify") throw { kind: "verify", message: "signed transaction differs from the request in: value", delivered: true };
        emit(t, "verifying"); await sleep(400);
        const hash = rndHash();
        pending = { hash, to: q.to, amount: q.amount_eth, chain: parseInt(q.chain_id, 16), polls: 0, quote: a.quote as Quote };
        return { hash, signer: activeAcct()?.address ?? ADDRESS } as T;
      }
      case "sign_cancel": cancelled = true; return undefined as T;
      case "broadcast_verified": {
        await sleep(800);
        if (outcome === "broadcastfail") throw "node error for eth_sendRawTransaction: replacement transaction underpriced";
        if (!pending || pending.hash !== a.hash) throw "this transaction was not verified in this session, so it will not be broadcast";
        const q = pending.quote;
        history = [base({ kind: "out", hash: pending.hash, chain_id: pending.chain, counterparty: q.token ? q.token.recipient : pending.to, amount_eth: pending.amount, fee_max_eth: q.max_fee_eth, nonce: parseInt(q.nonce, 16),
          time: Math.floor(Date.now() / 1000), status: "pending", token_symbol: q.token?.symbol ?? null, token_amount: q.token?.amount ?? null,
          tx: { to: q.to, value: q.value, data: q.data, gas_limit: q.gas_limit, max_fee_per_gas: q.max_fee_per_gas, max_priority_fee_per_gas: q.max_priority_fee_per_gas },
          replaces: q.replaces?.hash ?? null, replacement_kind: q.replaces?.kind ?? null }), ...history];
        return pending.hash as T;
      }
      case "receipt": {
        await sleep(200);
        if (pending && pending.hash === a.hash && ++pending.polls < 2) return { mined: false, success: false, block: 0 } as T;
        // the stuck preview transaction stays stuck (so its speed-up wins the race)
        if (history.some((x) => x.hash === a.hash && x.status === "pending") && !(pending && pending.hash === a.hash)) return { mined: false, success: false, block: 0 } as T;
        return { mined: true, success: true, block: 20511299 } as T;
      }
      case "history_list": return history as T;
      case "history_mark": {
        const target = history.find((h) => h.hash === a.hash);
        history = history.map((h) => h.hash === a.hash ? { ...h, status: a.status as HistoryEntry["status"], block: a.block as number }
          : target && h.kind === "out" && h.status === "pending" && h.chain_id === target.chain_id && h.nonce === target.nonce && a.status !== "pending" ? { ...h, status: "dropped" } : h);
        return history as T;
      }
      case "history_add_incoming": return history as T;
      case "history_reconcile": await sleep(200); return history as T;
      case "replacement_quote": {
        await sleep(600);
        const e = history.find((x) => x.hash === a.hash);
        if (!e || e.status !== "pending") throw "this transaction is no longer pending (confirmed)";
        const cancel = a.kind === "cancel";
        if (!cancel && !e.tx) throw "this transaction was sent before this app kept its details, so it can only be cancelled";
        const c = e.chain_id;
        return { chain_id: "0x" + c.toString(16), nonce: "0x" + (e.nonce ?? 0).toString(16), max_priority_fee_per_gas: "0x1312d0", max_fee_per_gas: "0x47868c00", gas_limit: "0x5208",
          to: cancel ? ADDRESS.toLowerCase() : e.tx!.to, value: cancel ? "0x0" : e.tx!.value, data: "0x", amount_eth: cancel ? "0" : e.amount_eth, max_fee_eth: "0.0000252", total_eth: cancel ? "0.0000252" : (Number(e.amount_eth) + 0.0000252).toFixed(8),
          balance_eth: BAL[c] ?? "0", network: c === 8453 ? "Base" : "Ethereum Mainnet", token: null,
          replaces: { hash: e.hash!, kind: a.kind, previous_max_fee_per_gas: e.tx?.max_fee_per_gas ?? "0x3b9aca00", previous_max_priority_fee_per_gas: e.tx?.max_priority_fee_per_gas ?? "0xf4240" } } as T;
      }
      case "spot_usd": await sleep(200); return (a.symbol === "POL" ? 0.21 : a.symbol === "BTC" ? 61234.5 : 2451.37) as T;
      case "prices_usd": await sleep(200); return { ETH: 2451.37, POL: 0.21, BTC: 61234.5 } as T;
      case "watch_configure": return undefined as T;
      case "watch_scan_status": return [
        { chain_id: 8453, from_block: 20502300, to_block: 20511298, error: null },
        { chain_id: 42161, from_block: null, to_block: null, error: "node refused eth_getLogs: Archive requests require a personal token" },
      ] as T;
      case "nft_list": return nfts.filter((n) => n.chain_id === Number(a.chainId)) as T;
      case "nft_scan": {
        await sleep(1200); const c = chainOf(a.rpcUrl);
        if (c === 1) return { chain_id: c, nfts: [], from_block: null, to_block: null, error: "this node only answers log searches for specific contracts (\"Please specify an address in your request\")" } as T;
        return { chain_id: c, nfts: nfts.filter((n) => n.chain_id === c), from_block: 20502300, to_block: 20511298, error: null } as T;
      }
      case "nft_add_contract": {
        await sleep(900); const c = chainOf(a.rpcUrl);
        const n: Nft = { chain_id: c, contract: String(a.contract), token_id: "77", name: "Field Notes", symbol: "NOTE", owned: true, checked_at: now };
        nfts = [...nfts, n];
        return { chain_id: c, nfts: nfts.filter((x) => x.chain_id === c), from_block: 20502300, to_block: 20511298, error: null } as T;
      }
      case "nft_metadata": {
        await sleep(700);
        const i = nfts.findIndex((n) => n.contract === a.contract && n.token_id === a.tokenId);
        return { name: `${nfts[i]?.name ?? "Token"} #${a.tokenId}`, description: "Preview artwork.", image: art((i * 97 + 150) % 360, String(a.tokenId)), error: null } as T;
      }
      // ERC-20 (preview): a few entries shaped like the built-in list
      case "token_list": return MOCK_TOKENS as T;
      case "token_balances": {
        await sleep(300); const c = chainOf(a.rpcUrl);
        return { chain_id: c, balances: MOCK_TOKENS.filter((t) => t.chainId === c).map((t) => ({ address: t.address, symbol: t.symbol, name: t.name, decimals: t.decimals,
          raw: t.symbol === "USDC" ? "125500000" : "0", amount: t.symbol === "USDC" ? "125.5" : "0", error: null })) } as T;
      }
      case "token_quote": {
        await sleep(700); const c = chainOf(a.rpcUrl);
        const t = MOCK_TOKENS.find((x) => x.chainId === c && x.address.toLowerCase() === String(a.token).toLowerCase());
        if (!t) throw "that token is not in the built-in list for this network";
        const [w, f = ""] = String(a.amount).split(".");
        const raw = (BigInt(w || "0") * 10n ** BigInt(t.decimals) + BigInt((f + "0".repeat(t.decimals)).slice(0, t.decimals) || "0")).toString();
        return { chain_id: "0x" + c.toString(16), nonce: "0x4", max_priority_fee_per_gas: "0xf4240", max_fee_per_gas: "0xc3500", gas_limit: "0xfde8", to: t.address.toLowerCase(), value: "0x0",
          data: "0xa9059cbb", amount_eth: "0", max_fee_eth: "0.0000130", total_eth: "0.0000130", balance_eth: BAL[c] ?? "0", network: c === 8453 ? "Base" : "Ethereum Mainnet",
          token: { contract: t.address.toLowerCase(), symbol: t.symbol, name: t.name, decimals: t.decimals, recipient: String(a.to).toLowerCase(), amount_raw: raw, amount: String(a.amount).includes(".") ? String(a.amount).replace(/\.?0+$/, "") : String(a.amount) } } as T;
      }
    }
    throw `preview: no mock for ${cmd}`;
  }

  return {
    invoke,
    onProgress: (cb) => { listeners.add(cb); return () => listeners.delete(cb); },
    onEvent: (name, cb) => { if (!events.has(name)) events.set(name, new Set()); events.get(name)!.add(cb); return () => events.get(name)?.delete(cb); },
  };
}
