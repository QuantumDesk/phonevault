// PREVIEW DATA ONLY. Loaded when the page runs in a plain browser (no Tauri runtime) so the UI
// can be designed and screenshotted without a phone. Nothing here is ever used by the app.
//
// URL knobs: ?paired=0  ?phone=none|android|accessory  ?outcome=approve|reject|timeout|verify|nophone|broadcastfail
//            ?attest=development|genuine|fail|oldapp   (device check; "development" = today's dev phones: FAIL until Developer mode is on; ?devmode=1 starts with it on)
//            ?phonebusy=1   Send queues behind another request on the phone ("Waiting for your phone")
//            ?deposit=N     a deposit arrives N seconds after load (setup step 4, notifications)
//            ?history=0     empty activity (default: a stuck pending send, a speed-up pair, incoming ETH/USDC)
//            ?accounts=3    three paired accounts (Account 1, Account 2, Account 1 · passphrase)
//            ?phoneacct=2|pp|new  the phone is on Account 2 / the passphrase wallet / an unpaired account
//            Bitcoin: ?open=btc shows it; ?btc=0 no Bitcoin account yet (pairing), ?btcverified=1 receive address
//            already shown on the phone, ?btcshow=mismatch the phone shows another address, ?outcome= as above
// With ?paired=0 the guided setup opens. NFTs: three on Base; on Ethereum the scan is refused like on
// public nodes. The stuck transaction stays pending, so Speed up / Cancel can be walked through.

import type { Attestation, AttestationDetails, HistoryEntry, Stage, Quote, TxParams, Nft } from "./api";
import { checksumAddress } from "./checksum";

const params = new URLSearchParams(location.search);
const ADDRESS = "0x7A3B9C1d2e4F5061728394a5b6c7d8E9F0a1b2C3";
const ADDRESS2 = "0x51Ea0B8F1a0c6f3f0c1b2E5a6d7c8b9a0e1F2d3C";
const ADDRESS_PP = "0x9f3e2d1c0b9a8F7E6d5C4B3a2F1e0D9c8B7a6F5E";
const ADDRESS_NEW = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC";
/** The address the mock phone is on (its active account). */
const PHONE_ADDRESS = ({ "2": ADDRESS2, pp: ADDRESS_PP, new: ADDRESS_NEW } as Record<string, string>)[params.get("phoneacct") ?? ""] ?? ADDRESS;
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
/** The Rust messages the preview repeats (pairing.rs NOT_PAIRED, send.rs). */
const NOT_PAIRED = "Your phone isn't paired with this Mac yet. Pair it first, then try again.";
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

/** policy.rs UNLOCKED_PROBLEM (the problem an unlocked bootloader gives with Developer mode off). */
const UNLOCKED_PROBLEM = "The phone's bootloader is unlocked, so its software can be replaced without anyone noticing. Accept it only for a phone you flashed yourself: Settings → Device → Developer mode.";

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
  const r = (a: Partial<Attestation>): Attestation => ({ verdict: "development", headline: "", problems: [], cautions: [], notes: [], details: base, address: PHONE_ADDRESS, checked_at: now, dev_mode: allowDev, dev_mode_fixable: false, ...a });
  switch (kind) {
    case "genuine": return r({ verdict: "genuine", headline: "Genuine Phone Vault: locked Phone Vault firmware, Phone Vault app, keys in the security chip",
      details: { ...base, device_locked: true, verified_boot_state: "Self-signed (yellow)", verified_boot_key: "4f1c2a9e0b7d3c5a8e6f1b2d4c7a9e0f3b5d8c1a2e4f6b8d0c3a5e7f9b1d2c4e", verified_boot_key_known: true,
        app_signer: "7a1e3c5b9d2f4e6a8c0b1d3f5e7a9c2b4d6f8e0a1c3e5b7d9f2a4c6e8b0d1f3a", app_signer_kind: "release" } });
    case "fail": return r({ verdict: "fail", headline: "Not genuine: this phone failed the genuine check",
      problems: ["The phone boots firmware signed by a key that is not Phone Vault's (verified boot key 9c2e41d07a3b55e8…)."],
      details: { ...base, device_locked: true, verified_boot_state: "Self-signed (yellow)", verified_boot_key: "9c2e41d07a3b55e8f1d2c3b4a5968778695a4b3c2d1e0f1a2b3c4d5e6f708192", app_signer_kind: "development" } });
    case "oldapp": return r({ verdict: "fail", headline: "Not genuine: this phone failed the genuine check", address: null, details: null,
      problems: ["The phone did not answer the genuine check (Request fields do not match schema; missing=[nonce, …]). A Phone Vault app this old cannot prove it is genuine; update the app on the phone."] });
    case "beta":
      // a public beta phone: unlocked bootloader + beta-signed app (policy.rs)
      if (!allowDev) return r({ verdict: "fail", headline: "Not genuine: this phone failed the genuine check", details: { ...base, app_signer_kind: "beta" }, dev_mode_fixable: true,
        problems: ["This phone runs the Phone Vault public beta. Beta phones have an unlocked bootloader, so this Mac accepts one only after you confirm you flashed it yourself: Settings → Device → Developer mode.", UNLOCKED_PROBLEM] });
      return r({ verdict: "development", headline: "Beta build: bootloader unlocked, not production. Small amounts only", details: { ...base, app_signer_kind: "beta" },
        cautions: ["The Phone Vault app is the public beta (beta key), confirmed on this Mac as a phone you flashed yourself.", "Development firmware: bootloader unlocked, not safe for real funds"] });
    default:
      // Developer mode off: both reasons are problems, in policy.rs order (app, then boot)
      if (!allowDev) return r({ verdict: "fail", headline: "Not genuine: this phone failed the genuine check", dev_mode_fixable: true,
        problems: ["The Phone Vault app is signed with the development key, not the release key. Turn on Developer mode in Settings → Device only for a development phone.", UNLOCKED_PROBLEM] });
      return r({ verdict: "development", headline: "Development firmware: bootloader unlocked, not safe for real funds",
        cautions: ["Development firmware: bootloader unlocked, not safe for real funds", "The Phone Vault app is signed with the development key (Developer mode is on on this Mac)."] });
  }
}

export interface Mock {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  onProgress(cb: (ticket: string, stage: Stage) => void): () => void;
  onEvent(name: string, cb: (payload: unknown) => void): () => void;
}

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
  /** Wakes the one pending phone wait early (sign_cancel); one timer, so background tabs don't stretch it. */
  let wake: (() => void) | null = null;
  const phoneWait = (ms: number) => new Promise<void>((done) => {
    const t = setTimeout(() => { wake = null; done(); }, ms);
    wake = () => { clearTimeout(t); wake = null; done(); };
  });
  const listeners = new Set<(t: string, s: Stage) => void>();
  const emit = (t: string, s: Stage) => listeners.forEach((l) => l(t, s));
  const events = new Map<string, Set<(p: unknown) => void>>();
  const fire = (name: string, p: unknown) => events.get(name)?.forEach((l) => l(p));
  const now = Math.floor(Date.now() / 1000);
  const base = (e: Partial<HistoryEntry>): HistoryEntry => ({ kind: "out", hash: null, chain_id: 8453, counterparty: null, amount_eth: "0", fee_max_eth: null, nonce: null, time: now, status: "received", block: null, ...e });
  const STUCK = "0x3c7e1f5a9b2d4e6f8a0c1e3b5d7f9a2c4e6b8d0f1a3c5e7b9d2f4a6c8e0b1d3f";
  const SPED_ORIG = "0x71aa3e5c7b9d1f2a4c6e8b0d3f5a7c9e1b2d4f6a8c0e3b5d7f9a1c2e4b6d8f0a";
  let history: HistoryEntry[] = params.get("history") === "0" ? [] : [
    base({ kind: "out", hash: STUCK, counterparty: ADDRESS2, amount_eth: "0.0125", fee_max_eth: "0.0000213", nonce: 6, time: now - 60 * 14, status: "pending", tx: txp(ADDRESS2, "0x2c68af0bb140000") }),
    base({ kind: "in", hash: "0xa1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90", counterparty: ADDRESS2, token_symbol: "USDC", token_amount: "125.5", token_contract: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", time: now - 3600 * 2, block: 20511100, log_index: 3 }),
    base({ kind: "out", hash: "0x5f1c9a7e3b2d4c6f8a0e1b3d5c7f9a2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a", counterparty: ADDRESS2, amount_eth: "0.005", fee_max_eth: "0.00000412", nonce: 5, time: now - 3600 * 5, status: "confirmed", block: 20511233, replaces: SPED_ORIG, replacement_kind: "speedup", tx: txp(ADDRESS2, "0x11c37937e08000", "0x59682f00") }),
    base({ kind: "out", hash: SPED_ORIG, counterparty: ADDRESS2, amount_eth: "0.005", fee_max_eth: "0.00000210", nonce: 5, time: now - 3600 * 5 - 600, status: "dropped", tx: txp(ADDRESS2, "0x11c37937e08000") }),
    base({ kind: "in", hash: "0x0f9e8d7c6b5a49382716051f2e3d4c5b6a79880f9e8d7c6b5a49382716051f2e", counterparty: ADDRESS2, amount_eth: "0.02", time: now - 86400, block: 20480000 }),
    base({ kind: "in", amount_eth: "0.025", time: now - 86400 * 2 }),
    base({ kind: "out", hash: "0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", chain_id: 1, counterparty: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount_eth: "0.01", fee_max_eth: "0.00042", nonce: 11, time: now - 86400 * 9, status: "failed", block: 20111000 }),
  ];
  // ?deposit=1: the onboarding "waiting for a deposit" step sees funds arrive after a few seconds
  if (params.get("deposit")) setTimeout(() => { BAL[8453] = "0.05213377"; fire("watch-balance", { chain_id: 8453, balance_wei: toWei(BAL[8453]), balance_eth: BAL[8453], block: 20511300 }); }, Number(params.get("deposit")) * 1000 || 6000);
  let pending: { hash: string; to: string; amount: string; chain: number; polls: number; quote: Quote } | null = null;
  let lastAttestation: Attestation | null = null;
  let devMode = params.get("devmode") === "1";
  let nfts: Nft[] = [
    { chain_id: 8453, contract: "0x6F2A1b3c4d5e6F708192a3b4C5d6E7F8091a2b3C", token_id: "4211", name: "Base Pixels", symbol: "BPX", owned: true, checked_at: now },
    { chain_id: 8453, contract: "0x6F2A1b3c4d5e6F708192a3b4C5d6E7F8091a2b3C", token_id: "88", name: "Base Pixels", symbol: "BPX", owned: true, checked_at: now },
    { chain_id: 8453, contract: "0x9a8b7c6d5e4f3a2B1C0d9e8F7a6b5c4D3e2f1A0b", token_id: "3", name: "Onchain Summer Pass", symbol: "OSP", owned: true, checked_at: now },
  ];

  // ---- Bitcoin (BIP-84 test vectors of the "abandon … about" wallet; preview only)
  const XPUB = "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V";
  // BIP-49 / BIP-44 account 1 of "abandon … about" (pairing preview for the older address types)
  const BTC_OLDER: Record<string, { purpose: number; name: string; xpub: string; first: string }> = {
    "p2sh-p2wpkh": { purpose: 49, name: "Nested SegWit", xpub: "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7", first: "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf" },
    p2pkh: { purpose: 44, name: "Legacy", xpub: "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj", first: "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA" },
  };
  const btcAcct = (n: number, label: string) => ({ id: `73c5da0a-bitcoin-p2wpkh-${n}`, network: "bitcoin", kind: "p2wpkh", kind_name: "Native SegWit", account: n, label, fingerprint: "73c5da0a",
    path: `m/84h/0h/${n - 1}h`, xpub: XPUB, descriptor: `wpkh([73c5da0a/84h/0h/${n - 1}h]${XPUB}/<0;1>/*)#k6qmeeqa`, active: true, unit: "BTC", network_name: "Bitcoin" });
  const btcAccounts = params.get("btc") === "0" ? [] : [btcAcct(1, "Bitcoin 1")];
  let btcVerified = params.get("btcverified") === "1";
  const RECV = "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g";
  const btcHistory = [
    { txid: "d1c2b3a4958677685940312a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e", net_sats: 50_000, fee_sats: null, status: "pending", confirmations: 0, time: now - 240, counterparty: "bc1q9vza2e8x573nczrlzms0wvx3gsqjx7vavgkx0l", can_bump: false, sent_here: false },
    { txid: "7f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d7c6b5a4f3e", net_sats: -251_420, fee_sats: 1_420, status: "confirmed", confirmations: 18, time: now - 3600 * 6, counterparty: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", can_bump: false, sent_here: true },
    { txid: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9", net_sats: 1_000_000, fee_sats: null, status: "confirmed", confirmations: 1_204, time: now - 86400 * 9, counterparty: "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh", can_bump: false, sent_here: false },
    { txid: "9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", net_sats: 485_987, fee_sats: null, status: "confirmed", confirmations: 2_950, time: now - 86400 * 21, counterparty: "3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", can_bump: false, sent_here: false },
  ].map((e) => ({ ...e, explorer: `https://mempool.space/tx/${e.txid}` }));
  let btcConfirmed = 1_234_567;
  let btcSigned: { txid: string; q: Record<string, unknown>; polls: number } | null = null;
  const btcWallet = (id: string) => ({ id, network: "bitcoin", unit: "BTC", confirmed_sats: btcConfirmed, unconfirmed_sats: 50_000, receive_address: RECV, receive_index: 1, receive_verified: btcVerified,
    history: btcHistory, scanned_at: now - 40, error: null, server: "mempool.space", used_addresses: 4 });

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
        lastAttestation = mockAttestation(params.get("attest") ?? "development", devMode); return lastAttestation as T;
      }
      case "developer_mode": return devMode as T;
      case "set_developer_mode": {
        if (a.on && String(a.confirmation ?? "").trim() !== "I FLASHED THIS PHONE") throw "Type I FLASHED THIS PHONE to turn on Developer mode.";
        devMode = Boolean(a.on); lastAttestation = null; return devMode as T;
      }
      case "attestation_cached": return lastAttestation as T;
      case "confirm_pairing": {
        const addr = String(a.address); const known = accounts.find((x) => x.address.toLowerCase() === addr.toLowerCase());
        const label = (a.label as string | null) ?? `Account ${accounts.length + 1}`;
        if (known) known.label = label; else accounts.push({ address: addr, label, wallet: (a.wallet as Acct["wallet"]) ?? null, account: (a.account as number | null) ?? null });
        paired = addr.toLowerCase(); return "" as T;
      }
      case "forget_pairing": paired = null; accounts.length = 0; return undefined as T;
      case "open_backup_card": return undefined as T;
      case "wallet": {
        await sleep(300 + Math.random() * 500);
        if (!paired) throw NOT_PAIRED;
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
        return { ok: true, checksum: checksumAddress(s), error: null } as T;
      }
      case "quote": {
        await sleep(700);
        const amt = String(a.amountEth);
        if (!amt || Number(amt) <= 0) throw "amount must be more than zero";
        const c = chainOf(a.rpcUrl);
        return { chain_id: "0x" + c.toString(16), nonce: "0x4", max_priority_fee_per_gas: "0xf4240", max_fee_per_gas: "0xc3500", gas_limit: "0x5208", to: String(a.to).toLowerCase(), value: "0x1", data: "0x", amount_eth: amt, max_fee_eth: "0.0000042", total_eth: (Number(amt) + 0.0000042).toFixed(8), balance_eth: BAL[c] ?? "0", network: c === 8453 ? "Base" : "Ethereum Mainnet" } as T;
      }
      case "simulate": {
        // ?sim=ok (default) | reverts | nochanges | unavailable
        await sleep(900);
        const q = a.quote as Quote;
        const c = parseInt(q.chain_id, 16);
        const node = new URL(String(a.rpcUrl)).host;
        const sym = c === 137 ? "POL" : "ETH";
        const kind = params.get("sim") ?? "ok";
        const base = { method: "eth_simulateV1", changes: [], fee_wei: null, gas_used: null, reason: null, note: null, node, block: 20511298, for_phone: false };
        if (kind === "reverts") return { ...base, status: "reverts", gas_used: "35241", reason: q.token ? "ERC20: transfer amount exceeds balance" : "Too little received" } as T;
        if (kind === "nochanges") return { ...base, status: "no_changes", method: "eth_call", gas_used: "52310", note: "Balance changes unavailable on this node (it does not support eth_simulateV1). eth_call says it does not revert." } as T;
        if (kind === "unavailable") return { ...base, status: "unavailable", method: "none", reason: "the node could not run it: header not found" } as T;
        const fee = 0.0000231;
        const changes = q.token
          ? [{ asset: "native", token_id: null, delta: "-23100000000000", symbol: sym, decimals: 18, display: `−${fee} ${sym}` },
             { asset: q.token.contract.toLowerCase(), token_id: null, delta: "-" + q.token.amount_raw, symbol: q.token.symbol, decimals: q.token.decimals, display: `−${q.token.amount} ${q.token.symbol}` }]
          : [{ asset: "native", token_id: null, delta: "-1", symbol: sym, decimals: 18, display: `−${(Number(q.amount_eth) + fee).toFixed(8).replace(/0+$/, "")} ${sym}` }];
        return { ...base, status: "ok", changes, fee_wei: "23100000000000", gas_used: q.token ? "62248" : "21000", for_phone: true,
          note: [8453, 10, 42161].includes(c) ? "Plus a small L1 data fee the simulation does not include." : null } as T;
      }
      case "sign_start": {
        const t = String(a.ticket); cancelled = false;
        const q = a.quote as { to: string; amount_eth: string; chain_id: string };
        // ?phonebusy=1: the phone is answering another request first (queued, not an error)
        if (params.get("phonebusy")) { await sleep(50); emit(t, "waiting"); await phoneWait(6000); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: false }; }
        emit(t, "connecting"); await sleep(900);
        if (outcome === "nophone") throw { kind: "no_phone", message: "no Android device on USB", delivered: false };
        emit(t, "delivered");
        await phoneWait(4000); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: true };
        if (outcome === "reject") throw { kind: "rejected", message: "rejected on the phone", delivered: true };
        if (outcome === "timeout") throw { kind: "timeout", message: "the phone did not answer within 300 s", delivered: true };
        if (outcome === "verify") throw { kind: "verify", message: "signed transaction differs from the request in: value", delivered: true };
        emit(t, "verifying"); await sleep(400);
        const hash = rndHash();
        pending = { hash, to: q.to, amount: q.amount_eth, chain: parseInt(q.chain_id, 16), polls: 0, quote: a.quote as Quote };
        return { hash, signer: activeAcct()?.address ?? ADDRESS } as T;
      }
      case "sign_cancel": cancelled = true; wake?.(); return undefined as T;
      // signing.rs: personal_sign / eth_signTypedData_v4 (the Sign a message screen and dApp requests)
      case "sign_message": case "sign_typed_data": {
        if (!paired) throw NOT_PAIRED;
        if (![1, 11155111, 8453, 10, 42161, 137].includes(Number(a.chainId))) throw `the phone has no reviewed profile for chain ${a.chainId}`;
        if (cmd === "sign_message") {
          const m = String(a.message ?? "");
          if (a.isHex && !m.trim().startsWith("0x")) throw "hex message must start with 0x";
          if (a.isHex && !/^(?:[0-9a-fA-F]{2})*$/.test(m.trim().slice(2))) throw "hex message must be an even number of hex digits";
          if (!(a.isHex ? m.trim().slice(2) : m)) throw "the message is empty";
        } else {
          try { JSON.parse(String(a.typedData ?? "")); } catch { throw "typed data is not valid JSON"; }
        }
        await sleep(2600);
        if (outcome === "reject") throw "rejected on the phone";
        if (outcome === "nophone") throw "no Android device on USB";
        return { signature: rndHash() + rndHash().slice(2) + "1b", digest: rndHash(), signer: activeAcct()?.address ?? ADDRESS } as T;
      }
      case "broadcast_verified": {
        await sleep(800);
        if (outcome === "broadcastfail") throw "node error for eth_sendRawTransaction: replacement transaction underpriced";
        if (!pending || pending.hash !== a.hash) throw "This transaction was not verified in this session, so it was not sent to the network. Start the send again.";
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
    switch (cmd) {
      case "btc_accounts": return { accounts: btcAccounts, servers: {}, defaults: { bitcoin: ["https://mempool.space/api", "https://blockstream.info/api"], testnet: ["https://mempool.space/testnet4/api"], signet: ["https://mempool.space/signet/api"] } } as T;
      case "btc_wallet": case "btc_refresh": await sleep(cmd === "btc_refresh" ? 900 : 100); return btcWallet(String(a.id)) as T;
      case "btc_read_account": {
        await sleep(1600); if (phone === "none") throw "no Android device on USB";
        const n = Number(a.account); const tr = a.kind === "p2tr"; const older = BTC_OLDER[String(a.kind)];
        return { id: `73c5da0a-${a.network}-${a.kind}-${n}`, network: a.network, kind: a.kind, account: n, fingerprint: "73c5da0a", path: `m/${older ? older.purpose : tr ? 86 : 84}h/0h/${n - 1}h`,
          xpub: older ? older.xpub : tr ? "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ" : XPUB, descriptor: "",
          first_address: older ? older.first : tr ? "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr" : "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", already_paired: false, label: `Bitcoin ${n}${older ? ` · ${older.name}` : tr ? " · Taproot" : ""}` } as T;
      }
      case "btc_show_address": {
        await sleep(1800); if (phone === "none") throw "no Android device on USB";
        const olderShown = Object.entries(BTC_OLDER).find(([k]) => String(a.id).includes(`-${k}-`))?.[1];
        const expected = Number(a.index) === 0 ? (olderShown ? olderShown.first : String(a.id).includes("p2tr") ? "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr" : "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu") : RECV;
        const bad = params.get("btcshow") === "mismatch";
        const address = bad ? "bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh" : expected;
        if (!bad && Number(a.index) === 1) btcVerified = true;
        return { address, expected, matches: !bad } as T;
      }
      case "btc_confirm_account": { const acc = btcAcct(btcAccounts.length + 1, String(a.label ?? `Bitcoin ${btcAccounts.length + 1}`)); btcAccounts.push(acc); return acc as T; }
      case "btc_select": case "btc_rename": case "btc_set_server": return undefined as T;
      case "btc_forget": { const i = btcAccounts.findIndex((x) => x.id === a.id); if (i >= 0) btcAccounts.splice(i, 1); return undefined as T; }
      case "btc_fees": await sleep(300); return { fast: 12.4, normal: 6.1, slow: 2, server: "mempool.space" } as T;
      case "btc_check_address": {
        const v = String(a.address).trim().replace(/^bitcoin:/, "");
        if (/^(bc1q[02-9ac-hj-np-z]{38}|bc1p[02-9ac-hj-np-z]{58}|[13][1-9A-HJ-NP-Za-km-z]{25,34})$/i.test(v)) {
          if (v.endsWith("x")) return { ok: false, error: "Checksum mismatch: a character is probably wrong", own: false, kind: null } as T;
          return { ok: true, error: null, own: v === RECV, kind: v.startsWith("bc1p") ? "Taproot" : v.startsWith("bc1q") ? "Native SegWit" : v.startsWith("3") ? "Script (P2SH)" : "Legacy" } as T;
        }
        if (/^tb1/.test(v)) return { ok: false, error: "That is a test-network address, not a Bitcoin address", own: false, kind: null } as T;
        return { ok: false, error: "Not a Bitcoin address", own: false, kind: null } as T;
      }
      case "btc_quote": case "btc_bump_quote": {
        await sleep(900);
        const rate = Number(a.feeRate);
        const vsize = 141;
        const fee = Math.ceil(vsize * rate) + (cmd === "btc_bump_quote" ? 300 : 0);
        const amount = a.max ? btcConfirmed + 50_000 - fee : Math.round(Number(a.amount) * 1e8);
        if (amount + fee > btcConfirmed + 50_000) throw `not enough bitcoin: ${a.amount} BTC plus the fee needed, 0.01284567 BTC spendable`;
        const inputs = [{ outpoint: "0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9:1", sats: 1_000_000, address: "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", confirmed: true }];
        const inTotal = 1_000_000;
        const change = a.max ? 0 : inTotal - amount - fee;
        const to = cmd === "btc_bump_quote" ? "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq" : String(a.to).trim();
        const outputs = [{ address: to, sats: amount, change: false, path: null }, ...(change > 0 ? [{ address: "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el", sats: change, change: true, path: "m/84h/0h/0h/1/0" }] : [])];
        return { quote_id: rndHash(), network: "bitcoin", unit: "BTC", recipient: to, amount_sats: amount, fee_sats: fee, vsize, rate: rate.toFixed(1), total_sats: amount + fee, change_sats: change,
          inputs, outputs, replaces: cmd === "btc_bump_quote" ? String(a.txid) : null, own_recipient: to === RECV, unconfirmed_inputs: false, balance_sats: inTotal, sequence: "0xfffffffd (replaceable)" } as T;
      }
      case "btc_sign_start": {
        const t = String(a.ticket); cancelled = false;
        emit(t, "connecting"); await sleep(900);
        if (outcome === "nophone") throw { kind: "no_phone", message: "no Android device on USB", delivered: false };
        emit(t, "delivered");
        await phoneWait(4000); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: true };
        if (outcome === "reject") throw { kind: "rejected", message: "rejected on the phone", delivered: true };
        if (outcome === "verify") throw { kind: "verify", message: "the phone returned a different transaction (output 1 amount (so the fee too) changed)", delivered: true };
        emit(t, "verifying"); await sleep(500);
        const txid = rndHash().slice(2);
        btcSigned = { txid, q: a, polls: 0 };
        return { txid, fee_sats: 857, vsize: 141, rate: "6.1", amount_sats: 250_000, recipient: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", explorer: `https://mempool.space/tx/${txid}`,
          checks: ["Same transaction as reviewed: 1 input, 2 outputs, recipient and amount unchanged", "Fee exactly 857 sat (inputs − outputs, amounts from this Mac's records)",
            "Every input signed by this wallet's key for that address (ECDSA, SIGHASH_ALL)", "Each input verified by Bitcoin Core's script interpreter (libbitcoinconsensus)"] } as T;
      }
      case "btc_sign_cancel": cancelled = true; wake?.(); return undefined as T;
      case "btc_broadcast": {
        await sleep(700);
        if (outcome === "broadcastfail") throw "HTTP 400: sendrawtransaction RPC error: {\"code\":-26,\"message\":\"min relay fee not met, 141 < 282\"}";
        if (!btcSigned || btcSigned.txid !== a.txid) throw "This transaction was not verified in this session, so it was not sent to the network. Start the send again.";
        btcConfirmed -= 250_857;
        btcHistory.unshift({ txid: btcSigned.txid, net_sats: -250_857, fee_sats: 857, status: "pending", confirmations: 0, time: Math.floor(Date.now() / 1000), counterparty: "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", can_bump: true, sent_here: true, explorer: `https://mempool.space/tx/${btcSigned.txid}` });
        return btcSigned.txid as T;
      }
      case "btc_tx_status": { if (btcSigned) btcSigned.polls++; return { confirmed: !!btcSigned && btcSigned.polls > 1, confirmations: 1, height: 915_002 } as T; }
      case "btc_export": return { descriptor: btcAccounts[0]?.descriptor ?? "", receive: `wpkh([73c5da0a/84h/0h/0h]${XPUB}/0/*)#4z5slzlv`, change: `wpkh([73c5da0a/84h/0h/0h]${XPUB}/1/*)#5sxa2p6a`,
        fingerprint: "73c5da0a", path: "m/84h/0h/0h", xpub: XPUB, text: "" } as T;
      case "btc_save_export": return "/Users/you/Downloads/phone-vault-Bitcoin-1-watch-only.txt" as T;
    }
    throw `preview: no mock for ${cmd}`;
  }

  return {
    invoke,
    onProgress: (cb) => { listeners.add(cb); return () => listeners.delete(cb); },
    onEvent: (name, cb) => { if (!events.has(name)) events.set(name, new Set()); events.get(name)!.add(cb); return () => events.get(name)?.delete(cb); },
  };
}
