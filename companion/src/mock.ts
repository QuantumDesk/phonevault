// PREVIEW DATA ONLY. Loaded when the page runs in a plain browser (no Tauri runtime) so the UI
// can be designed and screenshotted without a phone. Nothing here is ever used by the app.
//
// URL knobs: ?paired=0  ?phone=none|android|accessory  ?outcome=approve|reject|timeout|verify|nophone|broadcastfail

import type { HistoryEntry, Stage } from "./api";

const params = new URLSearchParams(location.search);
const ADDRESS = "0x7A3b9C1d2E4f5061728394A5b6C7d8E9f0A1B2c3";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const BAL: Record<number, string> = { 8453: "0.04213377", 1: "0.1284", 10: "0.0", 42161: "0.0031", 137: "12.5", 11155111: "1.9" };
const RPC_CHAIN: Record<string, number> = {
  "https://mainnet.base.org": 8453, "https://ethereum-rpc.publicnode.com": 1, "https://optimism-rpc.publicnode.com": 10,
  "https://arbitrum-one-rpc.publicnode.com": 42161, "https://polygon-bor-rpc.publicnode.com": 137, "https://ethereum-sepolia-rpc.publicnode.com": 11155111,
};
const toWei = (eth: string) => { const [w, f = ""] = eth.split("."); return (BigInt(w || "0") * 10n ** 18n + BigInt((f + "0".repeat(18)).slice(0, 18))).toString(); };

export interface Mock {
  invoke<T>(cmd: string, args?: Record<string, unknown>): Promise<T>;
  onProgress(cb: (ticket: string, stage: Stage) => void): () => void;
}

export function createMock(): Mock {
  let paired: string | null = params.get("paired") === "0" ? null : ADDRESS.toLowerCase();
  const phone = params.get("phone") ?? "accessory";
  const outcome = params.get("outcome") ?? "approve";
  let cancelled = false;
  const listeners = new Set<(t: string, s: Stage) => void>();
  const emit = (t: string, s: Stage) => listeners.forEach((l) => l(t, s));
  const now = Math.floor(Date.now() / 1000);
  let history: HistoryEntry[] = [
    { kind: "out", hash: "0x5f1c9a7e3b2d4c6f8a0e1b3d5c7f9a2e4b6d8f0a1c3e5b7d9f2a4c6e8b0d1f3a", chain_id: 8453, counterparty: "0x51eA0B8f1a0C6f3F0c1B2E5A6d7C8b9A0e1F2d3C", amount_eth: "0.005", fee_max_eth: "0.00000412", nonce: 3, time: now - 3600 * 5, status: "confirmed", block: 20511233 },
    { kind: "in", hash: null, chain_id: 8453, counterparty: null, amount_eth: "0.025", fee_max_eth: null, nonce: null, time: now - 86400 * 2, status: "received", block: null },
    { kind: "out", hash: "0x9e8d7c6b5a4f3e2d1c0b9a8f7e6d5c4b3a2f1e0d9c8b7a6f5e4d3c2b1a0f9e8d", chain_id: 1, counterparty: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", amount_eth: "0.01", fee_max_eth: "0.00042", nonce: 11, time: now - 86400 * 9, status: "failed", block: 20111000 },
  ];
  let pending: { hash: string; to: string; amount: string; chain: number; polls: number } | null = null;

  async function invoke<T>(cmd: string, a: Record<string, unknown> = {}): Promise<T> {
    const chainOf = (url: unknown) => RPC_CHAIN[String(url)] ?? 8453;
    switch (cmd) {
      case "device_status": return { phone, paired, paired_checksum: paired ? ADDRESS : null, pairing_path: "~/Library/Application Support/PhoneVault/paired-signer.json" } as T;
      case "read_address": await sleep(1200); if (phone === "none") throw "no Android device on USB"; return ADDRESS as T;
      case "confirm_pairing": paired = ADDRESS.toLowerCase(); return "" as T;
      case "forget_pairing": paired = null; return undefined as T;
      case "wallet": {
        await sleep(300 + Math.random() * 500);
        if (!paired) throw "not paired yet";
        const c = chainOf(a.rpcUrl); const eth = BAL[c] ?? "0";
        return { address: ADDRESS, balance_wei: toWei(eth), balance_eth: eth, chain_id: c, block: 20511298 } as T;
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
        emit(t, "connecting"); await sleep(900);
        if (outcome === "nophone") throw { kind: "no_phone", message: "no Android device on USB", delivered: false };
        emit(t, "delivered");
        for (let i = 0; i < 40; i++) { await sleep(100); if (cancelled) throw { kind: "cancelled", message: "cancelled on this Mac", delivered: true }; }
        if (outcome === "reject") throw { kind: "rejected", message: "rejected on the phone", delivered: true };
        if (outcome === "timeout") throw { kind: "timeout", message: "the phone did not answer within 300 s", delivered: true };
        if (outcome === "verify") throw { kind: "verify", message: "signed transaction differs from the request in: value", delivered: true };
        emit(t, "verifying"); await sleep(400);
        const hash = "0x" + Array.from({ length: 64 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");
        pending = { hash, to: q.to, amount: q.amount_eth, chain: parseInt(q.chain_id, 16), polls: 0 };
        return { hash, signer: ADDRESS } as T;
      }
      case "sign_cancel": cancelled = true; return undefined as T;
      case "broadcast_verified": {
        await sleep(800);
        if (outcome === "broadcastfail") throw "node error for eth_sendRawTransaction: replacement transaction underpriced";
        if (!pending || pending.hash !== a.hash) throw "this transaction was not verified in this session, so it will not be broadcast";
        history = [{ kind: "out", hash: pending.hash, chain_id: pending.chain, counterparty: pending.to, amount_eth: pending.amount, fee_max_eth: "0.0000042", nonce: 4, time: Math.floor(Date.now() / 1000), status: "pending", block: null }, ...history];
        return pending.hash as T;
      }
      case "receipt": {
        await sleep(200);
        if (pending && pending.hash === a.hash && ++pending.polls < 2) return { mined: false, success: false, block: 0 } as T;
        return { mined: true, success: true, block: 20511299 } as T;
      }
      case "history_list": return history as T;
      case "history_mark": history = history.map((h) => h.hash === a.hash ? { ...h, status: a.status as HistoryEntry["status"], block: a.block as number } : h); return history as T;
      case "history_add_incoming": return history as T;
      case "spot_usd": await sleep(200); return (a.symbol === "POL" ? 0.21 : 2451.37) as T;
    }
    throw `preview: no mock for ${cmd}`;
  }

  return { invoke, onProgress: (cb) => { listeners.add(cb); return () => listeners.delete(cb); } };
}
