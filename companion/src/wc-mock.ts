// PREVIEW DATA ONLY. A pretend dApp for the browser preview (no Tauri), so the WalletConnect UI can
// be designed and screenshotted. Nothing here runs inside the app; the real policy is in wc.rs.
//
// URL knobs:
//   ?wc=proposal   a session proposal is waiting on load
//   ?wc=session    one connected session
//   ?wc=requests   one session and a queue of requests (tx, personal_sign, typed data, eth_sign)
//   ?wc=noid       as if no project ID was set
//   ?wcverify=VALID|UNKNOWN|INVALID|SCAM   the Verify API result for the mock dApp
//   ?wctx=native|approve|swap              the eth_sendTransaction the mock dApp sends

import type { Backend, Events, ProposalIn, RequestIn, SessionIn, Validation } from "./wc-backend";

const params = new URLSearchParams(location.search);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const ADDRESS = "0x7A3b9C1d2E4f5061728394A5b6C7d8E9f0A1B2c3";
const UNI_ICON = "data:image/svg+xml," + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#fc72ff"/><path d="M20 44c6-2 8-9 12-16s10-10 14-8c-5 1-7 5-9 10s-5 12-17 14z" fill="#fff"/></svg>');
const ALLOWED = [1, 10, 137, 8453, 42161, 11155111];
const NAMES: Record<number, string> = { 1: "Ethereum", 10: "Optimism", 137: "Polygon", 8453: "Base", 42161: "Arbitrum One", 11155111: "Sepolia (testnet)", 56: "BNB Chain", 324: "zkSync" };
const SUPPORTED = ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "eth_chainId", "eth_accounts", "eth_requestAccounts", "wallet_switchEthereumChain"];
const hex = (n: number | bigint) => "0x" + n.toString(16);
const rand = (n: number) => "0x" + Array.from({ length: n * 2 }, () => "0123456789abcdef"[Math.floor(Math.random() * 16)]).join("");

function verify(): ProposalIn["verify"] {
  const v = (params.get("wcverify") ?? "VALID").toUpperCase();
  if (v === "SCAM") return { validation: "VALID", origin: "https://app.uniswap.org", isScam: true };
  if (v === "INVALID") return { validation: "INVALID", origin: "https://app-uniswap.help", isScam: false };
  return { validation: v as Validation, origin: "https://app.uniswap.org", isScam: false };
}

const DAPP = { name: "Uniswap Interface", description: "Swap, earn, and build on the leading decentralized crypto trading protocol.", url: "https://app.uniswap.org", icons: [UNI_ICON] };
const REQUIRED = {};
const OPTIONAL = { eip155: { chains: ["eip155:8453", "eip155:1", "eip155:10", "eip155:42161", "eip155:137", "eip155:56", "eip155:324"], methods: ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "eth_sign", "wallet_switchEthereumChain", "wallet_getCapabilities"], events: ["chainChanged", "accountsChanged"] } };

function sampleTx(): Record<string, string> {
  const kind = params.get("wctx") ?? "native";
  if (kind === "approve") return { from: ADDRESS, to: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", data: "0x095ea7b3000000000000000000000000000000000022d473030f116ddee9f6b43ac78ba3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" };
  if (kind === "swap") return { from: ADDRESS, to: "0x6fF5693b99212Da76ad316178A184AB56D299b43", value: "0x5af3107a4000", data: "0x3593564c" + "0".repeat(120) };
  return { from: ADDRESS, to: "0x51eA0B8f1a0C6f3F0c1B2E5A6d7C8b9A0e1F2d3C", value: "0x38d7ea4c68000" };
}

const PERMIT2 = JSON.stringify({
  types: {
    EIP712Domain: [{ name: "name", type: "string" }, { name: "chainId", type: "uint256" }, { name: "verifyingContract", type: "address" }],
    PermitSingle: [{ name: "details", type: "PermitDetails" }, { name: "spender", type: "address" }, { name: "sigDeadline", type: "uint256" }],
    PermitDetails: [{ name: "token", type: "address" }, { name: "amount", type: "uint160" }, { name: "expiration", type: "uint48" }, { name: "nonce", type: "uint48" }],
  },
  primaryType: "PermitSingle",
  domain: { name: "Permit2", chainId: 8453, verifyingContract: "0x000000000022D473030F116dDEE9F6B43aC78BA3" },
  message: { details: { token: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", amount: "1461501637330902918203684832716283019655932542975", expiration: "1790000000", nonce: "0" }, spender: "0x6fF5693b99212Da76ad316178A184AB56D299b43", sigDeadline: "1760000000" },
});

export function createMockBackend(ev: Events): Backend {
  let sessions: SessionIn[] = [];
  let queue: RequestIn[] = [];
  let nextId = Date.now() * 1000;
  const mode = params.get("wc");

  const makeSession = (chains: number[]): SessionIn => ({
    topic: rand(32).slice(2), meta: DAPP, expiry: Math.floor(Date.now() / 1000) + 7 * 86400,
    namespaces: { eip155: { chains: chains.map((c) => `eip155:${c}`), accounts: chains.map((c) => `eip155:${c}:${ADDRESS}`), methods: [...SUPPORTED, "eth_sign"], events: ["chainChanged", "accountsChanged"] } },
  });
  const push = (topic: string, method: string, p: unknown, chain = 8453) => {
    queue.push({ id: nextId++, topic, method, params: p, chainId: `eip155:${chain}`, verify: verify(), expiry: Math.floor(Date.now() / 1000) + 300 });
  };
  const burst = (topic: string) => {
    push(topic, "eth_chainId", []);
    push(topic, "eth_sendTransaction", [sampleTx()]);
    push(topic, "personal_sign", ["0x" + Array.from(new TextEncoder().encode("app.uniswap.org wants you to sign in with your Ethereum account:\n" + ADDRESS + "\n\nSign in to Uniswap.\n\nURI: https://app.uniswap.org\nVersion: 1\nChain ID: 8453\nNonce: 8f3a1c2b\nIssued At: 2026-09-27T10:00:00Z")).map((b) => b.toString(16).padStart(2, "0")).join(""), ADDRESS]);
    push(topic, "eth_signTypedData_v4", [ADDRESS, PERMIT2]);
    push(topic, "eth_sign", [ADDRESS, "0x" + "ab".repeat(32)]);
    ev.changed();
  };
  const proposal = (): ProposalIn => ({ id: nextId++, meta: DAPP, required: REQUIRED, optional: OPTIONAL, verify: verify(), expiry: Math.floor(Date.now() / 1000) + 300 });

  if (mode === "session" || mode === "requests") sessions.push(makeSession([8453, 1]));
  if (mode === "requests") setTimeout(() => burst(sessions[0].topic), 400);
  if (mode === "proposal") setTimeout(() => ev.proposal(proposal()), 600);

  return {
    async pair(uri) {
      await sleep(500);
      if (!uri.startsWith("wc:")) throw "not a WalletConnect link";
      setTimeout(() => ev.proposal(proposal()), 700);
    },
    async approve(_id, namespaces) {
      await sleep(400);
      const ns = namespaces as { eip155: { chains: string[] } };
      const s = makeSession(ns.eip155.chains.map((c) => Number(c.split(":")[1])));
      sessions.push(s); ev.changed();
      setTimeout(() => burst(s.topic), 2500);
    },
    async reject() { await sleep(200); },
    async respond(_t, id, result) { console.info("[preview wc] respond", id, result); queue = queue.filter((r) => r.id !== id); ev.changed(); },
    async respondError(_t, id, code, message) { console.info("[preview wc] error", id, code, message); queue = queue.filter((r) => r.id !== id); ev.changed(); },
    async update(topic, namespaces) { sessions = sessions.map((s) => s.topic === topic ? { ...s, namespaces: namespaces as SessionIn["namespaces"] } : s); ev.changed(); },
    async emitChainChanged() { /* nothing to do in the preview */ },
    async disconnect(topic) { await sleep(200); sessions = sessions.filter((s) => s.topic !== topic); queue = queue.filter((r) => r.topic !== topic); ev.changed(); },
    sessions: () => sessions,
    requests: () => queue,
    isPending: (id) => queue.some((r) => r.id === id),
    online: () => true,
    relayError: () => null,
  };
}

export const mockNoProjectId = () => params.get("wc") === "noid";

// ------------------------------------------------------------------ stand-ins for wc.rs commands
// Deliberately simple: enough to drive the UI. The real rules (and their tests) are in wc.rs.

interface RpcError { code: number; message: string }
const fail = (code: number, message: string): RpcError => ({ code, message });

export async function mockInvoke<T>(cmd: string, a: Record<string, unknown> = {}): Promise<T> {
  switch (cmd) {
    case "wc_plan_session": {
      const chains: { caip: string; id: number; name: string; supported: boolean; required: boolean }[] = [];
      const methods: string[] = [];
      for (const [ns, req] of [[a.required, true], [a.optional, false]] as const) {
        const e = (ns as Record<string, { chains?: string[]; methods?: string[] }>)?.eip155;
        for (const c of e?.chains ?? []) { const id = Number(c.split(":")[1]); if (!chains.some((x) => x.id === id)) chains.push({ caip: c, id, name: NAMES[id] ?? `Chain ${id}`, supported: ALLOWED.includes(id), required: req }); }
        for (const m of e?.methods ?? []) if (!methods.includes(m)) methods.push(m);
      }
      const refused = methods.filter((m) => !SUPPORTED.includes(m));
      return { chains, methods, refused_methods: refused, required_refused_methods: [], other_namespaces: [], blocker: null } as T;
    }
    case "wc_session_namespaces": {
      const sel = a.selected as number[];
      if (!sel.length) throw "choose at least one network";
      return { eip155: { chains: sel.map((c) => `eip155:${c}`), accounts: sel.map((c) => `eip155:${c}:${ADDRESS}`), methods: SUPPORTED, events: ["chainChanged", "accountsChanged"] } } as T;
    }
    case "wc_add_chain": {
      const ns = structuredClone(a.namespaces) as { eip155: { chains: string[]; accounts: string[] } };
      ns.eip155.chains.push(`eip155:${a.chainId}`); ns.eip155.accounts.push(`eip155:${a.chainId}:${ADDRESS}`);
      return ns as T;
    }
    case "wc_session_matches": return true as T;
    case "wc_prepare": {
      await sleep(350);
      const chain = Number(String(a.chain).split(":")[1]);
      const p = a.params as unknown[];
      switch (a.method) {
        case "eth_chainId": return { kind: "answer", result: hex(chain) } as T;
        case "eth_accounts": case "eth_requestAccounts": return { kind: "answer", result: [ADDRESS] } as T;
        case "eth_sign": throw fail(4200, "eth_sign is refused: it signs an opaque hash that nobody can review. Use personal_sign or eth_signTypedData_v4.");
        case "eth_signTransaction": throw fail(4200, "eth_signTransaction is refused: this wallet only returns transactions it broadcast itself. Use eth_sendTransaction.");
        case "wallet_switchEthereumChain": {
          const id = parseInt(String((p[0] as { chainId: string }).chainId), 16);
          if (!ALLOWED.includes(id)) throw fail(4902, `Unrecognized chain ${id}: your phone has no reviewed profile for it`);
          return { kind: "switch_chain", chain_id: id, name: NAMES[id], in_session: (a.sessionChains as string[]).includes(`eip155:${id}`) } as T;
        }
        case "personal_sign": {
          const m = String(p[0]);
          const bytes = m.startsWith("0x") ? new Uint8Array((m.slice(2).match(/../g) ?? []).map((x) => parseInt(x, 16))) : new TextEncoder().encode(m);
          let text: string | null = null;
          try { text = new TextDecoder("utf-8", { fatal: true }).decode(bytes); } catch { /* binary */ }
          return { kind: "personal_sign", chain_id: chain, message_hex: m, text, notes: text ? [] : [{ level: "danger", text: "This is not readable text. Sign only if you know exactly what it is." }] } as T;
        }
        case "eth_signTypedData_v4": {
          const td = JSON.parse(String(p[1]));
          return { kind: "typed_data", chain_id: chain, typed_data: String(p[1]),
            summary: { primary_type: td.primaryType, domain_name: td.domain.name ?? null, domain_version: td.domain.version ?? null, domain_chain: td.domain.chainId ?? null, verifying_contract: td.domain.verifyingContract ?? null },
            notes: [{ level: "danger", text: "This is a permit: it lets someone move your tokens without another transaction." }] } as T;
        }
        case "eth_sendTransaction": {
          const tx = p[0] as Record<string, string>;
          const data = tx.data ?? "0x";
          const value = BigInt(tx.value ?? "0x0");
          const eth = (w: bigint) => { const s = (Number(w) / 1e18).toFixed(8).replace(/0+$/, ""); return s.endsWith(".") ? s + "0" : s; };
          const fee = 4_200_000_000_000n * (data === "0x" ? 1n : 6n);
          const approve = data.startsWith("0x095ea7b3");
          const call = data === "0x" ? { kind: "transfer", selector: null, data_bytes: 0, party: null, amount: null, phone_supported: true }
            : approve ? { kind: "token_approve", selector: "0x095ea7b3", data_bytes: 68, party: "0x000000000022D473030F116dDEE9F6B43aC78BA3", amount: "unlimited", phone_supported: true }
            : { kind: "contract_call", selector: data.slice(0, 10), data_bytes: (data.length - 2) / 2, party: null, amount: null, phone_supported: false };
          const notes = approve ? [{ level: "danger", text: "Unlimited approval: the spender can move all of this token, now and later." }]
            : call.kind === "contract_call" ? [{ level: "danger", text: "This calls a contract. Your phone currently signs only plain transfers and token transfer/approve calls, so it will refuse this." }] : [];
          return { kind: "transaction", chain_id: chain, call, notes, quote: {
            chain_id: hex(chain), nonce: "0x4", max_priority_fee_per_gas: "0xf4240", max_fee_per_gas: "0xc3500", gas_limit: data === "0x" ? "0x5208" : "0x1d4c0",
            to: tx.to.toLowerCase(), value: hex(value), data, amount_eth: eth(value), max_fee_eth: eth(fee), total_eth: eth(value + fee), balance_eth: "0.04213377", network: NAMES[chain] ?? "Base",
          } } as T;
        }
      }
      throw fail(4200, `${a.method} is not supported by Phone Vault`);
    }
    case "sign_message": case "sign_typed_data": {
      await sleep(2600);
      const outcome = params.get("outcome") ?? "approve";
      if (outcome === "reject") throw "rejected on the phone";
      if (outcome === "nophone") throw "no Android device on USB";
      return { signature: rand(65), digest: rand(32), signer: ADDRESS } as T;
    }
  }
  throw `preview: no mock for ${cmd}`;
}
