import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";

type Presence = "none" | "android" | "accessory";
interface Status { phone: Presence; paired: string | null; paired_checksum: string | null; pairing_path: string }
interface Wallet { address: string; balance_wei: string; balance_eth: string; chain_id: number; block: number }
interface Quote {
  chain_id: string; nonce: string; max_priority_fee_per_gas: string; max_fee_per_gas: string; gas_limit: string;
  to: string; value: string; data: string; amount_eth: string; max_fee_eth: string; total_eth: string; balance_eth: string; network: string;
}
interface SignedTx { raw: string; hash: string; signer: string }
interface Receipt { mined: boolean; success: boolean; block: number }

const $ = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const show = (id: string, on = true) => { $(id).hidden = !on; };
const errorBox = $("error");
function fail(message: unknown) { errorBox.textContent = String(message); errorBox.hidden = false; }
function clearError() { errorBox.hidden = true; errorBox.textContent = ""; }

let status: Status | null = null;
let quote: Quote | null = null;
let signed: SignedTx | null = null;
let chainId = 1;

const rpcInput = $<HTMLInputElement>("rpc-url");
const rpc = () => rpcInput.value.trim();

function explorer(hash: string): string {
  const base: Record<number, string> = { 1: "https://etherscan.io", 11155111: "https://sepolia.etherscan.io", 8453: "https://basescan.org", 10: "https://optimistic.etherscan.io", 42161: "https://arbiscan.io", 137: "https://polygonscan.com" };
  return `${base[chainId] ?? "https://etherscan.io"}/tx/${hash}`;
}

async function refreshStatus() {
  try {
    status = await invoke<Status>("device_status");
    const pill = $("phone-pill");
    pill.textContent = status.phone === "accessory" ? "phone connected (accessory mode)" : status.phone === "android" ? "phone on USB" : "no phone on USB";
    pill.className = `pill ${status.phone}`;
    const paired = !!status.paired;
    $("pair-title").textContent = paired ? "Paired" : "Pair this Mac with your phone";
    $("pair-text").textContent = paired
      ? `Pinned signer ${status.paired_checksum}. Every signature is checked against it before broadcast. (${status.pairing_path})`
      : "Unlock the phone, plug it in, then read its address. You will compare it with the phone's own screen before it is pinned.";
    $<HTMLButtonElement>("btn-read").textContent = paired ? "Re-read address from phone" : "Read address from phone";
    show("btn-forget", paired);
    show("wallet-card", paired);
    show("send-card", paired);
    if (paired) await refreshWallet();
  } catch (e) { fail(e); }
}

async function refreshWallet() {
  try {
    const w = await invoke<Wallet>("wallet", { rpcUrl: rpc() });
    chainId = w.chain_id;
    $("wallet-address").textContent = w.address;
    $("wallet-balance").textContent = `${w.balance_eth} ETH`;
    $("wallet-network").textContent = ({ 1: "Ethereum Mainnet", 11155111: "Sepolia", 8453: "Base", 10: "Optimism", 42161: "Arbitrum One", 137: "Polygon" } as Record<number, string>)[w.chain_id] ?? `chain ${w.chain_id}`;
    $("wallet-block").textContent = String(w.block);
    clearError();
  } catch (e) { fail(e); }
}

$("btn-read").addEventListener("click", async () => {
  clearError();
  const btn = $<HTMLButtonElement>("btn-read"); btn.disabled = true; btn.textContent = "Asking the phone…";
  try {
    const address = await invoke<string>("read_address");
    $("pair-address").textContent = address;
    show("pair-compare");
  } catch (e) { fail(e); }
  finally { btn.disabled = false; btn.textContent = status?.paired ? "Re-read address from phone" : "Read address from phone"; }
});
$("btn-confirm").addEventListener("click", async () => {
  try { await invoke("confirm_pairing", { address: $("pair-address").textContent }); show("pair-compare", false); await refreshStatus(); } catch (e) { fail(e); }
});
$("btn-reject").addEventListener("click", () => { show("pair-compare", false); fail("Not pinned. If the phone's screen shows a different address, stop: something between this Mac and the phone is lying."); });
$("btn-forget").addEventListener("click", async () => { try { await invoke("forget_pairing"); await refreshStatus(); } catch (e) { fail(e); } });
$("btn-refresh").addEventListener("click", refreshWallet);

$("btn-quote").addEventListener("click", async () => {
  clearError();
  try {
    quote = await invoke<Quote>("quote", { rpcUrl: rpc(), to: $<HTMLInputElement>("send-to").value, amountEth: $<HTMLInputElement>("send-amount").value });
    $("q-amount").textContent = `${quote.amount_eth} ETH`;
    $("q-to").textContent = quote.to;
    $("q-network").textContent = quote.network;
    $("q-fee").textContent = `up to ${quote.max_fee_eth} ETH`;
    $("q-total").textContent = `${quote.total_eth} ETH (balance ${quote.balance_eth} ETH)`;
    $("q-nonce").textContent = String(parseInt(quote.nonce, 16));
    show("quote-box"); show("signed-box", false); show("result-box", false);
  } catch (e) { fail(e); }
});
$("btn-requote").addEventListener("click", () => { show("quote-box", false); quote = null; });

$("btn-sign").addEventListener("click", async () => {
  if (!quote) return;
  clearError(); show("quote-box", false); show("wait-box");
  try {
    signed = await invoke<SignedTx>("sign", { q: quote });
    $("s-hash").textContent = signed.hash;
    $("s-signer").textContent = signed.signer;
    show("signed-box");
  } catch (e) { fail(e); show("quote-box"); }
  finally { show("wait-box", false); }
});
$("btn-discard").addEventListener("click", () => { signed = null; show("signed-box", false); show("quote-box"); });

$("btn-broadcast").addEventListener("click", async () => {
  if (!signed) return;
  clearError();
  const btn = $<HTMLButtonElement>("btn-broadcast"); btn.disabled = true;
  try {
    const hash = await invoke<string>("broadcast", { rpcUrl: rpc(), raw: signed.raw, expectedHash: signed.hash });
    show("signed-box", false); show("result-box");
    $("result-text").textContent = `Broadcast. Waiting for it to be mined… ${hash}`;
    const link = $<HTMLAnchorElement>("result-link"); link.href = explorer(hash);
    link.onclick = (ev) => { ev.preventDefault(); openUrl(explorer(hash)); };
    for (let i = 0; i < 60; i++) {
      await new Promise((r) => setTimeout(r, 6000));
      const rc = await invoke<Receipt>("receipt", { rpcUrl: rpc(), hash });
      if (rc.mined) { $("result-text").textContent = rc.success ? `Mined in block ${rc.block}. ${hash}` : `Mined but REVERTED in block ${rc.block}. ${hash}`; await refreshWallet(); break; }
    }
  } catch (e) { fail(e); show("signed-box"); }
  finally { btn.disabled = false; }
});
$("btn-again").addEventListener("click", () => { signed = null; quote = null; show("result-box", false); $<HTMLInputElement>("send-amount").value = ""; });

(async () => {
  rpcInput.value = await invoke<string>("default_rpc");
  rpcInput.addEventListener("change", refreshWallet);
  await refreshStatus();
  setInterval(async () => { try { const s = await invoke<Status>("device_status"); const pill = $("phone-pill"); pill.textContent = s.phone === "accessory" ? "phone connected (accessory mode)" : s.phone === "android" ? "phone on USB" : "no phone on USB"; pill.className = `pill ${s.phone}`; } catch { /* ignore */ } }, 4000);
})();
