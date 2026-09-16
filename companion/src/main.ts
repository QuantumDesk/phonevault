import { invoke } from "@tauri-apps/api/core";
import { openUrl } from "@tauri-apps/plugin-opener";
import { isPermissionGranted, requestPermission, sendNotification } from "@tauri-apps/plugin-notification";

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
const netSelect = $<HTMLSelectElement>("net-select");
const rpc = () => rpcInput.value.trim();

// Public nodes per network. The node is untrusted input; anything it supplies is shown here and on the phone.
const NETWORKS: Record<number, { name: string; rpc: string; explorer: string; symbol: string; l2: boolean }> = {
  1: { name: "Ethereum Mainnet", rpc: "https://ethereum-rpc.publicnode.com", explorer: "https://etherscan.io", symbol: "ETH", l2: false },
  8453: { name: "Base", rpc: "https://base-rpc.publicnode.com", explorer: "https://basescan.org", symbol: "ETH", l2: true },
  10: { name: "Optimism", rpc: "https://optimism-rpc.publicnode.com", explorer: "https://optimistic.etherscan.io", symbol: "ETH", l2: true },
  42161: { name: "Arbitrum One", rpc: "https://arbitrum-one-rpc.publicnode.com", explorer: "https://arbiscan.io", symbol: "ETH", l2: true },
  137: { name: "Polygon", rpc: "https://polygon-bor-rpc.publicnode.com", explorer: "https://polygonscan.com", symbol: "POL", l2: false },
  11155111: { name: "Sepolia", rpc: "https://ethereum-sepolia-rpc.publicnode.com", explorer: "https://sepolia.etherscan.io", symbol: "ETH", l2: false },
};
const net = () => NETWORKS[chainId] ?? NETWORKS[1];
function explorer(hash: string): string { return `${net().explorer}/tx/${hash}`; }

// Balance watcher → macOS notification when funds arrive.
let lastBalanceWei: bigint | null = null;
async function notify(body: string) {
  try {
    let ok = await isPermissionGranted();
    if (!ok) ok = (await requestPermission()) === "granted";
    if (ok) sendNotification({ title: "Phone Vault", body });
  } catch { /* notifications are a convenience only */ }
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
    const switched = w.chain_id !== chainId;
    chainId = w.chain_id;
    if (switched) lastBalanceWei = null; // a different network has a different balance history
    $("wallet-address").textContent = w.address;
    $("wallet-balance").textContent = `${w.balance_eth} ${net().symbol}`;
    $("wallet-network").textContent = net().name;
    $("wallet-block").textContent = String(w.block);
    const now = BigInt(w.balance_wei);
    if (lastBalanceWei !== null && now > lastBalanceWei) {
      const delta = now - lastBalanceWei;
      const whole = delta / 1000000000000000000n; const frac = (delta % 1000000000000000000n).toString().padStart(18, "0").replace(/0+$/, "");
      await notify(`Received ${whole}${frac ? "." + frac.slice(0, 8) : ""} ${net().symbol} on ${net().name}. Balance ${w.balance_eth} ${net().symbol}.`);
    }
    lastBalanceWei = now;
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
    $("q-amount").textContent = `${quote.amount_eth} ${net().symbol}`;
    $("q-to").textContent = quote.to;
    $("q-network").textContent = quote.network;
    $("q-fee").textContent = `up to ${quote.max_fee_eth} ${net().symbol}`;
    $("q-total").textContent = `${quote.total_eth} ${net().symbol} (balance ${quote.balance_eth} ${net().symbol})`;
    $("q-nonce").textContent = String(parseInt(quote.nonce, 16));
    show("q-l2note", net().l2);
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
  netSelect.addEventListener("change", async () => { const n = NETWORKS[Number(netSelect.value)]; if (n) { rpcInput.value = n.rpc; await refreshWallet(); } });
  await refreshStatus();
  // watch the balance every 15 s while paired
  setInterval(async () => { if (status?.paired) { try { await refreshWallet(); } catch { /* shown by refreshWallet */ } } }, 15000);
  setInterval(async () => { try { const s = await invoke<Status>("device_status"); const pill = $("phone-pill"); pill.textContent = s.phone === "accessory" ? "phone connected (accessory mode)" : s.phone === "android" ? "phone on USB" : "no phone on USB"; pill.className = `pill ${s.phone}`; } catch { /* ignore */ } }, 4000);
})();
