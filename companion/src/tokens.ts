// ERC-20 support in the UI: the built-in token list (the SAME file the phone ships, served by the
// Rust side), per-network token balances, and small helpers for the send form. Amounts are kept
// as exact decimal strings; nothing here rounds a token amount that is shown for review.

import { api, errText } from "./api";
import type { TokenInfo, TokenBalance, Quote } from "./api";
import { h, short } from "./ui";

let listPromise: Promise<TokenInfo[]> | null = null;
let listError: string | null = null;
/** The built-in list (loaded once). Empty if the Rust side refused it; `tokenListError()` says why. */
export function tokenList(): Promise<TokenInfo[]> {
  return (listPromise ??= api.tokenList()
    .then((l) => { cached = l; listError = null; return l; })
    .catch((e) => { listError = errText(e); listPromise = null; return [] as TokenInfo[]; }));
}
export const tokenListError = () => listError;

let cached: TokenInfo[] = [];
void tokenList();
/** Synchronous view of the list once loaded (for rendering). */
export const tokensOn = (chainId: number): TokenInfo[] => cached.filter((t) => t.chainId === chainId);
export const tokenAt = (chainId: number, address: string): TokenInfo | undefined =>
  cached.find((t) => t.chainId === chainId && t.address.toLowerCase() === address.toLowerCase());

// ------------------------------------------------------------------ balances

interface Held { at: number; balances: TokenBalance[] }
const held = new Map<number, Held>();
const heldErrors = new Map<number, string>();
export const tokenBalancesFor = (chainId: number): TokenBalance[] | null => held.get(chainId)?.balances ?? null;
export const tokenBalanceOf = (chainId: number, address: string): TokenBalance | undefined =>
  held.get(chainId)?.balances.find((b) => b.address.toLowerCase() === address.toLowerCase());

/** Another account is shown: its token balances are fetched fresh. */
export function resetTokenBalances() { held.clear(); heldErrors.clear(); }

/** balanceOf for every listed token on `chainId` through `rpcUrl`. Display only. */
export async function refreshTokenBalances(chainId: number, rpcUrl: string): Promise<void> {
  if ((await tokenList()).every((t) => t.chainId !== chainId)) return;
  try {
    const r = await api.tokenBalances(rpcUrl);
    if (r.chain_id !== chainId) throw `the node is on chain ${r.chain_id}`;
    held.set(chainId, { at: Date.now(), balances: r.balances });
    heldErrors.delete(chainId);
  } catch (e) { heldErrors.set(chainId, errText(e)); }
}

/** Exact decimal text with the whole part grouped (1,234.000001): no digit is dropped. */
export function fmtExact(amount: string): string {
  const [w, f] = amount.split(".");
  const whole = w.replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return f ? `${whole}.${f}` : whole;
}

/** Plain decimal with at most `decimals` fractional digits and a positive value. */
export function validTokenAmount(text: string, decimals: number): { ok: boolean; msg: string } {
  const t = text.trim();
  if (!t) return { ok: false, msg: "" };
  if (!/^\d*\.?\d*$/.test(t) || t === ".") return { ok: false, msg: "Use digits and one dot, like 12.5" };
  const frac = t.split(".")[1] ?? "";
  if (frac.length > decimals) return { ok: false, msg: `At most ${decimals} decimals for this token` };
  if (!/[1-9]/.test(t)) return { ok: false, msg: "" };
  return { ok: true, msg: "" };
}

/** "50 USDC" / "0.5 ETH" for a quote: token amounts exact, native as the caller formats it. */
export function quoteAmount(q: Quote, nativeText: string): string {
  return q.token ? `${fmtExact(q.token.amount)} ${q.token.symbol}` : nativeText;
}

/** The token rows under Balances for the selected network. */
/** How a listed token is valued (same table as price.rs token_basis): USD stablecoins at $1 by
 *  definition, wrapped ETH at the ETH price, wrapped BTC at the BTC price; anything else: none. */
export function usdBasis(symbol: string): "USD" | "ETH" | "BTC" | null {
  if (["USDC", "USDT", "USDT0", "DAI"].includes(symbol)) return "USD";
  if (symbol === "WETH") return "ETH";
  if (symbol === "WBTC" || symbol === "cbBTC") return "BTC";
  return null;
}
/** USD value of a token amount (display only), or null without a price. */
export function tokenUsd(symbol: string, amount: string, prices: Record<string, number | null>): number | null {
  const basis = usdBasis(symbol);
  const p = basis === "USD" ? 1 : basis ? prices[basis] ?? null : null;
  const v = Number(amount) * (p ?? NaN);
  return Number.isFinite(v) ? v : null;
}

export function tokenSection(chainId: number, networkName: string, usd?: (symbol: string, amount: string) => string | null): HTMLElement | null {
  const list = tokensOn(chainId);
  if (!list.length) return listError ? h("p", { class: "inline-error" }, `Token list unavailable: ${listError}`) : null;
  const bals = tokenBalancesFor(chainId);
  const err = heldErrors.get(chainId);
  return h("section", { class: "section" },
    h("h3", { class: "section-title" }, `Tokens on ${networkName}`),
    h("ul", { class: "list nets tokens" }, list.map((t) => {
      const b = bals?.find((x) => x.address.toLowerCase() === t.address.toLowerCase());
      const zero = b?.raw === "0";
      const amount = b?.amount != null ? `${fmtExact(b.amount)} ${t.symbol}` : b?.error || err ? "unavailable" : "…";
      return h("li", null, h("div", { class: `net-row token-row${zero ? " zero" : ""}`, title: `${t.name}\n${t.address}` },
        h("span", { class: "token-sym" }, t.symbol),
        h("span", { class: "grow muted small" }, t.name, h("span", { class: "mono tag" }, short(t.address))),
        h("span", { class: "mono num", title: b?.error ?? err ?? "" }, amount),
        usd ? h("span", { class: "usd-col" }, b?.amount != null && !zero ? usd(t.symbol, b.amount) ?? "" : "") : null,
      ));
    })),
    h("p", { class: "muted small" }, "From the token list built into the phone app. Other tokens are not shown; the phone reviews them as unknown contracts.",
      usd ? " Dollar values: USDC, USDT and DAI at $1 by definition, WETH at the ETH price, WBTC/cbBTC at the BTC price (Coinbase)." : ""),
  );
}
