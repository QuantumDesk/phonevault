// NFTs (ERC-721) held by this wallet, found from Transfer logs on the user's own node within a
// recent block window and confirmed with ownerOf (src-tauri/src/nft.rs). Images are not loaded
// until asked for, and then only through the Rust side (size-capped, returned as data: URLs).

import { api, errText, openExternal } from "./api";
import type { Nft } from "./api";
import { byId } from "./networks";
import { h, icon, short, blockRange } from "./ui";

interface ChainView { nfts: Nft[]; scanned: boolean; scanning: boolean; error: string | null; window: string | null }
const views = new Map<number, ChainView>();
const meta = new Map<string, { loading: boolean; image: string | null; name: string | null; error: string | null }>();
const key = (n: Nft) => `${n.chain_id}:${n.contract.toLowerCase()}:${n.token_id}`;

/** Another account is shown: its NFTs are loaded fresh (each account has its own store). */
export function resetNfts() { views.clear(); }

export interface NftHost { chainId: () => number; rpcFor: (id: number) => string; rerender: () => void }

function viewFor(chainId: number, host: NftHost): ChainView {
  let v = views.get(chainId);
  if (!v) {
    v = { nfts: [], scanned: false, scanning: false, error: null, window: null };
    views.set(chainId, v);
    // stored results first, then one scan per session per network
    api.nftList(chainId).then((l) => { v!.nfts = l; host.rerender(); }).catch(() => {}).finally(() => { void scan(chainId, host); });
  }
  return v;
}

async function scan(chainId: number, host: NftHost) {
  const v = views.get(chainId)!;
  if (v.scanning) return;
  v.scanning = true; v.error = null; host.rerender();
  try {
    const r = await api.nftScan(host.rpcFor(chainId));
    if (r.chain_id !== chainId) throw `the node is on chain ${r.chain_id}`;
    v.nfts = r.nfts; v.error = r.error;
    v.window = r.from_block !== null && r.to_block !== null ? blockRange(r.from_block, r.to_block) : null;
  } catch (e) { v.error = errText(e); }
  v.scanning = false; v.scanned = true; host.rerender();
}

async function addContract(chainId: number, contract: string, host: NftHost, msg: HTMLElement) {
  const v = views.get(chainId)!;
  msg.textContent = "Looking up this collection…"; msg.className = "field-msg";
  try {
    const r = await api.nftAddContract(host.rpcFor(chainId), contract);
    v.nfts = r.nfts;
    msg.textContent = r.error ?? "Added."; msg.className = `field-msg ${r.error ? "warn" : "ok"}`;
    host.rerender();
  } catch (e) { msg.textContent = errText(e); msg.className = "field-msg bad"; }
}

async function loadImage(n: Nft, host: NftHost) {
  const k = key(n);
  meta.set(k, { loading: true, image: null, name: null, error: null }); host.rerender();
  try {
    const m = await api.nftMetadata(host.rpcFor(n.chain_id), n.contract, n.token_id);
    meta.set(k, { loading: false, image: m.image, name: m.name, error: m.image ? null : m.error ?? "no image" });
  } catch (e) { meta.set(k, { loading: false, image: null, name: null, error: errText(e) }); }
  host.rerender();
}

function card(n: Nft, host: NftHost) {
  const m = meta.get(key(n));
  const net = byId(n.chain_id);
  const art = h("div", { class: "nft-art" },
    m?.image ? h("img", { src: m.image, alt: m.name ?? `${n.name ?? "Token"} #${n.token_id}` })
      : m?.loading ? h("i", { class: "spinner" })
      : h("div", { class: "stack" },
        h("span", null, (n.symbol ?? "NFT").slice(0, 10)),
        h("button", { class: "chip-btn", onclick: () => loadImage(n, host), title: "Fetch this token's metadata and image (through this app, size-limited). The server hosting it sees the request." }, "Load image"),
        m?.error ? h("span", { class: "muted small", title: m.error }, "No image") : null));
  return h("div", { class: `nft${n.owned === false ? " gone" : ""}` }, art,
    h("span", { class: "nft-name", title: m?.name ?? n.name ?? "" }, m?.name ?? `${n.name ?? "Unnamed collection"} #${n.token_id.length > 10 ? n.token_id.slice(0, 8) + "…" : n.token_id}`),
    h("button", { class: "link nft-sub", title: `${n.contract}\nOpen in explorer`, onclick: () => openExternal(`${net.explorer}/token/${n.contract}?a=${n.token_id}`) }, short(n.contract), icon("external", 12)),
  );
}

export function nftSection(host: NftHost): HTMLElement {
  const chainId = host.chainId();
  const net = byId(chainId);
  const v = viewFor(chainId, host);
  const input = h("input", { type: "text", placeholder: "Collection contract 0x…", spellcheck: "false", autocomplete: "off" });
  const msg = h("p", { class: "field-msg" });
  const add = h("form", { class: "add-row" }, input, h("button", { type: "submit" }, "Add"));
  add.addEventListener("submit", (e) => { e.preventDefault(); if (input.value.trim()) void addContract(chainId, input.value.trim(), host, msg); });
  const held = v.nfts.filter((n) => n.owned !== false);
  return h("section", { class: "section" },
    h("div", { class: "row between" },
      h("h3", { class: "section-title" }, `NFTs on ${net.name}`),
      h("button", { class: "chip-btn", disabled: v.scanning, onclick: () => scan(chainId, host) }, v.scanning ? [h("i", { class: "mini-spin" }), "Searching…"] : [icon("refresh", 13), "Search again"]),
    ),
    held.length ? h("div", { class: "nft-grid" }, held.map((n) => card(n, host)))
      : h("p", { class: "empty" }, v.scanning ? "Searching your node for ERC-721 transfers to this address…" : v.scanned ? "No NFTs found in the recent block window on this network." : "…"),
    v.error ? h("p", { class: "muted small scan-note" }, icon("alert", 14), h("span", null, v.error.charAt(0).toUpperCase() + v.error.slice(1) + ".")) : null,
    h("p", { class: "muted small" }, `Found from ERC-721 transfers to this address${v.window ? ` in ${v.window}` : " in a recent block window"} on your ${net.name} node, then checked with ownerOf. Older NFTs, ERC-1155 items and NFTs from contracts that don't emit standard events may be missing: add a collection by its contract.`),
    h("div", { class: "field" }, add, msg),
  );
}
