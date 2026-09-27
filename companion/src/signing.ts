// Message signing (personal_sign / eth_signTypedData_v4). Self-contained: builds its own card so
// main.ts only needs to call mountSigning(). The phone shows the review; this Mac only returns a
// signature after recomputing the digest itself and recovering the pinned signer from it.
import { invoke } from "@tauri-apps/api/core";

interface SignedMessage { signature: string; digest: string; signer: string }

const NETWORKS: [number, string][] = [
  [1, "Ethereum Mainnet"], [8453, "Base"], [10, "Optimism"], [42161, "Arbitrum One"], [137, "Polygon"], [11155111, "Sepolia (testnet)"],
];

function el<K extends keyof HTMLElementTagNameMap>(tag: K, props: Partial<HTMLElementTagNameMap[K]> = {}, ...children: (Node | string)[]): HTMLElementTagNameMap[K] {
  const node = Object.assign(document.createElement(tag), props);
  node.append(...children);
  return node;
}

function area(placeholder: string, rows: number): HTMLTextAreaElement {
  const t = el("textarea", { placeholder, rows, spellcheck: false });
  Object.assign(t.style, { width: "100%", boxSizing: "border-box", padding: "10px 12px", borderRadius: "10px", border: "1px solid var(--line)", background: "var(--ink)", color: "var(--paper)", fontFamily: "ui-monospace, monospace", fontSize: "13px" });
  return t;
}

export function mountSigning(parent: HTMLElement = document.querySelector("main") ?? document.body): void {
  const chain = el("select");
  for (const [id, name] of NETWORKS) chain.append(el("option", { value: String(id), textContent: name }));
  const message = area("Text to sign, or 0x-prefixed hex bytes", 4);
  const isHex = el("input", { type: "checkbox" });
  const hexLabel = el("label", {}, isHex, "The message is hex bytes");
  hexLabel.style.cssText = "display:flex;gap:8px;align-items:center";
  const typed = area('eth_signTypedData_v4 JSON: {"types":…,"primaryType":…,"domain":…,"message":…}', 8);
  const signMsg = el("button", { className: "primary", textContent: "Sign message on phone" });
  const signTyped = el("button", { className: "primary", textContent: "Sign typed data on phone" });
  const wait = el("div", { className: "wait", hidden: true }, el("div", { className: "spinner" }),
    el("p", { textContent: "Waiting for the phone: unlock it, read the review, approve or reject. (up to 5 minutes)" }));
  const out = el("div", { className: "quote", hidden: true });
  const error = el("p", { className: "error", hidden: true });

  const card = el("section", { className: "card", id: "message-card" },
    el("p", { className: "kicker", textContent: "SIGN A MESSAGE" }),
    el("h2", { textContent: "Message or typed data" }),
    el("p", { className: "muted small", textContent: "The phone shows who is asking and what the signature allows. Anyone who receives a signature can use it; sign only what you started yourself." }),
    el("label", {}, "Network your app is on", chain),
    el("label", {}, "Message (personal_sign)", message),
    hexLabel,
    el("div", { className: "row" }, signMsg),
    el("label", {}, "Typed data (eth_signTypedData_v4)", typed),
    el("div", { className: "row" }, signTyped),
    wait, out, error);
  const anchor = parent.querySelector("#error");
  if (anchor) parent.insertBefore(card, anchor); else parent.append(card);

  async function run(command: string, args: Record<string, unknown>) {
    error.hidden = true; out.hidden = true; wait.hidden = false;
    signMsg.disabled = signTyped.disabled = true;
    try {
      const r = await invoke<SignedMessage>(command, { ...args, chainId: Number(chain.value) });
      out.replaceChildren(
        el("p", { className: "ok", textContent: "Signed and verified on this Mac: digest recomputed from your input, signer is the paired phone." }),
        el("table", {},
          el("tr", {}, el("td", { textContent: "Signature" }), el("td", {}, el("code", { className: "addr", textContent: r.signature }))),
          el("tr", {}, el("td", { textContent: "Digest" }), el("td", {}, el("code", { className: "addr", textContent: r.digest }))),
          el("tr", {}, el("td", { textContent: "Signer" }), el("td", {}, el("code", { className: "addr", textContent: r.signer })))));
      out.hidden = false;
    } catch (e) {
      error.textContent = String(e); error.hidden = false;
    } finally {
      wait.hidden = true; signMsg.disabled = signTyped.disabled = false;
    }
  }
  signMsg.addEventListener("click", () => run("sign_message", { message: message.value, isHex: isHex.checked }));
  signTyped.addEventListener("click", () => run("sign_typed_data", { typedData: typed.value.trim() }));
}
