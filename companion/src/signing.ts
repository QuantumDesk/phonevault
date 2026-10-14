// Message signing (personal_sign / eth_signTypedData_v4). Self-contained: builds its own card so
// main.ts only needs to call mountSigning(). The phone shows the review; this Mac only returns a
// signature after recomputing the digest itself and recovering the pinned signer from it.
import { call, errText, REVIEW_LIMIT_MS } from "./api";
import { NETWORKS } from "./networks";
import { h, icon, capitalize, fact } from "./ui";

interface SignedMessage { signature: string; digest: string; signer: string }

/** The network a message is signed for unless the user picks another. */
const DEFAULT_SIGNING_CHAIN = 1;

export function mountSigning(parent: HTMLElement = document.querySelector("main") ?? document.body): void {
  const chain = h("select", { class: "net-select", "aria-label": "Network your app is on" },
    NETWORKS.map((n) => h("option", { value: n.id, selected: n.id === DEFAULT_SIGNING_CHAIN }, n.testnet ? `${n.name} (testnet)` : n.name)));
  const chainName = h("span", null, chain.selectedOptions[0]?.textContent ?? "");
  chain.addEventListener("change", () => { chainName.textContent = chain.selectedOptions[0]?.textContent ?? ""; });
  const message = h("textarea", { rows: 4, spellcheck: "false", placeholder: "Text to sign, or 0x-prefixed hex bytes" });
  const isHex = h("input", { type: "checkbox" });
  const typed = h("textarea", { rows: 8, spellcheck: "false", placeholder: 'eth_signTypedData_v4 JSON: {"types":…,"primaryType":…,"domain":…,"message":…}' });
  const signMsg = h("button", { class: "big primary" }, "Sign message on phone");
  const signTyped = h("button", { class: "big primary" }, "Sign typed data on phone");
  const wait = h("p", { class: "wait-line", hidden: true }, h("i", { class: "mini-spin" }),
    `Waiting for the phone: unlock it, read the review, approve or reject. (up to ${REVIEW_LIMIT_MS / 60_000} minutes)`);
  const out = h("div", { hidden: true });
  const error = h("p", { class: "inline-error", hidden: true });

  const card = h("section", { class: "card form", id: "message-card" },
    h("p", { class: "kicker" }, "Sign a message"),
    h("h3", null, "Message or typed data"),
    h("p", { class: "muted small" }, "The phone shows who is asking and what the signature allows. Anyone who receives a signature can use it; sign only what you started yourself."),
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Network your app is on"),
      h("span", { class: "net-chip asset-chip" }, chainName, icon("chevron", 14), chain)),
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Message (personal_sign)"), message),
    h("label", { class: "toggle" }, h("span", null, "The message is hex bytes"), isHex, h("i", { class: "knob" })),
    h("div", { class: "actions" }, signMsg),
    h("label", { class: "field" }, h("span", { class: "field-label" }, "Typed data (eth_signTypedData_v4)"), typed),
    h("div", { class: "actions" }, signTyped),
    wait, out, error);
  const anchor = parent.querySelector("#error");
  if (anchor) parent.insertBefore(card, anchor); else parent.append(card);

  async function run(command: string, args: Record<string, unknown>) {
    error.hidden = true; out.hidden = true; wait.hidden = false;
    signMsg.disabled = signTyped.disabled = true;
    try {
      const r = await call<SignedMessage>(command, { ...args, chainId: Number(chain.value) });
      out.replaceChildren(
        h("p", { class: "field-msg ok" }, icon("check", 13), "Signed and verified on this Mac: digest recomputed from your input, signer is the paired phone."),
        h("dl", { class: "facts" },
          fact("Signature", h("span", { class: "mono break" }, r.signature)),
          fact("Digest", h("span", { class: "mono break" }, r.digest)),
          fact("Signer", h("span", { class: "mono break" }, r.signer))));
      out.hidden = false;
    } catch (e) {
      error.replaceChildren(icon("alert", 15), capitalize(errText(e))); error.hidden = false;
    } finally {
      wait.hidden = true; signMsg.disabled = signTyped.disabled = false;
    }
  }
  signMsg.addEventListener("click", () => run("sign_message", { message: message.value, isHex: isHex.checked }));
  signTyped.addEventListener("click", () => run("sign_typed_data", { typedData: typed.value.trim() }));
}
