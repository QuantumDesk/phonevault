// "Print backup card": the blank, print-ready card from tools/backup-card (bundled with the app)
// opens in Preview for printing. The user fills it in BY HAND from the phone: no recovery word,
// SeedQR or other secret ever reaches this Mac.

import { api, errText } from "./api";
import { h, icon, toast } from "./ui";

type Paper = "a4" | "letter";
type Grid = "compact" | "standard";

const LETTER_REGIONS = /-(US|CA|MX|PH|CL|CO|VE|GT|CR|PA|DO|PR|SV|NI)$/i;
const KEY = "pv.backupCard";

function load(): { paper: Paper; grid: Grid } {
  try {
    const v = JSON.parse(localStorage.getItem(KEY) ?? "null");
    if (v && (v.paper === "a4" || v.paper === "letter") && (v.grid === "compact" || v.grid === "standard")) return v;
  } catch { /* fall through */ }
  return { paper: LETTER_REGIONS.test(navigator.language) ? "letter" : "a4", grid: "compact" };
}
function save(v: { paper: Paper; grid: Grid }) { try { localStorage.setItem(KEY, JSON.stringify(v)); } catch { /* per-device convenience only */ } }

/** Paper and grid choice plus the "Print backup card" button. */
export function backupCardPicker(): HTMLElement {
  const choice = load();
  const wrap = h("div", { class: "backup-card" });
  const msg = h("p", { class: "field-msg" });
  const render = () => {
    const seg = <T extends string>(cur: T, opts: [T, string][], set: (v: T) => void) =>
      h("div", { class: "segmented two" }, opts.map(([v, label]) => h("button", { class: v === cur ? "on" : "", onclick: () => { set(v); save(choice); render(); } }, label)));
    wrap.replaceChildren(
      seg(choice.paper, [["a4", "A4"], ["letter", "US Letter"]], (v) => { choice.paper = v; }),
      seg(choice.grid, [["compact", "SeedQR 25×25 (compact)"], ["standard", "SeedQR 29×29 (standard)"]], (v) => { choice.grid = v; }),
      h("div", { class: "row gap" }, h("button", { onclick: async () => {
        msg.textContent = ""; msg.className = "field-msg";
        try { await api.openBackupCard(choice.paper, choice.grid); toast("Backup card opened. Print it, then fill it in by hand."); }
        catch (e) { msg.textContent = errText(e); msg.className = "field-msg bad"; }
      } }, icon("print", 15), "Print backup card")),
      msg,
    );
  };
  render();
  return wrap;
}

/** Settings → Backup. */
export function backupCardSection(): HTMLElement {
  return h("section", { class: "set" },
    h("h4", null, "BACKUP"),
    h("p", { class: "muted small" }, "A one-page card to write your 24 recovery words on, with an optional SeedQR grid. It prints blank: you fill it in with a pen from your phone's screen. Never photograph or type the words, keep two copies in separate places, and note that a passphrase is not on the card."),
    backupCardPicker(),
    h("p", { class: "muted small" }, "On the phone: Security → Show recovery phrase, or Show as SeedQR to copy the grid. The 25×25 grid matches the phone's default CompactSeedQR."),
  );
}
