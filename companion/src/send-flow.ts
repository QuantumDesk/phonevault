// Pieces shared by the Ethereum (main.ts) and Bitcoin (bitcoin.ts) send flows and site requests:
// the progress stepper, the waiting clock and the Cancel button. Each flow keeps its own states.
import { h, icon, clock } from "./ui";

const STEPS = ["Details", "Phone", "Send to network", "Confirmed"];

/** `at`: the current step (0-3); `done`: it is finished (confirmed); `bad`: it failed. */
export function stepper(at: number, done: boolean, bad: boolean) {
  return h("ol", { class: "stepper", "aria-label": "Progress" }, STEPS.map((label, i) => {
    const ticked = i < at || (i === at && done);
    return h("li", { class: ticked ? "done" : i === at ? (bad ? "now bad" : "now") : "" },
      h("span", { class: "bullet" }, ticked ? icon("check", 12) : String(i + 1)), h("span", { class: "lbl" }, label));
  }));
}

const clockText = (t0: number, limit: number | null) => limit ? `Waiting ${clock(Date.now() - t0)} · gives up after ${clock(limit)}` : `${clock(Date.now() - t0)} elapsed`;

/** Time since `t0`, and the limit when there is one; kept current by updateClocks(). */
export function clockLine(t0: number, limit: number | null) {
  return h("p", { class: "clock", "data-t0": t0, "data-limit": limit ?? "" }, clockText(t0, limit));
}

export function updateClocks() {
  document.querySelectorAll<HTMLElement>(".clock[data-t0]").forEach((c) => { c.textContent = clockText(Number(c.dataset.t0), c.dataset.limit ? Number(c.dataset.limit) : null); });
}

/** For a flow's setFlow(): runs updateClocks() every second while the state shows a clock. */
export function clockTicker(): (state: string) => void {
  let tick = 0;
  return (state) => {
    clearInterval(tick);
    if (state === "connecting" || state === "on_phone" || state === "submitted") tick = window.setInterval(updateClocks, 1000);
  };
}

export function cancelButton(cancelling: boolean | undefined, onCancel: () => void) {
  return h("button", { class: "big", disabled: !!cancelling, onclick: onCancel }, cancelling ? "Cancelling…" : "Cancel");
}
