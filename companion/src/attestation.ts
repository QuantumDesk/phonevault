// Device check (attestation) views: the header badge, the pairing card and Settings → Device.
// The verdict itself is computed in Rust (src-tauri/src/attest); this only shows it.

import type { Attestation } from "./api";
import { h, icon, short, ago } from "./ui";

export interface DeviceCheck {
  report: Attestation | null;
  checking: boolean;
  /** Transport problem (locked phone, no phone, busy): not a verdict. */
  error: string | null;
}

export function verdictLabel(a: Attestation): { label: string; cls: string } {
  return a.verdict === "genuine" ? { label: "Genuine", cls: "att-ok" }
    : a.verdict === "development" ? { label: "Development", cls: "att-dev" }
    : { label: "Not genuine", cls: "att-fail" };
}

/** Header badge; null when there is nothing to say (no phone, never checked). */
export function badge(c: DeviceCheck, onClick: () => void): HTMLElement | null {
  if (c.checking && !c.report) return h("button", { class: "att-badge att-checking", title: "Checking that the phone is genuine…", onclick: onClick }, h("i", { class: "mini-spin" }), "Checking");
  if (!c.report) return null;
  const { label, cls } = verdictLabel(c.report);
  return h("button", { class: `att-badge ${cls}`, title: `${c.report.headline}\nClick for details (Settings → Device).`, onclick: onClick }, icon("shield", 14), label);
}

function reasonList(a: Attestation): HTMLElement | null {
  const items = a.verdict === "fail" ? a.problems : a.cautions.filter((c) => c !== a.headline);
  if (!items.length) return null;
  return h("ul", { class: "att-reasons" }, items.map((p) => h("li", null, p)));
}

/** The verdict as a card: used on the pairing screen and in the send-blocked dialog. */
export function verdictCard(c: DeviceCheck, recheck: () => void): HTMLElement {
  if (!c.report) {
    return h("section", { class: "card att-card att-pending" },
      h("p", { class: "kicker" }, "DEVICE CHECK"),
      c.checking ? h("p", { class: "row gap" }, h("i", { class: "mini-spin" }), "Checking that this phone is genuine Phone Vault hardware and firmware…")
        : h("p", { class: "muted" }, c.error ? `Not checked yet: ${c.error}` : "Not checked yet."),
      !c.checking ? h("div", { class: "row gap" }, h("button", { onclick: recheck }, icon("refresh", 15), "Check now")) : null,
    );
  }
  const a = c.report;
  const { label, cls } = verdictLabel(a);
  return h("section", { class: `card att-card ${cls}` },
    h("p", { class: "kicker" }, icon("shield", 13), " DEVICE CHECK · ", label.toUpperCase()),
    h("h3", null, a.headline),
    reasonList(a),
    a.verdict === "genuine" ? h("p", { class: "muted small" }, "Google's attestation proves the keys are in the Titan M, the app is Phone Vault's, and the phone booted locked Phone Vault firmware.") : null,
    a.verdict === "development" ? h("p", { class: "muted small" }, "Fine for testing with throwaway funds. A modified OS on an unlocked phone could fake everything above the security chip.") : null,
    a.verdict === "fail" ? h("p", { class: "small" }, "Pairing and sending are blocked for this phone. Don't use it for funds; get a phone from a trusted source or reflash it yourself.") : null,
  );
}

function row(k: string, v: Node | string | null | undefined, title?: string) {
  return h("div", { class: "set-row" }, h("span", { class: "muted" }, k), h("span", { class: "att-val", title: title ?? "" }, v ?? "—"));
}

/** The phrase Settings → Device asks for before Developer mode turns on (Rust checks it too). */
export const DEV_CONFIRMATION = "I FLASHED THIS PHONE";
/** Settings → Device's Developer-mode form: open, and the last error. Survives drawer re-renders. */
const devForm = { open: false, error: null as string | null, busy: false };

/** Settings → Device. `setDevMode` asks Rust (the only place Developer mode is stored). */
export function deviceSection(c: DeviceCheck, devMode: boolean, phonePresent: boolean, recheck: () => void, setDevMode: (on: boolean, confirmation: string | null) => Promise<void>, rerender: () => void): HTMLElement {
  const a = c.report;
  const d = a?.details ?? null;
  const change = async (on: boolean, confirmation: string | null) => {
    devForm.busy = true; devForm.error = null; rerender();
    try { await setDevMode(on, confirmation); devForm.open = false; }
    catch (e) { devForm.error = typeof e === "string" ? e : String((e as { message?: unknown })?.message ?? e); }
    finally { devForm.busy = false; rerender(); }
  };
  let devControls: (Node | null)[];
  if (devMode) {
    devControls = [
      h("div", { class: "set-row" }, h("span", null, "Developer mode"), h("span", { class: "att-badge att-dev" }, "On")),
      h("p", { class: "inline-error" }, icon("alert", 15), "Developer mode is ON. Phones with an unlocked bootloader or the development-signed app are accepted as Development (never Genuine). Turn it off for real funds."),
      h("div", { class: "row gap" }, h("button", { disabled: devForm.busy, onclick: () => change(false, null) }, "Turn off Developer mode")),
    ];
  } else if (!devForm.open) {
    devControls = [
      h("div", { class: "set-row" }, h("span", null, "Developer mode"), h("span", { class: "muted" }, "Off")),
      h("p", { class: "muted small" }, "Off: only locked Phone Vault firmware with the release-signed app passes. Developer mode is only for a phone you flashed yourself."),
      h("div", { class: "row gap" }, h("button", { class: "ghost", onclick: () => { devForm.open = true; devForm.error = null; rerender(); } }, "Developer mode…")),
    ];
  } else {
    const input = h("input", { type: "text", class: "mono", autocomplete: "off", spellcheck: "false", placeholder: DEV_CONFIRMATION, "aria-label": "Confirmation phrase" }) as HTMLInputElement;
    const turnOn = h("button", { class: "danger-ghost", disabled: true, onclick: () => change(true, input.value) }, "Turn on") as HTMLButtonElement;
    input.addEventListener("input", () => { turnOn.disabled = devForm.busy || input.value.trim() !== DEV_CONFIRMATION; });
    devControls = [
      h("div", { class: "callout", style: "border-color:color-mix(in srgb, var(--danger) 45%, transparent)" },
        h("strong", null, "Only for a phone you flashed yourself"),
        h("span", null, "Developer mode accepts phones with an unlocked bootloader or the development-signed app. Anyone who had such a phone before you could have changed what it shows and signs. If someone sold you this phone already set up, don't turn this on: flash it yourself from phonevault.org."),
        h("span", null, "To turn it on, type ", h("strong", { class: "mono" }, DEV_CONFIRMATION), ":")),
      input,
      devForm.error ? h("p", { class: "inline-error" }, icon("alert", 15), devForm.error) : null,
      h("div", { class: "row gap" }, turnOn, h("button", { onclick: () => { devForm.open = false; devForm.error = null; rerender(); } }, "Cancel")),
    ];
  }
  const level = (l: string | undefined) => l === "StrongBox" ? "StrongBox (Titan M)" : l === "TrustedEnvironment" ? "TEE (not the Titan M)" : l ?? "—";
  return h("section", { class: "set", id: "device-section" },
    h("h4", null, "DEVICE"),
    a ? h("div", { class: "set-row" }, h("span", null, "Device check"), h("span", { class: `att-badge ${verdictLabel(a).cls}` }, icon("shield", 13), verdictLabel(a).label))
      : h("div", { class: "set-row" }, h("span", null, "Device check"), h("span", { class: "muted" }, c.checking ? "Checking…" : phonePresent ? "Not checked yet" : "No phone on USB")),
    a ? h("p", { class: "small" }, a.headline) : null,
    a ? reasonList(a) : null,
    c.error && !c.checking ? h("p", { class: "muted small" }, c.error) : null,
    d ? h("div", { class: "att-details" },
      row("Bootloader", d.device_locked === null ? null : d.device_locked ? "Locked" : "Unlocked"),
      row("Boot state", d.verified_boot_state),
      row("Verified boot key", d.verified_boot_key ? h("span", null, h("span", { class: "mono" }, short(d.verified_boot_key)), d.verified_boot_key_known ? " · Phone Vault" : " · not Phone Vault's") : null, d.verified_boot_key ?? ""),
      row("Android", d.os_version),
      row("OS patch level", d.os_patch_level),
      row("Vendor / boot patch", [d.vendor_patch_level, d.boot_patch_level].map((x) => x ?? "—").join(" / ")),
      row("App", d.app_package ? `${d.app_package}${d.app_version !== null ? ` (version ${d.app_version})` : ""}` : null),
      row("App signer", d.app_signer ? h("span", null, d.app_signer_kind === "release" ? "Release key · " : d.app_signer_kind === "development" ? "Development key · " : "Unknown key · ", h("span", { class: "mono" }, short(d.app_signer))) : null, d.app_signer ?? ""),
      row("Key storage", level(d.attestation_security_level)),
      row("Attestation", `v${d.attestation_version} · ${d.provisioning} · ${d.chain_length} certificates`),
      row("Root", d.root),
      row("Revocation", d.revocation),
    ) : null,
    a && a.notes.length ? h("ul", { class: "att-notes muted small" }, a.notes.map((n) => h("li", null, n))) : null,
    a ? h("p", { class: "muted small" }, `Checked ${ago(a.checked_at)}${a.address ? ` for ${short(a.address)}` : ""}. Checked again on every connection and before sending.`) : null,
    h("div", { class: "row gap" }, h("button", { onclick: recheck, disabled: c.checking || !phonePresent }, icon("refresh", 15), c.checking ? "Checking…" : "Check again")),
    ...devControls,
  );
}
