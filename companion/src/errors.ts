// What a failed phone request means, in plain words. One table for the Ethereum send, the Bitcoin
// send and site transactions; the wording differs by chain only where the facts differ.
import { errText, REVIEW_LIMIT_MS } from "./api";
import type { SendError } from "./api";
import { capitalize } from "./ui";

export type Chain = "eth" | "btc";
export interface Explained { title: string; body: string; danger?: boolean; neutral?: boolean; hideDetail?: boolean }

/** A thrown value from sign_start / btc_sign_start as a typed failure. */
export function asSendError(e: unknown): SendError {
  if (e && typeof e === "object" && "kind" in e) return e as SendError;
  return { kind: "internal", message: errText(e), delivered: false };
}

/** Plain wording for common transport and phone errors (pairing, device check, phone_error). */
export function explainPlain(m: string, chain: Chain = "eth"): string {
  if (/no Android device/i.test(m)) return "No phone found on USB. Plug it in and unlock it.";
  if (/held by another program|adb/i.test(m)) return "Another program holds the phone's USB connection, usually the adb server. Run `adb kill-server` and try again.";
  if (/did not answer|not reading/i.test(m)) return "The phone didn't answer. Wake and unlock it; if that fails, unplug and reconnect the cable.";
  if (/not ready/i.test(m)) return "The phone isn't ready: unlock it and finish the backup check first.";
  if (chain === "btc" && /unknown method|not supported|schema/i.test(m)) return `The phone's app doesn't support Bitcoin yet (${m}). Update Phone Vault on the phone.`;
  if (chain === "eth" && /Only canonical transfer|calldata/i.test(m)) return "Your phone couldn't explain this contract call, so it refused it. Nothing was signed.";
  if (/not paired yet|isn.t paired with this Mac|not paired with a phone/i.test(m)) return "Pair your phone first (Settings → Phone).";
  if (isNodeTrouble(m)) return NODE_DOWN;
  return capitalize(m);
}

export const NODE_DOWN = "Your node didn't answer. Check your connection or choose another node in Settings → Network.";
/** The node couldn't be reached or answered garbage (eth.rs: "The network node is unreachable (…)", "node returned non-JSON: …"). */
export const isNodeTrouble = (m: string) => /node (is )?unreachable|node returned non-JSON|node didn.t answer|node did not answer/i.test(m);

/** A balance or node error (a node call, never a phone one), in plain words. */
export function explainNode(m: string): string {
  if (/not paired yet|isn.t paired with this Mac/i.test(m)) return "Pair your phone first (Settings → Phone).";
  return isNodeTrouble(m) || /timed out|error sending request|connection refused|dns error/i.test(m) ? NODE_DOWN : capitalize(m);
}

export function explainSendError(err: SendError, { chain }: { chain: Chain }): Explained {
  const sent = err.delivered;
  switch (err.kind) {
    case "no_phone": return { title: "Phone not found", body: "No phone on USB. Plug the vault into this Mac and unlock it, then try again. Nothing was sent." };
    case "usb_busy": return { title: "USB is in use", body: "Another program holds the phone's USB connection, usually the Android adb server. Run `adb kill-server`, then try again. Nothing was sent." };
    case "connect": return { title: "Couldn't open the USB connection", body: "Unplug the cable and plug it back in, unlock the phone, and try again. Nothing was sent." };
    case "not_delivered": return { title: "The phone didn't take the request", body: "Nothing reached the phone. Wake and unlock it; if that doesn't help, unplug and reconnect the cable. Then try again." };
    case "timeout": return sent
      ? { title: "No answer from the phone", body: `The request reached the phone, but no answer came back within ${REVIEW_LIMIT_MS / 60_000} minutes. If the phone still shows it, reject it there. Then try again.` }
      : { title: "The phone didn't respond", body: "Nothing reached the phone. Wake and unlock it, reconnect the cable, and try again." };
    case "disconnected": return { title: "The USB connection dropped", body: !sent ? "The link ended before the request reached the phone. Reconnect and try again."
      // an Ethereum transaction signs the same way again; a Bitcoin one is re-quoted, so no promise
      : chain === "eth" ? "The link ended while waiting for the phone. Nothing was sent to the network. If you approved on the phone, send it again: the phone signs the same transaction."
      : "The link ended while waiting for the phone. Nothing was sent to the network. Reconnect and try again." };
    case "cancelled": return { title: "Cancelled", neutral: true, hideDetail: true, body: sent ? "Stopped waiting on this Mac. If the phone still shows the request, tap Reject there." : "Stopped before anything reached the phone." };
    case "rejected": return { title: "Rejected on the phone", neutral: true, hideDetail: true, body: "You declined on the phone. No signature was created and nothing was sent to the network." };
    case "phone_error": return { title: "The phone refused the request", body: explainPlain(err.message, chain) };
    case "busy": return { title: "Still finishing the last request", body: "The previous request to the phone is still closing. Wait a few seconds and try again." };
    case "verify": return { title: "Signature failed verification", danger: true, body: chain === "eth"
      ? "What came back does not match what you entered, or was not signed by your paired phone. It was thrown away and will not be sent to the network. Stop and check the phone, the cable and this Mac before trying again."
      : "What came back is not exactly the transaction you reviewed, or is not signed by your paired account's keys. It was thrown away and will not be sent to the network. Stop and check the phone, the cable and this Mac before trying again." };
    case "protocol": return { title: "Unexpected reply from the phone", body: "The reply didn't follow the protocol, so it was discarded. Nothing was sent to the network. Reconnect the cable and try again." };
    case "not_paired": return { title: "Not paired", body: chain === "eth" ? "Pair this Mac with your phone first (Settings → Phone)." : "Add this Bitcoin account from your phone first." };
    case "reverts": return { title: "This transaction would fail", body: `Simulated on your node, this transaction fails (${err.message}). A failed transaction still costs its fee, so it was not sent to your phone. Edit it, or fix the cause and try again.`, hideDetail: true };
    case "attestation": return { title: "This phone failed the genuine check", danger: true, body: "The phone on USB could not prove it is genuine Phone Vault hardware and firmware holding your paired wallet, so nothing was sent to it. Open Settings → Device for the details." };
    default: return { title: "Something went wrong", body: "The request didn't complete. Nothing was sent to the network. Try again." };
  }
}
