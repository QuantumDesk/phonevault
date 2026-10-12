# Development-device scripts (0.3.x UI)

Scripts that drive the **development** Pixel 3 XL (crosshatch) over ADB from the native
build box. They exist so the physical checks the audits could not repeat are reproducible.
They assume the dev-appliance build (`assembleAppliance`: debug-signed, `DevTools` UI dumps
and screenshots enabled) and a phone provisioned as described in `NOTES.md`; they are
useless — by design — against a release build, which has no dump hook and refuses `adb install`.

Every tap is located by the widget's **text and live bounds** (`uiautomator dump`). There is
no coordinate table any more; `uiautomator` only lists visible nodes, so `tap_text` scrolls
once when a button is below the fold.

| Script | What it does |
|---|---|
| `buildapp.sh` | `gradle :app:assembleAppliance` with the pinned JDK/SDK paths of the build box |
| `deploy.sh` | build → `adb install -r` → re-assert device owner + kiosk → launch → pull the first UI dump |
| `firstrun.sh` | SET PIN → Create-or-Restore → Create → fresh-PIN reveal → 24 words (saved to `PV_WORDS_FILE`, 0600) → 3-word spot check → confirm account → Home |
| `backupcheck.sh` | fresh PIN → 3 random positions answered from `PV_WORDS_FILE` → confirm; checks the account binding |
| `seedqrtest.sh` | SeedQR + reminder (not yet run on a phone): Security → Show as SeedQR behind the PIN shows the 25 × 25 CompactSeedQR with the seed timer and no menu, switches to the 29 × 29 Standard SeedQR and to the words and back, Hide returns Home; `PV_USB_CHECK=1` plugs a host in while it is shown and requires the attach to stay parked; Security → Backup reminder saves each interval and restores "Every 3 months" |
| `restoretest.sh firstrun\|replace ADDR` | types the 24 words on the phone's own keyboard; requires the derived address shown **before** saving to equal `ADDR`; confirms; checks Home. `replace` goes through Security → Restore a different wallet (fresh PIN, replacement state machine) |
| `usbsigntest.sh` | AOA pair (USB address == screen), mainnet-shaped 0.5 ETH example transfer reviewed and approved on the phone, host recomputes hash + recovers signer against the pinned pairing |
| `msgsigntest.sh` | Message signing (needs the pairing from `usbsigntest.sh`): personal_sign text approved, sign-in for another account and unreadable bytes rejected, EIP-712 Mail and Permit2 (UNLIMITED) approved, Permit2 on the wrong host chain rejected; host checks each digest and recovers the signer |
| `tokensigntest.sh` | ERC-20 review (needs the pairing from `usbsigntest.sh`; not yet run on a phone): USDC transfer shown as "Send 50 USDC" and approved, UNLIMITED approval and unknown-contract transfer rejected, Base USDC increaseAllowance approved, calldata with a trailing byte refused before review; host checks to/value/data, hash and signer |
| `polishtest.sh` | Display polish (not yet run on a phone): the header battery indicator on every page; Display & auto-lock → screen timeout 30 s sets `settings get system screen_off_timeout` to 30000 (and caps the idle lock), back to 1 minute = 60000; haptics off/on; the power-button hint; then screenshots Home, ☰, Security, Display & auto-lock, Device information, Address book, Coming next, Backup reminder and the locked gate at standard and large text and fails if any text node leaves the screen horizontally (`PV_POLISH_OUT`, default `/tmp/polishtest`; `PV_POLISH_KEEP_LARGE=1` leaves large text on for running the review scripts) |
| `safetytest.sh` | Safety reviews (needs the pairing from `usbsigntest.sh`; not yet run on a phone): first send shows "First time sending", is approved and saved as contact "Alice" on the phone keyboard; the repeat send shows the contact and "Sent here once before"; a first-4/last-4 look-alike shows the DIFFERENT-address DANGER grid; setApprovalForAll and a real Universal Router swap are reviewed and rejected; an unknown contract call and an EIP-7702 authorization message are refused with the reason on screen; the contact is deleted from ☰ → Address book |
| `attesttest.sh` | Device attestation (needs the pairing from `usbsigntest.sh` and `PV_ATTEST_VERIFIER`, the companion's `attest_verify` example; not yet run on a phone): StrongBox attestation of a fresh challenge verified by the companion's code (DEVELOPMENT with Developer mode, FAIL without), a repeated challenge refused, a locked phone holds the request until the PIN; no review screen, no crash |
| `lifecycletest.sh` | stop-during-PIN-verify race, unlock, reveal/hide behind a fresh PIN, sleep-lock, wrong PIN counted, unlock, reboot persistence |
| `capture_backup.sh` | screencaps the six phrase pages for UI review (**dev wallets only**) |

Not yet ported: the two-phase **Replace wallet** drill (`regentest.sh`, removed with the 0.2.0
coordinate harness). Drive it by hand via Security → Replace wallet until it is rewritten on
`lib.sh`.

Environment:

* `PV_THROWAWAY_DEVICE=1` — required; every wrong PIN counts toward the 10-attempt erase.
* `PV_TEST_PIN` — 6 digits, prompted silently if unset, never printed. Any value in a report is
  burned; the real PIN is chosen on-device at the final wipe.
* `PV_WORDS_FILE` — a 0600 file with the throwaway 24-word phrase. `firstrun.sh` writes it;
  nothing prints it. Delete it when the throwaway wallet is retired.
* `PV_HOST_PY`, `PV_HOST_CLIENT`, `PV_PAIRING_FILE` — host client for `usbsigntest.sh`, `msgsigntest.sh`, `tokensigntest.sh` and `safetytest.sh` (`PV_VECTORS` overrides the vector fixture path).
* `ANDROID_SERIAL` — pick the phone when more than one is attached (adb honours it; keep `ADB` a bare binary).

Conventions that bit us (see `NOTES.md` for the history):

* Wake the screen and hold it (`svc power stayon usb`, `KEYCODE_WAKEUP`) before tapping.
* The vault locks on screen-off and on idle (30 s / 60 s / 2 min; set 2 min on a throwaway
  before long drills). Scripts re-unlock where a lock is likely.
* `adb shell` inside a `while read` loop eats the loop's stdin — the helpers use `</dev/null`.
* USB: the app opens an accessory transport only on a **fresh** `ACCESSORY_ATTACHED`. After any
  lock the host must reset the gadget (`usb_reset`) and switch again; the host adb server must be
  down during the AOA switch and is restarted a few seconds later (accessory+adb coexist).
* Android refuses `pm clear` for the device-owner app. The only app-level wipe is the app's own
  ten-wrong-PINs erase, and it still needs the owner's explicit approval.
* `adb root` is never called (Lineage gates it behind a toggle a /data wipe resets) and
  `settings global adb_enabled` is never touched remotely (it disabled adb on a kiosk once).
