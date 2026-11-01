# Development-device scripts

Scripts that drive a **development** phone (Pixel 3 XL or Pixel 6a running a dev-ladder image)
over adb and USB, so the physical checks are reproducible. They assume the dev-appliance app
build (`gradle :app:assembleAppliance`: debug-signed, `DevTools` UI dumps and screenshots
enabled) and a phone flashed and provisioned with a development rung
([`vault-os/dev-ladder/README.md`](../../vault-os/dev-ladder/README.md) or
[`vault-os/dev-ladder-bluejay/README.md`](../../vault-os/dev-ladder-bluejay/README.md)), with your
adb key pre-authorised (`PV_DEV_ADB_KEY` at build time). They are useless, by design, against a
release build, which has no dump hook and refuses `adb install`.

**Throwaway devices and wallets only.** Several scripts wipe, replace or restore the wallet,
and every wrong PIN counts toward the 10-attempt erase. See
[CONTRIBUTING.md](../../CONTRIBUTING.md#on-phone-tests-toolsdev-device).

Every tap is located by the widget's **text and live bounds** (`uiautomator dump`). There is
no coordinate table any more; `uiautomator` only lists visible nodes, so `tap_text` scrolls
once when a button is below the fold.

| Script | What it does |
|---|---|
| `deploy.sh` | build the dev appliance → `adb install -r` → re-assert device owner + kiosk → launch → pull the first UI dump (set `JAVA_HOME`, `ANDROID_HOME` and the Gradle path for your host) |
| `firstrun.sh` | SET PIN → Create-or-Restore → Create → fresh-PIN reveal → 24 words (saved to `PV_WORDS_FILE`, 0600) → 3-word spot check → confirm account → Home |
| `backupcheck.sh` | fresh PIN → 3 random positions answered from `PV_WORDS_FILE` → confirm; checks the account binding |
| `seedqrtest.sh` | SeedQR + reminder (resets the gadget first: an open AOA session blocks sensitive screens): Security → Show as SeedQR behind the PIN shows the 25 × 25 CompactSeedQR with the seed timer and no menu, switches to the 29 × 29 Standard SeedQR and to the words and back, Hide returns Home; `PV_USB_CHECK=1` plugs a host in while it is shown and requires the attach to stay parked; Security → Backup reminder saves each interval and restores "Every 3 months" |
| `restoretest.sh firstrun\|replace ADDR` | picks the phrase's length on "How many words?" (12, 15, 18, 21 or 24, from `PV_WORDS_FILE`), types the words on the phone's own keyboard; requires the derived address shown **before** saving to equal `ADDR`; confirms; checks Home. `replace` goes through Security → Restore a different wallet (fresh PIN, replacement state machine) |
| `usbsigntest.sh` | AOA pair (USB address == screen), mainnet-shaped 0.5 ETH example transfer reviewed and approved on the phone, host recomputes hash + recovers signer against the pinned pairing |
| `reconnecttest.sh` | Reconnect without a replug and without any adb USB reset between requests (needs the pairing from `usbsigntest.sh`): fresh attach; a new client process on the live session (no handshake); lock → unlock → request (the app reopened the attached accessory); lock → request held behind the gate, answered after unlock; a client killed mid-review, its orphaned answer drained by the next client; a session the phone ended itself (malformed line) reopened by the phone (beta5) or re-attached by the host (START + port reset); a host that times out while its request is held behind the lock, then a new client answered after unlock |
| `msgsigntest.sh` | Message signing (needs the pairing from `usbsigntest.sh`): personal_sign text approved, sign-in for another account and unreadable bytes rejected, EIP-712 Mail and Permit2 (UNLIMITED) approved, Permit2 on the wrong host chain rejected; host checks each digest and recovers the signer |
| `btctest.sh` | Bitcoin (testnet, fabricated coins, nothing broadcast; rerunnable): first revokes every remembered account in ☰ → Bitcoin sharing; `btc-account` share screen approved then remembered (no screen, same descriptor) and listed in ☰ → Bitcoin sharing, declined for another account; `btc-show` address on screen == answered address; `btc-sign` P2WPKH and P2TR reviewed ("Send 0.00060000 tBTC", change ✓, fee) and signed, each signature verified on the host with embit (`tools/btc_psbt_tool.py verify`); a rejection; a coin of another wallet refused with "Bitcoin transaction refused"; a revoked account is asked for again. Every step prints PASS or FAIL. Needs `PV_BTC_TOOL` and embit==0.8.0 in `PV_HOST_PY` |
| `btc-signet-e2e.sh` | A REAL signet round trip (needs a person to fund the printed address from a signet faucet; the script never contacts a faucet): signet P2WPKH account 1, receive address 0 shown on the phone, wait for a coin (mempool.space Esplora), PSBT to own receive address 1 + change at the recommended fee, signed on the phone, verified with embit (`tools/btc_signet.py`), broadcast, waited on until confirmed. Resumable from `$PV_SIGNET_DIR` (set it to a private directory of your own); `--address-only` stops after printing the address |
| `tokensigntest.sh` | ERC-20 review (needs the pairing from `usbsigntest.sh`): USDC transfer shown as "Send 50 USDC" and approved, UNLIMITED approval and unknown-contract transfer rejected, Base USDC increaseAllowance approved, calldata with a trailing byte refused before review; host checks to/value/data, hash and signer |
| `polishtest.sh` | Display polish: the header battery indicator on every page; Display & auto-lock → screen timeout 30 s sets `settings get system screen_off_timeout` to 30000 (and caps the idle lock), back to 1 minute = 60000; haptics off/on; the power-button hint; then screenshots Home, ☰, Security, Display & auto-lock, Device information, Address book, Coming next, Backup reminder and the locked gate at standard and large text and fails if any text node leaves the screen horizontally (`PV_POLISH_OUT`, default `/tmp/polishtest`; `PV_POLISH_KEEP_LARGE=1` leaves large text on for running the review scripts) |
| `safetytest.sh` | Safety reviews (needs the pairing from `usbsigntest.sh`): first send to a fresh `0xabcd…1234` address each run (the per-wallet send history cannot be cleared) shows "First time sending", is approved and saved as contact "Alice" on the phone keyboard; the repeat send shows the contact and "Sent here once before"; a first-4/last-4 look-alike shows the DIFFERENT-address DANGER grid; setApprovalForAll and a real Universal Router swap are reviewed and rejected; an unknown contract call and an EIP-7702 authorization message are refused with the reason on screen; the contact is deleted from ☰ → Address book |
| `accountstest.sh` | Accounts and passphrase wallet (rerunnable: resets an earlier run's Account 2 first; an EXIT trap always leaves Account 1 active): getAddress names Account 1; ☰ → Accounts adds Account 2 and switches; a request whose `from` is Account 1 is refused ("Switch to the right account on the phone"); the Account 2 review shows "Signing with"; rename to "Savings" on the phone keyboard; back to Account 1 and hide Savings; open a throwaway passphrase wallet (fingerprint preview, getAddress `wallet: passphrase`, review says "(passphrase wallet)"); relock forgets the passphrase and keeps the saved list |
| `migrationtest.sh` | Migration support WITHOUT changing the wallet (rerunnable; an EXIT trap always leaves Standard numbering and Account 1): getAddress has no `scheme`; `list-addresses` Standard ×5 shown on "Share 5 addresses with your Mac?" and shared (Account 1 == getAddress == the pinned pairing), Ledger Live ×3 declined (clean `rejected`), Ledger Live ×5 shared (Account 1 the same, Account 2 different); ☰ → Accounts → Account numbering → Ledger Live, the check screen shows Account 2 at m/44'/60'/1'/0/0 with that address; getAddress then says `"scheme":"ledger-live"`, Device information shows it, Ledger Live Account 2 is the listed address and survives a relock; switching back to Standard returns Account 1 with no `scheme` |
| `simtest.sh` | The Mac's simulation claim (needs the pairing from `usbsigntest.sh` and the current `aoa_client.py`): an honest `hostSimulation` for a 100 USDC send shows in the box "NOT VERIFIED BY THIS PHONE" and is approved and host-verified; a lying claim shows the red "does not match what this transaction does" row and is rejected; a malformed claim is refused with a schema error; no claim shows no box |
| `attesttest.sh` | Device attestation (needs the pairing from `usbsigntest.sh` and `PV_ATTEST_VERIFIER`, the companion's `attest_verify` example; the attestation itself has been verified on both phones, the repeated-challenge and locked-phone cases not yet): StrongBox attestation of a fresh challenge verified by the companion's code (DEVELOPMENT with Developer mode, FAIL without), a repeated challenge refused, a locked phone holds the request until the PIN (and, where the system PIN prompt is readable, the prompt says "Incoming request", "From your Mac", "Hardware check."); no review screen, no crash |
| `credentialtest.sh` | Credential mode (vault PIN = device PIN, `vault-os/docs/pin-credential-design.md`): relock → the vault's gate → system PIN prompt → Home; wrong-then-right PIN; phrase reveal inside and after the seed key's window; reboot → Android's boot lock screen once → Home without a second prompt. The system prompt is a secure window, so the PIN is keyed in blind |
| `sensitivecanceltest.sh` | Credential mode, a dismissed PIN prompt on a sensitive action: past the seed key's window, Security → Show recovery phrase opens the system prompt, Back dismisses it (nothing shown, still unlocked), twice, and each next tap must open a fresh prompt; then the PIN opens the phrase screen (its words are never read) and ☰ → Wallet returns Home |
| `lifecycletest.sh` | stop-during-PIN-verify race, unlock, reveal/hide behind a fresh PIN, sleep-lock, wrong PIN counted, unlock, reboot persistence (still expects the app-side "WRONG PIN · N ATTEMPTS LEFT" text; in credential mode the count lives in the system prompt) |

On the Pixel 3 XL at rung 4b (credential mode), `safetytest`, `simtest`, `accountstest`,
`seedqrtest`, `polishtest`, `usbsigntest` and `credentialtest` pass in one sequential run. On the
Pixel 6a at rung b4c, `firstrun`, `usbsigntest`, `msgsigntest` and `credentialtest` pass. Running
the scripts from macOS needs Homebrew bash ≥ 4.

Not yet ported: the two-phase **Replace wallet** drill (`regentest.sh`, removed with the 0.2.0
coordinate harness). Drive it by hand via Security → Replace wallet until it is rewritten on
`lib.sh`.

Environment:

* `PV_THROWAWAY_DEVICE=1` — required; every wrong PIN counts toward the 10-attempt erase.
* `PV_TEST_PIN` — 6 digits, never printed. Defaults to `PV_DEFAULT_TEST_PIN` in `env.sh`, the
  one place the harness's test PIN is defined; it is not a pattern, because from beta5 the app's
  SET PIN refuses guessable PINs (all-same digits, straight runs, repeated groups, the common
  list; `firstrun.sh` checks first). Unlock never applies that check: a phone set up before beta5
  with another test PIN keeps working by exporting `PV_TEST_PIN=<that PIN>` before running any
  script (the variable always wins over the default). Any value in a report is burned; the real
  PIN is chosen on-device at the final wipe.
* `PV_WORDS_FILE` — a 0600 file with the throwaway phrase (24 words from `firstrun.sh`; `restoretest.sh` also takes 12, 15, 18 or 21). `firstrun.sh` writes it;
  nothing prints it. Delete it when the throwaway wallet is retired.
* `PV_HOST_PY`, `PV_HOST_CLIENT`, `PV_PAIRING_FILE` — host client for `usbsigntest.sh`, `msgsigntest.sh`, `tokensigntest.sh`, `safetytest.sh` and `simtest.sh` (`PV_VECTORS` overrides the vector fixture path).
* `ANDROID_SERIAL` — pick the phone when more than one is attached (adb honours it; keep `ADB` a bare binary).

Conventions learned the hard way:

* Wake the screen and hold it (`svc power stayon usb`, `KEYCODE_WAKEUP`) before tapping.
* The vault locks on screen-off and on idle (30 s / 60 s / 2 min; set 2 min on a throwaway
  before long drills). Scripts re-unlock where a lock is likely.
* Accounts: the pairing pins the standard wallet's **Account 1**, and a request whose `from` is
  not the active account is refused ("Switch to the right account on the phone"). Every signing
  script starts with `ensure_account1` (☰ → Accounts; closes a passphrase wallet), and
  `accountstest.sh` restores it on any exit.
* An open AOA accessory session (left by any USB script) makes the app refuse sensitive screens
  ("Disconnect USB first"), by design; plain adb is not a session. `usb_reset` ends it.
* The default 1-minute screen timeout caps the idle lock at 1 minute. Stretches with no touch
  (getAddress, gadget reset, adb restart, lock-settle probes) can reach that, so `usb_reset` and
  the getAddress helper `nudge` (tap the header title, a plain label) to restart the idle timer.
* Under `set -e`, `{ kill $pid; die …; }` exits silently when the client already ended: write
  `kill $pid 2>/dev/null || true`. Wait for the top of a review, never for "Reject request"
  (below the fold: the wait itself let the idle lock close the review).
* `adb shell` inside a `while read` loop eats the loop's stdin — the helpers use `</dev/null`.
* USB: the app opens an accessory session on `ACCESSORY_ATTACHED` and, since the stale-session
  fix, reopens the still-attached accessory after every lock and on start; the host client probes
  an existing accessory (zero-length packet) and re-attaches a dead one itself (AOA START + USB
  port reset), so no script needs `usb_reset` between two requests any more (`reconnecttest.sh`
  proves it). Scripts still `usb_reset` to start from a fresh attach, and before sensitive screens
  (an open session refuses them). The host adb server must be down while the client talks and is
  restarted a few seconds later (accessory+adb coexist).
* Android refuses `pm clear` for the device-owner app. The only app-level wipe is the app's own
  ten-wrong-PINs erase, and it still needs the owner's explicit approval.
* `adb root` is never called (Lineage gates it behind a toggle a /data wipe resets) and
  `settings global adb_enabled` is never touched remotely (it disabled adb on a kiosk once).
