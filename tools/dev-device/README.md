# Development-device scripts

Scripts that drive the **development** Pixel 3 XL (crosshatch) over ADB from the native
build box. They exist so the physical checks the audits could not repeat are reproducible.
They assume the dev-appliance build (`assembleAppliance`: debug-signed, `DevTools` UI dumps
enabled) and a phone provisioned as described in `NOTES.md`; they are useless — by design —
against a release build, which has no dump hook and refuses `adb install`.

| Script | What it does |
|---|---|
| `buildapp.sh` | `gradle :app:assembleAppliance` with the pinned JDK/SDK paths of the build box |
| `deploy.sh` | build → `adb install -r` → re-assert device owner + kiosk (`device_provisioned=0` dance) → launch → pull the first UI dump |
| `capture_backup.sh` | reveal the recovery phrase via uiautomator taps and pull the dump (**dev wallets only**) |
| `pintest.sh` | first-run PIN flow: partial entry, confirm, mismatch, unlock, sleep/wake lock, wrong PIN, unlock |
| `regentest.sh` | two-phase wallet replacement: cancel keeps the wallet, activate swaps address + QR, survives relock |
| `lifecycletest.sh` | stop-during-PIN-verify race (6th digit + immediate sleep), unlock, reveal/hide, sleep-lock, wrong → right PIN |

Conventions that bit us (see `NOTES.md` for the history):

* Wake the screen and hold it (`svc power stayon usb`, `KEYCODE_WAKEUP`) before tapping: the
  device-owner screen-off timeout is 60 s and taps on a dark screen do nothing.
* Reset to a LOCKED state between scripts (sleep → wake). Keypad coordinates overlap the home
  screen's buttons; never blind-tap a PIN unless the gate is showing.
* Every wrong PIN counts toward the 10-attempt erase. A correct PIN resets the counter.
* Keypad coordinates are for the 1440×2960 panel; find buttons by text (`uiautomator dump`)
  where the scripts do, and update the coordinate table if the layout moves.
* The scripts embed the build box's local paths (`/root/android-sdk`, `/root/pv-root`) and no
  credentials. The device test PIN they use is a throwaway; the wallet on the dev phone must
  never hold funds.
