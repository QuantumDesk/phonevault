# PIN bound to the Android lock credential (option A, chosen 2026-09-23)

## Goal

Code running on the phone without the PIN must not be able to use the seed key, and the
10-attempt limit must be enforced by the Titan M, not by our app.

## Today

- Seed record encrypted with a StrongBox AES-256-GCM key (`phone-vault-wrapping-key-v1`,
  `setUnlockedDeviceRequired(true)`). The device has **no** lock credential and the keyguard is
  disabled by device-owner policy, so "unlocked device" is always true.
- The 6-digit PIN is checked by the app (`VaultPin`, PBKDF2 hash in app prefs); 10 wrong tries run
  the app's verified erase. An attacker with code execution in our app's context can skip the PIN
  and call the wrapping key directly.

## Design

1. **The vault PIN becomes the Android lock-screen PIN.** At first-run SET PIN the app (device
   owner) installs it with `setResetPasswordToken` + `resetPasswordWithToken`. The PIN digits pass
   through our keypad once, at setup, and are zeroed afterwards. Gatekeeper/Weaver on the Titan M
   now verifies it and throttles guesses in hardware.
2. **Wrong-attempt wipe by policy.** `setMaximumFailedPasswordsForWipe(admin, 10)`: the system
   factory-resets after 10 failures, destroying the keystore (and the seed with it).
3. **Seed key bound to the credential.** A new StrongBox wrapping key (`…-v2`) with
   `setUserAuthenticationRequired(true)` + `setUserAuthenticationParameters(30, AUTH_DEVICE_CREDENTIAL)`:
   usable only within 30 s of a successful credential check. The seed is decrypted once at unlock
   and held in memory for the session, as today; re-reveal of the phrase asks for the credential
   again (`BiometricPrompt` with `DEVICE_CREDENTIAL`, or the confirm-credential intent).
4. **Unlock is the system keyguard.** `setKeyguardDisabled(false)`; the kiosk activity keeps
   `setShowWhenLocked(true)` so the locked-state USB request card can still be shown over the
   keyguard, and `requestDismissKeyguard` brings up the PIN entry. The app's own `PinScreen` is used
   only for first-run SET/CONFIRM.
5. **Migration.** On the first unlock after upgrade: decrypt with v1 (still usable), re-encrypt with
   v2 inside one journaled `WalletPersistence` commit, verify by read-back, then delete v1. A failed
   migration keeps v1 and retries next unlock.
6. **Change PIN.** `resetPasswordWithToken(new)` after a fresh credential check; no re-wrap needed
   because the key is bound to "the current credential", not to the digits.

## Risks to prove on the phone before building on them (spike)

- Does lock-task/kiosk mode behave with a secure keyguard on this LineageOS build (keyguard over
  the kiosk, `requestDismissKeyguard` from HOME, no escape to other apps)?
- Does `setResetPasswordToken` activate immediately when no credential exists (docs: yes)?
- Does `setMaximumFailedPasswordsForWipe` on a device-owner kiosk wipe cleanly and come back to
  owner provisioning (it must — the factory reset path is also the recovery path)?
- Theming: how much of the system keyguard can be styled (wallpaper, lock-screen message).

The spike is reversible: `adb shell locksettings set-pin 123456` then
`adb shell locksettings clear --old 123456`. The wipe policy is NOT part of the spike.

## Spike results (phone 2, rung 2d-b, 2026-09-23)

`locksettings set-pin 123456` succeeded ("lockscreen disabled" flipped to false). Then:

- **No keyguard ever appeared** — not after screen off/on, not after swipe/HOME/recents. The
  device-owner `setKeyguardDisabled(true)` applied at provisioning keeps suppressing the keyguard
  even after a credential is added later (the docs only say it cannot be *set* while a credential
  exists). Focus stayed on Phone Vault, lock task stayed LOCKED, nothing escaped the kiosk.
- `locksettings clear --old 123456` restored the exact baseline (lock screen disabled, kiosk
  LOCKED, no password quality).

What this means for the design: the kiosk and a system credential coexist, and we can keep our
own full-screen UI because the keyguard stays suppressed. The credential is then checked through
`KeyguardManager.createConfirmDeviceCredentialIntent` (or BiometricPrompt with DEVICE_CREDENTIAL)
when the app needs the auth-bound key, not through a lock screen.

### Reboot with the credential set (approved, 2026-09-23)

- After reboot Android logged `Not unlocking CE storage for user 0 yet because user is secured`
  and **showed its stock lock screen despite the disabled keyguard** ("Unlock for all features
  and data", our starfield wallpaper, clock, plus two notifications: "Discover Trust" and "USB
  debugging connected"). Phone Vault could not start: its storage was still encrypted.
- Typing the PIN with `input text` without first opening the PIN pad did nothing (screen then
  slept). `locksettings verify --old 123456` over adb unlocked CE storage; the app then came up in
  the kiosk, lock task LOCKED. `clear` restored the baseline. No wipe needed.

What this means:

- **The Titan M-checked PIN protects the wallet at rest after every reboot**, through file-based
  encryption, before any of our code runs. That is the strongest part of option A, and it works.
- The cost is **one stock Android PIN entry per boot**. Everything after that stays in our UI.
  To make that screen presentable: device-owner `setKeyguardDisabledFeatures` to hide lock-screen
  notifications, keep our wallpaper, and set a lock-screen message ("Phone Vault — enter your
  PIN"). Stripping the notification sources belongs to the ladder anyway.
- **Open decision for in-session locking** (screen-off / idle while booted): (a) keep our keypad
  for in-session unlock and let FBE carry the at-rest protection, or (b) require the Titan M check
  on every unlock through the system confirm-credential screen, with the seed key auth-bound for
  30 s. (b) is stronger against code running on a booted phone; (a) keeps the look. Recommendation:
  (b) for the seed key only — unlock stays ours, and the system screen appears only when the seed
  is actually needed (unlock load, phrase reveal, signing session start).

## Stage 2–3 on phone 2 (2026-09-24): working

Build `006e6a7` + fixes (USE_BIOMETRIC permission, admin uses-policies, crash-safe prompt).
Phone 2's existing wallet upgraded on the first keypad unlock: the PIN became the device PIN, the
system prompt confirmed it, the record was re-sealed under the credential-bound v2 key, same
address `0xE0966BCe…5D49`.

- Screen off → our "locked" screen + system PIN prompt → Home: 2/2. Wrong PIN then right: OK.
- Phrase reveal inside the 30 s window: no second prompt; after the window: prompt, then phrase.
- USB pair + sign + host verification: pass (`usbsigntest.sh`, harness now keys the system PIN).
- Reboot: Android's lock screen (storage locked) → PIN → storage unlocked → vault asks for the PIN
  again for the seed key → Home, kiosk LOCKED. 0 crashes throughout.

Open items:

- ~~Boot asks twice.~~ Fixed 2026-09-24: the first gate after boot waits (≤4 s) for the boot lock
  screen to finish dismissing, tries the key, and prompts only if the keystore refuses
  (`UserNotAuthenticatedException`). Later locks always prompt. `credentialtest.sh` passes 2/2
  including reboot. One unexplained observation from an earlier failed run (Home shown after a
  relock without a PIN entry) could not be reproduced in 3 targeted checks + 2 full runs; its log
  had rolled over. Flagged for the audit.
- ~~Admin policies need re-provisioning.~~ Done 2026-09-24: phone 2 wiped and reprovisioned on
  rung 2d-b; `disable-keyguard-features`, `watch-login`, `wipe-data` active; features=31,
  maximumFailedPasswordsForWipe=10. Boot lock screen now shows no notifications. It showed Android's
  generic "This device belongs to your organization"; Android 15 renders the device owner's
  organization name there, so provisioning now sets it: "This device belongs to Phone Vault"
  (seen 2026-09-27). The wallpaper padlock sat under the big clock; moved and shrunk (next image).
- **Wipe after 10 proved** (approved, 2026-09-24): wrong PINs on Android's boot lock screen; the
  system warned at 7 ("after 3 more … this phone will be reset"), and at 10 showed "Factory data
  reset · Restarting…". The phone came back with no credential, no wallet, Phone Vault device
  owner again. The warning dialog swallows input until OK is tapped.
- **First-boot provisioning regression, root-caused.** After a wipe, patch 0003's `setActiveAdmin`
  (16:09:30) sent DEVICE_ADMIN_ENABLED while the freshly wiped package was still in Android's
  "stopped" state (PACKAGE_UNSTOPPED at 16:09:33), so it was never delivered; only USER_STARTED /
  USER_SWITCHED reached the receiver. Result: launcher/HOME chooser instead of the kiosk until
  the activity was started by hand. Fix: the receiver also provisions on `onUserStarted` (every
  boot, idempotent) and then brings the vault to the front. Proved 2026-09-27: rebuilt 2d-b, wiped, factory boot went straight to the
  locked kiosk at SET PIN with no chooser and no manual start.
- **App update showed the HOME chooser** (2026-09-27, dev `adb install -r`): the persistent HOME
  preference was dropped. `PackageReplacedReceiver` (MY_PACKAGE_REPLACED, not exported, no
  permission) re-provisions and brings the vault back; proved by the next reinstall.
- **Fewer prompts.** Before showing the system PIN prompt, `withSeedKey` asks the keystore whether
  the seed key is usable now (since 2026-10-11 a complete throwaway encrypt, see next item; the
  keystore still enforces the window on the real operation), but only when the app did not see the
  last PIN check itself (boot lock screen, PIN just installed). Not yet observed removing the
  prompt right after SET PIN (needs a factory boot).
- **The window's last second (root-caused 2026-10-11, phone 2).** "Backup unavailable" right after
  a PIN, intermittent on rung 4b. Not a 4b removal: the same edge reproduces on 4a. Two clocks
  decide the window. keystore2 admits `Cipher.init` (begin) by its own *receipt* time of the auth
  token, in whole seconds (`token_age.seconds() > 30`), and BiometricService re-delivers the same
  token when the prompt closes (~0.4 s after issue), so begin works until ~31 s after the token
  reached keystore2. The Titan M decides on the first update/finish, from the token's *issue*
  timestamp and a fresh secure-clock TimeStampToken, in ms: 30.000 s after issue. A controlled
  sweep (open the phrase X s after the PIN) gave, on both rungs: decrypt at ≤ +29.47 s after
  receipt → shown; +29.68 … +30.78 s → init OK, `KeystoreOperation::update` →
  `KEY_USER_NOT_AUTHENTICATED` (citadel `UpdateOperation`) every time (4b 4/4, 4a 4/4); ≥ +31.5 s →
  init refused → PIN prompt → shown. The app's init-only probe passed inside that band, so the app
  skipped the prompt and the decrypt failed. `credentialtest.sh`'s "inside the window" reveal
  lands right on it (harness navigation takes ~29–30 s after the PIN: 4a +29.34 s pass, 4b
  +29.98 / +30.2 s fail), which is why it looked rung-dependent. The automatic re-prompt added earlier the
  same day never worked: it re-entered `beginSensitive` while the flow was still active, was
  refused, and left "Opening secure backup" up after the PIN (seen 8/8 in the sweep); its sticky
  flag then made the next lapse go straight to "Backup unavailable".
  Fix (app): (1) when the app confirmed the PIN itself it never probes near the edge: ≥ 22 s → ask
  (`SeedKeyWindow`); (2) the probe runs a complete operation (`init` + `doFinal` of nothing), so the
  chip's own check answers it, and no StrongBox operation is left open for the GC; (3) the backup
  retry re-opens inside the same sensitive flow, once. Sweeps with the fix: own-confirm path
  prompts at 25–31 s and shows the phrase; forced-probe build refuses at +29.69 … +30.78 s and
  prompts; init-only probe + new retry: decrypt fails, one re-prompt, phrase shown.
- **Boot asked twice again on rung 4b (fixed 2026-10-11).** Same day, after the reboot step:
  Android's lock screen took the PIN, then the vault's own prompt appeared 0.7 s later (2 of 2 boots
  on 4b, baseline and fixed app). Cause in the app, timing from the OS: on a cold start both
  `onCreate` and `onResume` show the credential gate; the first starts the silent boot attempt, the
  second replaced its loading screen with the locked page and queued `promptUnlock`, which fired
  while the attempt was still waiting for the keyguard to finish going away (here 35.07 s exit vs
  35.16 s prompt). 4a passed its reboots here (2/2), consistent with the attempt winning there (not measured). Fix:
  the gate returns early while that session's boot attempt is pending (`bootAttemptSession`); the
  attempt shows the gate itself if the keystore refuses.
- `lifecycletest.sh` still expects the app's "WRONG PIN · 9 ATTEMPTS LEFT" text; in credential
  mode the count lives in the system prompt.
- Auditor review: unlock/session boundary changed (system prompt, v2 key, migration, one permission).

## Stages

1. Spike on phone 2 (needs owner approval: modifies the phone's lock settings).
2. Credential provisioning at first-run + keyguard re-enabled + unlock via system keyguard.
3. v2 auth-bound key + migration + phrase re-reveal via credential prompt.
4. Wipe-after-10 by policy; remove the app-side attempt counter once the system one is proven.
5. Change PIN. Harness updated; auditor review requested (session/unlock boundary changes).
