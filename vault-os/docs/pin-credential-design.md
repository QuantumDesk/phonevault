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

- **Boot asks twice.** The boot-screen unlock already satisfies the key's 30 s window; the vault
  should try the key first and only prompt if the keystore refuses.
- **Admin policies need re-provisioning.** Android caches the device-admin policy list from
  activation, so phone 2 (provisioned before this build) refuses `disable-keyguard-features` and
  the 10-failure wipe: its boot lock screen still shows notifications ("Discover Trust", "USB
  debugging") and the generic "belongs to your organization" line, and wrong PINs only throttle.
  A phone provisioned with this build gets both. Proving the policy wipe needs a fresh
  provisioning and its own approval.
- `lifecycletest.sh` still expects the app's "WRONG PIN · 9 ATTEMPTS LEFT" text; in credential
  mode the count lives in the system prompt.
- Auditor review: unlock/session boundary changed (system prompt, v2 key, migration, one permission).

## Stages

1. Spike on phone 2 (needs owner approval: modifies the phone's lock settings).
2. Credential provisioning at first-run + keyguard re-enabled + unlock via system keyguard.
3. v2 auth-bound key + migration + phrase re-reveal via credential prompt.
4. Wipe-after-10 by policy; remove the app-side attempt counter once the system one is proven.
5. Change PIN. Harness updated; auditor review requested (session/unlock boundary changes).
