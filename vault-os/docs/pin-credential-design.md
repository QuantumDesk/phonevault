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

Still unknown (next spike step, needs its own approval because recovery could need a wipe):
**reboot with the credential set.** File-based encryption ties the app's storage to the credential,
so after a reboot Android must ask for the PIN before our app can start at all. Does it show its
PIN bouncer despite the disabled keyguard, and does unlock then land in the kiosk?

## Stages

1. Spike on phone 2 (needs owner approval: modifies the phone's lock settings).
2. Credential provisioning at first-run + keyguard re-enabled + unlock via system keyguard.
3. v2 auth-bound key + migration + phrase re-reveal via credential prompt.
4. Wipe-after-10 by policy; remove the app-side attempt counter once the system one is proven.
5. Change PIN. Harness updated; auditor review requested (session/unlock boundary changes).
