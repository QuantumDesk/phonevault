# PIN bound to the Android lock credential

## Goal

Code running on the phone without the PIN must not be able to use the seed key, and the
10-attempt limit must be enforced by the Titan M, not by our app.

## Before this design

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

## Risks that had to be proven on the phone first

- Does lock-task/kiosk mode behave with a secure keyguard on this LineageOS build (keyguard over
  the kiosk, `requestDismissKeyguard` from HOME, no escape to other apps)?
- Does `setResetPasswordToken` activate immediately when no credential exists (docs: yes)?
- Does `setMaximumFailedPasswordsForWipe` on a device-owner kiosk wipe cleanly and come back to
  owner provisioning (it must — the factory reset path is also the recovery path)?
- Theming: how much of the system keyguard can be styled (wallpaper, lock-screen message).

The spike is reversible: `adb shell locksettings set-pin 123456` then
`adb shell locksettings clear --old 123456`. The wipe policy is NOT part of the spike.

## As built, and what the hardware showed

Implemented and passing on development phones (Pixel 3 XL from rung 2d-b on; Pixel 6a from b0):
`credentialtest.sh` (relock, wrong-then-right PIN, phrase reveal inside and after the window,
reboot) passes repeatedly, together with the USB signing suites.

**Kiosk and system credential coexist.** With a credential set, the device-owner
`setKeyguardDisabled(true)` applied at provisioning keeps suppressing the keyguard while the
phone is booted (the documentation only says it cannot be *set* while a credential exists).
Focus stays on Phone Vault and lock task stays LOCKED. So the app keeps its own full-screen UI,
and the credential is checked through `BiometricPrompt` with `DEVICE_CREDENTIAL` when the
auth-bound seed key is needed (unlock, phrase reveal, account changes), not through a lock
screen. This replaces design point 4.

**One system PIN entry per boot.** After a reboot Android shows its own lock screen despite the
disabled keyguard ("Not unlocking CE storage for user 0 yet because user is secured"): the
wallet is protected at rest by file-based encryption, checked by the Titan M, before any Phone
Vault code runs. That is the strongest part of this design. To keep that screen presentable the
device owner hides lock-screen notifications (`setKeyguardDisabledFeatures`), sets the
organization name ("This device belongs to Phone Vault") and a lock-screen message, and the
overlay removes the clock (frameworks-base patch 0005). Android 17 shows the device-owner
lock-screen text; Android 15 does not.

**Migration.** An existing wallet upgrades on the first keypad unlock: the PIN becomes the device
PIN, the system prompt confirms it, and the record is re-sealed under the credential-bound v2 key
with the same address.

**Wipe after 10, by policy.** Wrong PINs on Android's boot lock screen: the system warns at 7
("after 3 more … this phone will be reset") and at 10 factory-resets. The phone comes back with
no credential and no wallet, Phone Vault device owner again. The warning dialog swallows input
until OK is tapped.

**First-boot provisioning.** On a factory boot, `setActiveAdmin` can send `DEVICE_ADMIN_ENABLED`
while the freshly installed package is still in Android's "stopped" state, and the broadcast is
dropped (launcher or HOME chooser instead of the kiosk). Fixes: the receiver also provisions on
`onUserStarted` (every boot, idempotent) and brings the vault to the front; an app update
re-provisions HOME from `MY_PACKAGE_REPLACED` (`PackageReplacedReceiver`, not exported); on
Android 17 the platform patch itself re-sends the enable broadcast after user 0 unlocks
(`port-bluejay.md` §11).

**Boot gate: one prompt, not two.** The first gate after boot waits (≤ 4 s) for the boot lock
screen to finish dismissing, tries the key, and prompts only if the keystore refuses
(`UserNotAuthenticatedException`). On a cold start both `onCreate` and `onResume` show the
credential gate; the gate returns early while that session's boot attempt is pending
(`bootAttemptSession`), otherwise the second call would queue a prompt while the first attempt
is still waiting for the keyguard to go away. Later locks always prompt.

**The seed key's window has two clocks.** keystore2 admits `Cipher.init` by its own *receipt*
time of the auth token, in whole seconds (`token_age.seconds() > 30`), and BiometricService
re-delivers the same token when the prompt closes (~0.4 s after issue), so `init` works until
about 31 s after the token reached keystore2. The Titan M decides on the first update/finish,
from the token's *issue* timestamp and a fresh secure-clock TimeStampToken, in milliseconds:
30.000 s after issue. A controlled sweep (open the phrase X s after the PIN) showed: decrypt at
≤ +29.5 s succeeds; +29.7 … +30.8 s → `init` succeeds but `update` fails with
`KEY_USER_NOT_AUTHENTICATED`; ≥ +31.5 s → `init` refused → PIN prompt. An `init`-only probe
therefore passes inside that band and the decrypt then fails. The app's rules:

1. When the app confirmed the PIN itself, it never probes near the edge: from 22 s on it asks
   again (`SeedKeyWindow`).
2. When it did not see the last PIN check (boot lock screen, PIN just installed), its probe runs a
   complete operation (`init` + `doFinal` of nothing), so the chip's own check answers it and no
   StrongBox operation is left open.
3. A backup reveal that still lapses re-opens the prompt once, inside the same sensitive flow.

Open items:

- Owner text on Android's own lock screen on Android 15.
- `lifecycletest.sh` still expects the app's "WRONG PIN · N ATTEMPTS LEFT" text; in credential
  mode the count lives in the system prompt.
- Independent review of the changed unlock/session boundary (system prompt, v2 key, migration,
  the `USE_BIOMETRIC` permission).
- Change PIN (design point 6) in the UI.

## Accounts and passphrase wallets

Switching accounts, adding one, opening or closing a passphrase wallet all decrypt the seed
record once (`VaultKeyStore.deriveAccount`), so they run inside the seed key's
`AUTH_WINDOW_SECONDS` exactly like unlock: through `withSeedKey`, which reuses a fresh PIN
confirmation or asks for the PIN, and with one automatic re-prompt when the window lapsed between
the check and the decrypt (`authLapsed`). Unlock itself derives the saved active account of the
standard wallet in the same single decrypt as before; the passphrase is never part of unlock.
