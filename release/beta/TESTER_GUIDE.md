# Phone Vault beta: tester guide (Pixel 6a)

For **0.1.0-beta4**. Downloads: [https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4).

This guide takes you from a Pixel 6a to a first small signed transaction, and back to Google's
own Android when you are done. Plan for about an hour.

> **Before you start.** This is a beta for small amounts only, amounts you can afford to lose.
> It is not yet independently audited. The phone's bootloader stays unlocked, the genuine check
> reports **Development**, and the images are signed with beta-test keys. Installing **erases
> everything on the phone**.

## What you need

- A **Google Pixel 6a**. Not a Verizon model. A phone sold locked to a carrier needs a carrier
  unlock first (ask the carrier).
- A **Mac with Apple silicon** (M1 or later, macOS 12 or later), about 5 GB of free disk space
  (2.4 GB download, and the same again while the install script joins `super.img`).
- **Chrome** or **Edge** (Brave works too) for the Phone Vault browser extension.
- Google's **fastboot** on the Mac: `brew install android-platform-tools` (with
  [Homebrew](https://brew.sh)), or Google's
  [SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools).
- A **USB-C data cable**, plugged straight into the Mac (no hub). Some cheap cables only charge.
- **Pen and paper** for the recovery phrase, or a printed backup card.

## 1. Check that OEM unlocking can be turned on

1. On the Pixel 6a, connect to Wi-Fi. (A new phone may need to be online for a while before the
   switch becomes available.)
2. Settings → About phone → tap **Build number** seven times to turn on Developer options.
3. Settings → System → Developer options → **OEM unlocking**.
   - If you can switch it on: switch it on and continue.
   - If it is greyed out: the phone is carrier-locked or a Verizon model. A carrier-locked phone
     needs the carrier's unlock first. A Verizon Pixel 6a cannot be used.

## 2. Make sure the phone runs the firmware this beta needs

Phone Vault never changes the phone's firmware, so the phone must already run the Google release
the beta was built on: bootloader `bluejay-17.0-15199431`, radio
`g5123b-145971-260414-B-15201439`. The installer reads both and writes nothing if they differ.

- Google's Android 17 builds **CP2A.260605.012** and **CP2A.260705.006** carry exactly this
  bootloader and radio. Check yours in bootloader mode with `fastboot getvar version-bootloader`
  and `fastboot getvar version-baseband`.
- If the installer later says the bootloader or radio does not match, first install one of
  those Google builds with Google's [Android Flash Tool](https://flash.android.com/) (it erases
  the phone), then come back.
- Pixel phones cannot go back to an older bootloader. If your phone already has a **newer**
  bootloader than the one above, wait for a beta built on that release.

## 3. Unlock the bootloader

Follow Google's official instructions:
[Lock and unlock the bootloader](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking).
In short:

1. Install `fastboot` on the Mac if you have not yet: `brew install android-platform-tools`.
2. Turn the phone off. Hold **Volume Down + Power** until the bootloader screen appears.
3. Connect the cable and run `fastboot flashing unlock`.
4. On the phone, use the volume keys to choose **Unlock the bootloader** and press Power.

Unlocking erases the phone. From now on the phone shows Google's warning that the bootloader is
unlocked at every start. That is expected in this beta.

## 4. Install Vault OS

1. From the release page, [https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4](https://github.com/QuantumDesk/phonevault/releases/tag/v0.1.0-beta4), download every file
   into one new folder: `super.img.part-aa`, `super.img.part-ab`,
   `PhoneVault-beta4-images-bluejay.zip`, `install-beta4-mac.sh`, `flash-beta4-mac.sh`,
   `manifest.json`, `SHA256SUMS`, `PhoneVault-Companion-0.1.0-beta4-arm64.dmg`,
   `PhoneVault-Extension-0.1.0-beta4-chromium.zip` and `SHA256SUMS-assets`. (If Safari unpacks
   the zip into a folder by itself, leave that folder where it is: the script uses it.)
2. In Terminal, in that folder, check the downloads:

   ```sh
   cd ~/Downloads/phonevault-beta4        # the folder you downloaded into
   shasum -a 256 -c SHA256SUMS-assets     # every line must say OK
   ```

   If Safari unpacked the images zip, its line reports the zip as missing: that is fine, the
   install script checks every image inside it against `SHA256SUMS`. Any other `FAILED` line
   means a damaged download: download that file again.

3. Optional, and it never touches the phone: `bash install-beta4-mac.sh --verify-only` joins
   `super.img`, unzips the images and checks every file against `SHA256SUMS`, then stops.
4. Put the phone in bootloader mode (off, then hold **Volume Down + Power**) and connect it to
   the Mac with the cable, straight into the Mac.
5. Run the installer and follow it:

   ```sh
   bash install-beta4-mac.sh
   ```

   It checks that `fastboot` is installed, joins and checks every file, then runs
   `flash-beta4-mac.sh --check`: a read-only check that the phone is a Pixel 6a with the right
   bootloader and radio and an unlocked bootloader. Only then does it start the install, which
   asks you to type `FLASH` before it writes anything. Anything else stops it.

The install writes slot a (the boot images and `super`), **erases** the phone's data, and never
touches the bootloader, the radio firmware or the lock state. The bootloader screen (Volume Down
+ Power) always stays reachable, so a failed install can be repeated.

A web installer (phonevault.org/install) is planned but not available for this release.

## 5. First start: SET PIN

1. The phone restarts. Google's unlocked-bootloader warning appears first: press nothing, it
   continues by itself.
2. The first start takes about a minute. The phone must land on Phone Vault's **SET PIN**
   screen without a single tap: no setup wizard, no home screen.
3. Choose a six-digit PIN and enter it twice. **Ten wrong PINs in a row erase the phone.**

If the phone stays on the Google logo for more than five minutes or returns to the bootloader:
hold Volume Down + Power, install again, and report what you saw.

## 6. Create or restore a wallet

On the phone:

- **Create a new wallet** (recommended for the beta). Optional: Advanced → add your own dice
  rolls.
- **Restore** a recovery phrase you already have (12 to 24 words), typed on the phone's own
  keyboard. If it came from Ledger Live, choose **Ledger Live** account numbering afterwards
  (Accounts → Account numbering). For a beta, prefer a new wallet and move a small amount over:
  restoring puts your old phrase on a second device.

## 7. Write down the recovery phrase

1. The phone shows 24 words, a few at a time. Write them on paper, in order, or use the
   printable backup card (the companion has it under Settings).
2. Pass the spot check: the phone asks for some of the words, then shows the address to confirm.
   The wallet cannot receive or sign until you pass it.
3. Keep the paper offline: no photo, no cloud, no password manager. Anyone with these words owns
   the wallet; without them, a lost or erased phone means lost funds.

## 8. Install Phone Vault Companion on your Mac

1. Use `PhoneVault-Companion-0.1.0-beta4-arm64.dmg` from the release folder (its line in
   `SHA256SUMS-assets` said OK in section 4). It runs on Apple silicon Macs only.
2. Open the DMG and drag **Phone Vault Companion** to **Applications**.
3. The app is **not signed or notarized yet**, so macOS blocks a double-click. The first time,
   **right-click → Open** in Applications, then **Open**. (On recent macOS: if it is still
   blocked, System Settings → Privacy & Security → **Open Anyway**.) This step goes away once
   the app is notarized.
4. If you use adb for other phones, run `adb kill-server` first: a running adb can hold the USB
   connection.

## 9. Load the browser extension

Until the store listings exist, load it unpacked in **Chrome, Brave or Edge**:

1. Unzip `PhoneVault-Extension-0.1.0-beta4-chromium.zip` from the release folder (checked in
   section 4) into a folder you will keep: the browser loads the extension from that folder every
   time.
2. Open `chrome://extensions` (or `brave://extensions`, `edge://extensions`) and turn on
   **Developer mode**.
3. Choose **Load unpacked** and select the unzipped folder (the one that contains
   `manifest.json`).
4. Check that the ID is `fbomijndbpoddicmbngledanaafapmlk`: the companion talks only to that
   ID.

Then, in the companion: **Settings → Browser extension → Install browser connection**, and reload
any open site tabs. Firefox is not packaged for this release.

## 10. Pair the phone with your Mac

1. Unlock the phone and connect it to the Mac with the cable. Start the companion.
2. **Genuine check.** The companion asks the phone's security chip to prove what booted. A beta
   phone is not accepted until you turn on **Settings → Device → Developer mode** and type
   `I FLASHED THIS PHONE` when it asks. Only do this for a phone you installed yourself. The
   genuine check then shows **Beta build: bootloader unlocked, not production. Small amounts
   only** (verdict Development): the bootloader is unlocked and the keys are beta-test keys. If
   the check says **Not genuine** with Developer mode on, stop and report it.
3. **Pair.** Compare the address the companion shows with the address on the phone's Wallet
   screen, character by character, then confirm.

## 11. A first small test transaction

1. **Receive.** In the companion, choose a network (Base has low fees) and **Receive**. Compare
   the address with the one on the phone's Wallet screen. Send a small amount there from another
   wallet you control.
2. **Send back.** In the companion, **Send** a small amount to an address you control.
3. On the phone, read the review: amount, recipient, network, maximum fee. Approve, or press
   **Reject** if anything looks wrong.
4. The companion checks the signature. Nothing goes out until you click **Send to network**.
5. Watch it confirm in Activity.

Then try a site: open Uniswap, choose **Phone Vault** in its wallet list, approve the connection
in the companion, and do a tiny swap. The phone shows "You give · You get at least · Recipient".

For Bitcoin: in the companion, pick Bitcoin in the network menu, **Add from phone** (Native SegWit
is the default), compare the first address with the phone, receive a very small amount, then send
part of it back.

## 12. Erasing the phone

There is no in-app "erase wallet" button in this beta. To erase:

- **Install again** with `install-beta4-mac.sh`: it erases all data on the phone.
- **Go back to Google's Android** (next section): also erases everything.
- Ten wrong PINs in a row erase the phone.

Erase only after you have checked your recovery phrase on paper, or after you have moved your
funds out. Without the phrase, an erased wallet cannot be recovered.

## 13. Going back to Google's Android

1. Move any funds out, or make sure you have your recovery phrase.
2. Open Google's **Android Flash Tool** at https://flash.android.com/ in Chrome or Edge.
3. Put the phone in bootloader mode (off, then Volume Down + Power) and connect it.
4. Choose the latest Pixel 6a release and install it. Keep **Wipe device** selected.
5. Optional: Google's tool can relock the bootloader for **Google's own** system ("Lock
   bootloader"). Only relock when the phone runs a factory image from Google, never with Vault
   OS on it.

## Reporting a problem

- Bugs and questions: [GitHub Issues](https://github.com/QuantumDesk/phonevault/issues/new/choose).
  Include the phone model, the image version (Security → Device information), the companion
  version, your macOS version, what you did, what you expected and what you saw. A photo of the
  phone's screen helps.
- Security problems: privately, through GitHub's private vulnerability reporting ("Report a
  vulnerability" on the repository's Security tab); see [SECURITY.md](../../SECURITY.md). Never
  in a public issue.
- Never share your recovery phrase, PIN or passphrase, not even with us.
