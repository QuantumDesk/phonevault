# Phone Vault beta: tester guide (Pixel 6a)

This guide takes you from a Pixel 6a to a first small signed transaction, and back to Google's
own Android when you are done. Plan for about an hour.

> **Before you start.** This is a beta for small amounts only, amounts you can afford to lose.
> It is not yet independently audited. The phone's bootloader stays unlocked, the genuine check
> reports **Development**, and the images are signed with beta-test keys. Installing **erases
> everything on the phone**.

## What you need

- A **Google Pixel 6a**. Not a Verizon model. A phone sold locked to a carrier needs a carrier
  unlock first (ask the carrier).
- A **Mac** with **Chrome** or **Edge** (for the web installer), about 2.6 GB of free disk space.
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

- If the installer later says the bootloader or radio does not match, first install Google's
  matching Android release with Google's [Android Flash Tool](https://flash.android.com/) (it
  erases the phone), then come back.
- Pixel phones cannot go back to an older bootloader. If your phone already has a **newer**
  bootloader than the one above, wait for a beta built on that release.

## 3. Unlock the bootloader

Follow Google's official instructions:
[Lock and unlock the bootloader](https://source.android.com/docs/core/architecture/bootloader/locking_unlocking).
In short:

1. Install Google's platform tools on the Mac (they include `fastboot`):
   [SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools).
2. Turn the phone off. Hold **Volume Down + Power** until the bootloader screen appears.
3. Connect the cable and run `fastboot flashing unlock`.
4. On the phone, use the volume keys to choose **Unlock the bootloader** and press Power.

Unlocking erases the phone. From now on the phone shows Google's warning that the bootloader is
unlocked at every start. That is expected in this beta.

## 4. Install Vault OS

Put the phone in bootloader mode (off, then **Volume Down + Power**) and connect it to the Mac.

### Option A: the web installer (recommended)

1. Open **https://phonevault.org/install** in Chrome or Edge on the Mac.
2. Optional, read-only: open **https://phonevault.org/install?check** first. It downloads the
   images, checks every file, reads the phone and stops without writing anything.
3. Press **Start**, choose the phone in the browser's USB list, and follow the page. It checks
   the phone, downloads about 2.4 GB, checks every file against hashes pinned in the page, reads
   the phone again, asks you to confirm, then installs.

### Option B: the Mac script

1. Download the release folder and its `SHA256SUMS` from the release page (link TBD).
2. In Terminal, in that folder:

   ```sh
   shasum -a 256 -c SHA256SUMS        # every line must say OK
   ./flash-beta3-mac.sh --check       # read-only check of the phone
   ./flash-beta3-mac.sh               # type FLASH when asked
   ```

Both options write the same partitions, erase the phone's data, and never touch the bootloader,
the radio firmware or the lock state. The bootloader screen (Volume Down + Power) always stays
reachable.

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

1. Download the companion DMG and its `.sha256` (link TBD). Check it:
   `shasum -a 256 -c "Phone Vault Companion_0.1.0_aarch64.dmg.sha256"`.
2. Open the DMG and drag **Phone Vault Companion** to **Applications**.
3. The app is **not signed or notarized yet**, so macOS blocks a double-click. The first time,
   **right-click → Open** in Applications, then **Open**. (On recent macOS: if it is still
   blocked, System Settings → Privacy & Security → **Open Anyway**.) This step goes away once
   the app is notarized.
4. If you use adb for other phones, run `adb kill-server` first: a running adb can hold the USB
   connection.

## 9. Load the browser extension

Until the store listings exist, load it unpacked:

- **Chrome, Brave or Edge:** download `phone-vault-extension-<version>-chromium-unpacked.zip` (link TBD), check its SHA-256, unzip it, open
  `chrome://extensions` (or `brave://extensions`, `edge://extensions`), turn on **Developer
  mode**, choose **Load unpacked**, and select the unzipped folder. Check that the ID is
  `fbomijndbpoddicmbngledanaafapmlk`: the companion talks only to that ID.
- **Firefox 128+:** `about:debugging#/runtime/this-firefox` → **Load Temporary Add-on…** → the
  `manifest.json` from the unzipped `phone-vault-extension-<version>-firefox.zip`. A temporary add-on is removed when Firefox quits.

Then, in the companion: **Settings → Browser extension → Install browser connection**, and reload
any open site tabs.

## 10. Pair the phone with your Mac

1. Unlock the phone and connect it to the Mac with the cable. Start the companion.
2. **Genuine check.** The companion asks the phone's security chip to prove what booted. A beta
   phone reports **Development**: the bootloader is unlocked and the keys are beta-test keys. To
   accept a Development phone, turn on **Settings → Device → Developer mode** and type
   `I FLASHED THIS PHONE` when it asks. Only do this for a phone you installed yourself. If the check says
   **Not genuine**, stop and report it.
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

- **Install again** with the web installer or the Mac script: it erases all data on the phone.
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

- Bugs and questions: TBD channel.
- Security problems: privately, see [SECURITY.md](../../SECURITY.md).
- Never share your recovery phrase, PIN or passphrase, not even with us.
