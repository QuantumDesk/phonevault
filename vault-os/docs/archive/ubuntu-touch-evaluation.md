# Ubuntu Touch / mobile Linux baseline evaluation

## Device identity matters

The test phone is a Pixel 3 XL (`crosshatch`). It is not the Pixel 3a XL
(`bonito`). UBports currently lists the Pixel 3a and 3a XL as supported devices,
but its Pixel 3/3 XL forum states that there is no active port, OTA channel, or
installer configuration for the Pixel 3/3 XL.

## What Ubuntu Touch would improve

- A small native signer can be written with conventional Linux tooling.
- USB gadget functions and a narrowly configured systemd service can provide a
  clean desktop transport.
- The root filesystem and package set are easier to inspect than a full Android
  application stack.

## What it does not solve automatically

- The crosshatch port would still depend on Halium, Android device/kernel code,
  and proprietary vendor firmware.
- A community image being bootable does not prove Pixel AVB custom-key support,
  rollback protection, or successful bootloader relocking.
- A general Ubuntu userspace exposes services and package-management behavior
  that must be removed or locked down for an offline signing appliance.
- Replacing the Android app means replacing the tested Android Keystore-backed
  key wrapper and on-device policy model with an independently reviewed Linux
  implementation.

## Decision gate

Do not switch the primary crosshatch implementation unless a candidate image
passes all of these on the physical device:

1. Boots with a project-owned AVB root and a locked bootloader.
2. Retains hardware-backed key storage or provides a documented equivalent.
3. Has no enabled Wi-Fi, Bluetooth, cellular, NFC, SSH, package update, or
   discovery services.
4. Exposes only the intended USB protocol and charging functions.
5. Supports atomic signed updates, rollback, recovery, and reproducible package
   manifests.

Until those properties are demonstrated, LineageOS/AOSP remains the primary
baseline. Ubuntu Touch/mobile Linux remains a useful parallel research path,
especially for Pixel 3a/3a XL hardware.

## Sources checked 2026-08-17

- https://ubports.com/pixel-3a/xl
- https://ubports.com/blog/ubports-news-1/ubuntu-touch-24-04-1-0-release-3973
- https://forums.ubports.com/category/68/google-pixel-3-3-xl
- https://docs.ubports.com/en/latest/porting/introduction/Intro.html
