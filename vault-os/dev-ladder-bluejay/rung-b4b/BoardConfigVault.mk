# RUNG b4b (bluejay): identical to b4a (b4b's change is the Android.bp app strip). b4a: kernel
# slice 2, the radio drivers (end of file), removed together with their services. b1 (our own
# verified-boot key) + b2 kernel hardening slice 1.
#
# AVB. Lineage gs101 signs vbmeta with the PUBLIC AOSP testkey_rsa4096 and chains boot,
# vbmeta_system (system, system_ext, product, pvmfw) and vbmeta_vendor (vendor) with the PUBLIC
# testkey_rsa2048, and appends `--flags 3` (verification + hashtree off). Anyone can sign with
# those. b1 signs vbmeta AND every chained partition with the Phone Vault bluejay DEVELOPMENT key
# and turns verification on (flags 0).
#   - The key is a DEV key: RSA-4096, generated on the build host, private half only at
#     /home/aipg/.phonevault-keys/avb/phonevault_bluejay_avb_DEV_rsa4096.pem (mode 0400, aipg),
#     reached through the in-tree symlink vendor/phonevault/keys/avb_bluejay_dev.pem
#     (vendor/phonevault/keys/ is never synced from the repo and never committed). It is NOT the
#     release key, which is generated separately for b8/b9 and never lives on the build host.
#   - Public key (avbtool extract_public_key, the future avb_custom_key blob):
#     sha256 068a9865f04cc9b91f6838b537c14f32e4fa6e32682cbcfbfd6c9782ab71ae8c,
#     sha1   af09b166ade90fb31a184e9ab6c59819cd33fc8a (what `avbtool info_image` prints).
#   - One key for all four signatures: chained partitions carry their own public key in vbmeta,
#     so separate keys only matter once release OTAs are signed by different parties.
#   - Rollback indexes unchanged from gs101: $(PLATFORM_SECURITY_PATCH_TIMESTAMP) at locations
#     2 (boot), 1 (vbmeta_system), 3 (vbmeta_vendor) and for vbmeta itself.
#   - The phone stays UNLOCKED (no avb_custom_key, no relock before b9). An unlocked bootloader
#     boots a mis-signed image anyway (orange state), so flags 0 is safe to test: a bad
#     signature or a corrupted partition shows up as a verification error / dm-verity
#     enforcing restart instead of being silently ignored.
PHONEVAULT_AVB_KEY := vendor/phonevault/keys/avb_bluejay_dev.pem
ifeq ($(wildcard $(PHONEVAULT_AVB_KEY)),)
$(error rung b1: $(PHONEVAULT_AVB_KEY) missing; link it to the dev key in /home/aipg/.phonevault-keys/avb (dev-ladder-bluejay/README.md))
endif
PHONEVAULT_AVB_ALGORITHM := SHA256_RSA4096

BOARD_AVB_ALGORITHM := $(PHONEVAULT_AVB_ALGORITHM)
BOARD_AVB_KEY_PATH := $(PHONEVAULT_AVB_KEY)
BOARD_AVB_BOOT_ALGORITHM := $(PHONEVAULT_AVB_ALGORITHM)
BOARD_AVB_BOOT_KEY_PATH := $(PHONEVAULT_AVB_KEY)
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := $(PHONEVAULT_AVB_ALGORITHM)
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := $(PHONEVAULT_AVB_KEY)
BOARD_AVB_VBMETA_VENDOR_ALGORITHM := $(PHONEVAULT_AVB_ALGORITHM)
BOARD_AVB_VBMETA_VENDOR_KEY_PATH := $(PHONEVAULT_AVB_KEY)
# Verification on: drop gs101's `--flags 3` (added because WITH_AVB is unset).
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS := $(strip $(subst --flags 3,,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS)))

# Boot image. gs101 uses $(TARGET_KERNEL_DIR)/boot.img as BOARD_PREBUILT_BOOTIMAGE, but the
# Lineage 24.0 kernel manifest's Kleaf dist boot.img is kernel-only (ramdisk size 0). The 6a
# launched with Android 12 and has no init_boot, so first-stage init must be in boot's generic
# ramdisk: that prebuilt would panic with no /init. Build boot.img here instead, from the dist
# kernel (Image.lz4 is byte-identical to the dist boot.img's kernel) plus the generic ramdisk,
# which is the layout of Google's own bluejay boot.img. dtb, cmdline and the vendor ramdisk are
# in vendor_boot as before. Not a product decision; drop when the kernel dist ships a full boot.img.
BOARD_PREBUILT_BOOTIMAGE :=
TARGET_NO_KERNEL := false
TARGET_PREBUILT_KERNEL := $(TARGET_KERNEL_DIR)/Image.lz4

# fastboot refuses the image zip unless the phone is a bluejay on exactly the bootloader and
# radio this tree's blobs come from (CP2A.260705.006). Firmware is never in our image zip.
TARGET_BOARD_INFO_FILE := vendor/phonevault/config/board-info-bluejay.txt

# ---------------------------------------------------------------------------------------------
# Rung b2: kernel hardening, slice 1 (the crosshatch 2d-a/2d-d intent, as far as GKI allows).
#
# The kernel is GKI android14-6.1 (a downloaded, Google-built prebuilt) plus Kleaf-built Pixel
# vendor modules. Nothing can be removed from the GKI image itself without leaving GKI (never edit
# gki_defconfig: every vendor module is built against its KMI). What GKI ships as *unprotected
# modules*, and what the vendor ships, can be left out of the image: such a .ko is neither
# installed on vendor_dlkm / in the vendor_boot ramdisk nor named in a load list, so there is no
# file to load.
#
# Slice 1 removes only modules that NOTHING in this image's userspace uses, so no vendor service
# loses its device in this rung (radio drivers whose HALs/daemons would crash-loop go in b4a,
# together with those services: the crosshatch 2d-c lesson):
#   - the Linux Bluetooth host stack and its UART/SDIO/vendor drivers (Android's Bluetooth stack
#     reaches the controller through the vendor HAL over a tty, never through these);
#   - mac80211 (bcmdhd4389 is a FullMAC cfg80211 driver) and libarc4 (used by mac80211/ppp_mppe);
#   - the Linux NFC netlink subsystem (the ST NFC HAL uses the st21nfc char device);
#   - IEEE 802.15.4 / 6LoWPAN, CAN, PPP/PPTP/L2TP, TIPC (+ its diag), 802.1Q VLAN, WWAN;
#   - USB *host* class drivers that only matter when the phone hosts a device (USB ethernet
#     adapters, USB serial, CDC-ACM). Host mode is also refused in userspace from b3.
# Not removable without leaving GKI (built into the GKI image): every USB gadget function (mass
# storage, FunctionFS, MIDI, HID, UVC, UAC2, NCM/ECM/EEM, ACM/serial, accessory), usb-storage/uas,
# uvcvideo, snd-usb-audio, xhci, tcpm/typec. Gadget functions are therefore enforced in userspace
# (b3: no function instances except AOA/adb), and USB devices are never authorised when the phone
# is a host (cmdline below).
# Stays (still used, or later): rfkill + cfg80211 + bcmdhd4389, nitrous, st21nfc/st54spi/st33spi,
# bcm47765/bbd_pps_gpio, the s5300 modem stack (all b4a, with their services); AoC (audio and
# sensors route through it), the EdgeTPU (the thermal HAL binds its tpu_cooling device), LWIS
# camera, MFC/smfc/BigWave codecs, g2d; pktgen (already in the vendor blocklist).
PHONEVAULT_KMODS_REMOVED := \
    bluetooth.ko hci_uart.ko btbcm.ko btqca.ko btsdio.ko rfcomm.ko hidp.ko \
    mac80211.ko libarc4.ko \
    nfc.ko \
    6lowpan.ko nhc_dest.ko nhc_fragment.ko nhc_hop.ko nhc_ipv6.ko nhc_mobility.ko \
    nhc_routing.ko nhc_udp.ko ieee802154.ko ieee802154_6lowpan.ko ieee802154_socket.ko \
    mac802154.ko \
    can.ko can-raw.ko can-bcm.ko can-gw.ko can-dev.ko vcan.ko slcan.ko \
    ppp_generic.ko bsd_comp.ko ppp_deflate.ko ppp_mppe.ko pppox.ko pptp.ko slhc.ko \
    l2tp_core.ko l2tp_ppp.ko \
    tipc.ko diag.ko \
    8021q.ko \
    wwan.ko \
    usbnet.ko mii.ko asix.ko ax88179_178a.ko cdc_ether.ko cdc_eem.ko cdc_ncm.ko aqc111.ko \
    r8152.ko r8153_ecm.ko rtl8150.ko \
    cdc-acm.ko usbserial.ko ftdi_sio.ko

# Rung b4a: kernel slice 2, the radios (the crosshatch 2d-a/2d-b intent). Each goes in the same
# rung as the vendor service that drives it (Android.bp overrides + rc/feature/VINTF diffs), so no
# daemon is left crash-looping on a missing device:
#   Wi-Fi     bcmdhd4389 (BCM4389 FullMAC, PCIe) + cfg80211 + rfkill. The Wi-Fi HAL and
#             wpa_supplicant stay installed and simply find no wlan0 (as crosshatch 2d-a).
#   Bluetooth nitrous (Pixel BT power/LPM driver; the controller sits on a UART). HAL bcmbtlinux out.
#   NFC / eSE st21nfc (ST NFC controller), st54spi + st33spi (ST secure elements). NFC HAL and the
#             gto eSE HAL out. The vault's keys live in the Titan M2 (citadel), never in the eSE.
#   GNSS      bcm47765 + bbd_pps_gpio (Broadcom GNSS over SPI). gpsd/lhd/scd + GNSS HAL out.
#   Modem     the Samsung s5300 interface stack: cpif (+ shm_ipc, cpif_page, exynos_dit,
#             boot_device_spi), so cbd can no longer boot the CP and nothing can talk to it. cbd,
#             rfsd, dmd, shared_modem_platform out. Kept: google_modemctl (aoc_alsa_dev_util and
#             google_bcl depend on it), cp_thermal_zone (standalone thermal zone), the telephony
#             framework, rild and the radio HAL manifest (the telephony rung, as on crosshatch).
#             The modem FIRMWARE (modem_a/modem_b partitions) is untouched: it is never loaded.
PHONEVAULT_KMODS_REMOVED += \
    bcmdhd4389.ko cfg80211.ko rfkill.ko \
    nitrous.ko \
    st21nfc.ko st54spi.ko st33spi.ko \
    bcm47765.ko bbd_pps_gpio.ko \
    cpif.ko shm_ipc.ko cpif_page.ko exynos_dit.ko boot_device_spi.ko

# Every name must be a real module of this kernel (a typo would silently remove nothing).
$(foreach k,$(PHONEVAULT_KMODS_REMOVED),$(if $(filter %/$(k),$(KERNEL_MODULES)),,\
  $(error Phone Vault: $(k) in PHONEVAULT_KMODS_REMOVED is not a module in $(KERNEL_MODULE_DIR))))
# Dependencies were closed over by hand (modinfo depends, 2026-10-13): nothing kept depends on a
# removed module. check-build.sh re-checks modules.dep in the target files.
phonevault-kmod-keep = $(foreach m,$(1),$(if $(filter $(PHONEVAULT_KMODS_REMOVED),$(notdir $(m))),,$(m)))
BOARD_VENDOR_KERNEL_MODULES := $(call phonevault-kmod-keep,$(BOARD_VENDOR_KERNEL_MODULES))
BOARD_VENDOR_KERNEL_MODULES_LOAD := $(call phonevault-kmod-keep,$(BOARD_VENDOR_KERNEL_MODULES_LOAD))
BOARD_VENDOR_RAMDISK_KERNEL_MODULES := $(call phonevault-kmod-keep,$(BOARD_VENDOR_RAMDISK_KERNEL_MODULES))
BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD := $(call phonevault-kmod-keep,$(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD))

# USB device authorisation off by default (GKI built-in usbcore parameter; vendor_boot cmdline,
# covered by vbmeta): if the phone ever ends up a USB host, a connected device enumerates but is
# never configured, so no interface driver (usb-storage, uvcvideo, snd-usb-audio, HID: all GKI
# built-ins) binds. Root hubs are always authorised; the phone has no internal USB devices (Wi-Fi
# and the modem sit on PCIe). Gadget mode (the Mac connection) is not affected.
PHONEVAULT_KERNEL_CMDLINE := usbcore.authorized_default=0
BOARD_KERNEL_CMDLINE += $(PHONEVAULT_KERNEL_CMDLINE)
