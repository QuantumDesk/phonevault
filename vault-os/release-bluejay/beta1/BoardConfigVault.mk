# Phone Vault BETA 1 for the Pixel 6a (bluejay): board policy.
#
# Installed in the build tree as vendor/phonevault/config/BoardConfigVault.mk by
# release-bluejay/sync-beta.sh; the sync appends its include to device/google/bluejay/bluejay/
# BoardConfig.mk, after every upstream board setting (gs101 BoardConfig-common.mk included).
#
# = dev-ladder-bluejay/rung-b4d-1/BoardConfigVault.mk (passed on hardware 2026-10-18) with:
#   - AVB signed with the dedicated BETA key, never the dev key (below);
#   - the project-owned AVB rollback index (release-version.mk) instead of the security-patch
#     timestamp;
#   - the serial/early consoles and printk.devkmsg removed from the kernel command line;
# and, unchanged: b1 built boot.img + bootloader/baseband pins, b2 + b4a kernel module removal,
# b2 usbcore.authorized_default=0.

# ---------------------------------------------------------------------------------------------
# AVB: the Phone Vault bluejay BETA key.
#   - RSA-4096, generated on the build host by release-bluejay/gen-beta-keys.sh, private half only
#     at $(PV_BETA_KEY_DIR)/phonevault_bluejay_avb_BETA_rsa4096.pem (mode 0600, aipg's, in a 0700
#     directory), reached through the in-tree symlink vendor/phonevault/keys/avb_bluejay_beta.pem
#     that sync-beta.sh creates. Never committed, never copied off the host.
#   - BETA-TEST key: it signs only beta test images and is replaced by an offline-generated beta
#     key (and later the release key) before any phone is relocked to it.
#   - One key for vbmeta and every chained partition (boot, vbmeta_system, vbmeta_vendor), as on
#     the rungs; verification on (flags 0).
#   - The dev key (avb_bluejay_dev.pem) is refused outright below.
PHONEVAULT_AVB_KEY := vendor/phonevault/keys/avb_bluejay_beta.pem
ifeq ($(wildcard $(PHONEVAULT_AVB_KEY)),)
$(error Phone Vault beta1: $(PHONEVAULT_AVB_KEY) missing; re-run release-bluejay/sync-beta.sh with PV_BETA_KEY_DIR set to the directory holding phonevault_bluejay_avb_BETA_rsa4096.pem (release-bluejay/README.md))
endif
ifneq ($(findstring DEV,$(notdir $(realpath $(PHONEVAULT_AVB_KEY)))),)
$(error Phone Vault beta1: $(PHONEVAULT_AVB_KEY) resolves to a DEVELOPMENT key ($(realpath $(PHONEVAULT_AVB_KEY))); the beta is signed with the BETA key only)
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

# Project-owned, strictly increasing AVB rollback index (release-version.mk, YYYYMMDDNN) for
# vbmeta and every chained partition, instead of the inherited security-patch timestamp
# (1790812800 on the rungs; the project index is larger, so a phone that booted a rung is never
# locked out). Enforced by the bootloader only once a phone is relocked to this key.
include vendor/phonevault/config/release-version.mk
BOARD_AVB_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)
BOARD_AVB_BOOT_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)
BOARD_AVB_VBMETA_VENDOR_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)

# Boot image (b0): build boot.img from the Kleaf dist kernel plus the generic ramdisk (the 6a has
# no init_boot; the dist boot.img is kernel-only). Not a product decision.
BOARD_PREBUILT_BOOTIMAGE :=
TARGET_NO_KERNEL := false
TARGET_PREBUILT_KERNEL := $(TARGET_KERNEL_DIR)/Image.lz4

# fastboot refuses the image zip unless the phone is a bluejay on exactly the bootloader and
# radio this tree's blobs come from (CP2A.260705.006). Firmware is never in our image zip.
TARGET_BOARD_INFO_FILE := vendor/phonevault/config/board-info-bluejay.txt

# ---------------------------------------------------------------------------------------------
# Kernel modules: b2 (slice 1, nothing in userspace uses them) + b4a (the radios, removed together
# with their services). Identical to rung b4d-1; reasons in dev-ladder-bluejay/README.md (b2, b4a)
# and in rung-b4d-1/BoardConfigVault.mk.
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

PHONEVAULT_KMODS_REMOVED += \
    bcmdhd4389.ko cfg80211.ko rfkill.ko \
    nitrous.ko \
    st21nfc.ko st54spi.ko st33spi.ko \
    bcm47765.ko bbd_pps_gpio.ko \
    cpif.ko shm_ipc.ko cpif_page.ko exynos_dit.ko boot_device_spi.ko

# Every name must be a real module of this kernel (a typo would silently remove nothing).
$(foreach k,$(PHONEVAULT_KMODS_REMOVED),$(if $(filter %/$(k),$(KERNEL_MODULES)),,\
  $(error Phone Vault: $(k) in PHONEVAULT_KMODS_REMOVED is not a module in $(KERNEL_MODULE_DIR))))
phonevault-kmod-keep = $(foreach m,$(1),$(if $(filter $(PHONEVAULT_KMODS_REMOVED),$(notdir $(m))),,$(m)))
BOARD_VENDOR_KERNEL_MODULES := $(call phonevault-kmod-keep,$(BOARD_VENDOR_KERNEL_MODULES))
BOARD_VENDOR_KERNEL_MODULES_LOAD := $(call phonevault-kmod-keep,$(BOARD_VENDOR_KERNEL_MODULES_LOAD))
BOARD_VENDOR_RAMDISK_KERNEL_MODULES := $(call phonevault-kmod-keep,$(BOARD_VENDOR_RAMDISK_KERNEL_MODULES))
BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD := $(call phonevault-kmod-keep,$(BOARD_VENDOR_RAMDISK_KERNEL_MODULES_LOAD))

# ---------------------------------------------------------------------------------------------
# Kernel command line (vendor_boot, covered by vbmeta).
# Removed for the beta (deep-audit "bluejay release gap"): gs101 BoardConfig-common.mk's serial
# and early consoles and unthrottled /dev/kmsg writes. A user image has no serial console user;
# earlycon/console=ttySAC0 print every kernel message on the UART pins and androidboot.console
# names the tty init would run a console shell on (debuggable builds only); printk.devkmsg=on lets
# any process with /dev/kmsg access write unlimited lines into the kernel log. The pstore/ramoops
# console (the previous boot's kernel log after a crash) is separate and unaffected.
PHONEVAULT_KERNEL_CMDLINE_REMOVED := earlycon=% console=% androidboot.console=% printk.devkmsg=%
BOARD_KERNEL_CMDLINE := $(filter-out $(PHONEVAULT_KERNEL_CMDLINE_REMOVED),$(BOARD_KERNEL_CMDLINE))
BOARD_BOOTCONFIG := $(filter-out $(PHONEVAULT_KERNEL_CMDLINE_REMOVED),$(BOARD_BOOTCONFIG))

# b2: USB device authorisation off by default (GKI built-in usbcore parameter): if the phone ever
# ends up a USB host, a connected device is never configured, so no interface driver binds.
PHONEVAULT_KERNEL_CMDLINE := usbcore.authorized_default=0
BOARD_KERNEL_CMDLINE += $(PHONEVAULT_KERNEL_CMDLINE)
