# RUNG b1 (bluejay): b0 + our own verified-boot key.
#
# AVB. Lineage gs101 signs vbmeta with the PUBLIC AOSP testkey_rsa4096 and chains boot,
# vbmeta_system (system, system_ext, product, pvmfw) and vbmeta_vendor (vendor) with the PUBLIC
# testkey_rsa2048, and appends `--flags 3` (verification + hashtree off). Anyone can sign with
# those. b1 signs vbmeta AND every chained partition with the Phone Vault bluejay DEVELOPMENT key
# and turns verification on (flags 0).
#   - The key is a DEV key: RSA-4096, generated on the build host, private half only at
#     $(PV_AVB_KEY_DIR)/phonevault_bluejay_avb_DEV_rsa4096.pem (mode 0400, the tree owner's),
#     reached through the in-tree symlink vendor/phonevault/keys/avb_bluejay_dev.pem
#     that sync-rung.sh creates from PV_AVB_KEY_DIR
#     (vendor/phonevault/keys/ is never synced from the repo and never committed). It is NOT the
#     release key, which is generated separately for b8/b9 and never lives on the build host.
#   - Public key: `avbtool extract_public_key` (the future avb_custom_key blob); build-rung.sh
#     writes it next to the images and checks every signed image against its sha1.
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
$(error rung b1: $(PHONEVAULT_AVB_KEY) missing; re-run sync-rung.sh with PV_AVB_KEY_DIR set to the directory holding phonevault_bluejay_avb_DEV_rsa4096.pem (dev-ladder-bluejay/README.md))
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
