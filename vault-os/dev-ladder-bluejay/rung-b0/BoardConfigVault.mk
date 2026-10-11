# RUNG b0 (bluejay): AVB is still the Lineage gs101 default. vbmeta is signed with the PUBLIC
# AOSP test key external/avb/test/data/testkey_rsa4096.pem (sha1 2597c218…); boot, vbmeta_system
# (system, system_ext, product, pvmfw) and vbmeta_vendor (vendor) are chained and signed with the
# PUBLIC testkey_rsa2048.pem (sha1 cdbb7717…); without WITH_AVB the gs101 board file appends
# `--flags 3` to vbmeta (verification and hashtree enforcement off). Acceptable only
# on an unlocked development phone; rung b1 re-keys vbmeta and every chained partition with our
# own AVB key and removes `--flags 3`.

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
