# RUNG 4b board config (the crosshatch development baseline). Same board/kernel as rungs 2d-d,
# 3 and 4a; those rungs changed only the device/vendor diffs, common.mk and Android.bp.
# Active here: WITH_AVB, our AVB key + algorithm for vbmeta and vbmeta_system, verity and
# hashtree enforcement (no `--flags 3`, rung 2b), board-info, the appliance VINTF manifest and
# matrices (rung 2c), and the kernel appliance fragment in slices A-D (rungs 2d-a … 2d-d; DWC3
# stays dual-role). The release BoardConfigVault.mk carries the same, with the fragment as one
# file. Archived rungs: vault-os/docs/hardening-ladder.md.
WITH_AVB := true
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS := $(filter-out --flags 3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS))
BOARD_AVB_ALGORITHM := SHA256_RSA4096
BOARD_AVB_KEY_PATH := vendor/phonevault/keys/avb.pem
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := SHA256_RSA4096
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := vendor/phonevault/keys/avb.pem

# Fail closed on blueline: fastboot/OTA metadata is for crosshatch only.
TARGET_BOARD_INFO_FILE := vendor/phonevault/config/board-info.txt

DEVICE_MANIFEST_FILE := vendor/phonevault/vintf/manifest.xml
DEVICE_MATRIX_FILE := vendor/phonevault/vintf/compatibility_matrix.xml
DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE := vendor/phonevault/vintf/device_framework_matrix.xml

# Kernel fragment slices: a connectivity (BT/NFC/WLAN/CNSS/IPA/RMNET), b modem/GLINK,
# c camera/media/sensors/DSP (needs kernel-0002-*.patch), d USB gadget functions. The fragment
# files are installed into kernel/google/msm-4.9/arch/arm64/configs/ by dev-ladder-sync.sh.
TARGET_KERNEL_CONFIG += phonevault-a.config phonevault-b.config phonevault-c.config phonevault-d.config
