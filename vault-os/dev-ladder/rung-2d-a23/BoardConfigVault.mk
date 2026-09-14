# RUNG 2d-a3 (2c + sub-slice A23 of the kernel fragment: WLAN/CNSS + IPA/RMNET) — bisecting the 2d-a boot failure: the release BoardConfigVault.mk with the
# kernel fragment reintroduced in slices, each its own boot test (the full fragment was the
# August boot-blocker):
#   2b  remove `--flags 3` (verity + hashtree enforcement ON)
#   2c  appliance VINTF manifest / matrices
#   2d  kernel appliance config fragment
# Active here: WITH_AVB, our AVB key + algorithm for vbmeta and vbmeta_system, board-info.
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

# 2d-a: connectivity drivers only (BT/NFC/WLAN/CNSS/IPA/RMNET). Later slices: 2d-b modem/GLINK,
# 2d-c camera/media/sensors/DSP, 2d-d USB gadget functions. The fragment file is installed into
# kernel/google/msm-4.9/arch/arm64/configs/ by dev-ladder-sync.sh.
TARGET_KERNEL_CONFIG += phonevault-a23.config
