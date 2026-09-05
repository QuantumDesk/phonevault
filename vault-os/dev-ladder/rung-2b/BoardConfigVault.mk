# RUNG 2b of the re-hardening ladder (2a + verity/hashtree enforcement ON): the release BoardConfigVault.mk with three items still
# deferred to later rungs (each is its own boot test):
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

# 2c: DEVICE_MANIFEST_FILE := vendor/phonevault/vintf/manifest.xml
# 2c: DEVICE_MATRIX_FILE := vendor/phonevault/vintf/compatibility_matrix.xml
# 2c: DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE := vendor/phonevault/vintf/device_framework_matrix.xml

# 2d: TARGET_KERNEL_CONFIG += phonevault.config
