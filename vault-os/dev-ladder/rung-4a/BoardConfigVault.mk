# RUNG 4a (= rung 3 board/kernel; the rung's change is in Android.bp: user-facing apps overridden).
# RUNG 3 (= 2d-d kernel/board; the rung's change is in its device diff + common.mk: USB lock-down in the
# USB HALs and init usb rc — gadget allowlist {adb, accessory}, Type-C port sink/UFP-only, no host role).
# RUNG 2d-d (2d-c3 + slice D of the kernel fragment: USB gadget functions — only adb FunctionFS and Android Open Accessory remain; DWC3 gadget-only, no host/OTG). The release BoardConfigVault.mk with the
# no doze; the device diff also drops the NFC HAL, camera provider and CHRE daemon services).
# RUNG 2d-c2 (= 2d-c; the rung's change is in its device/vendor diffs: services for removed hardware are
# not installed). 2d-c: 2d-b + slice C of the kernel fragment: camera / media / sensors / DSP, with kernel patch 0002. The release BoardConfigVault.mk with the
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
TARGET_KERNEL_CONFIG += phonevault-a.config phonevault-b.config phonevault-c.config phonevault-d.config
