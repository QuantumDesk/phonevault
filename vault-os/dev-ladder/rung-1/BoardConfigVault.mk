# Development rung: the AVB, VINTF and kernel-fragment settings marked "(off in this rung)"
# are the release ones, not yet enabled at this rung.
# Never disable verification for a Vault OS build. Production keys are
# deliberately kept outside this repository and the Android source volume.
WITH_AVB := true
# Crosshatch's Lineage board file evaluates its WITH_AVB conditional before
# this appliance include and may already have appended `--flags 3`, which tells
# libavb to disable both verification and hashtree enforcement. Remove that
# development default explicitly; userdebug keeps authenticated ADB without
# weakening the boot chain.
# (off in this rung) BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS := $(filter-out --flags 3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS))
# (off in this rung) BOARD_AVB_ALGORITHM := SHA256_RSA4096
# (off in this rung) BOARD_AVB_KEY_PATH := vendor/phonevault/keys/avb.pem
# (off in this rung) BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := SHA256_RSA4096
# (off in this rung) BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := vendor/phonevault/keys/avb.pem

# The upstream common device tree deliberately accepts both Pixel 3 XL
# (crosshatch) and Pixel 3 (blueline). Phone Vault images are built and tested
# only for crosshatch, so fastboot/OTA metadata must fail closed on blueline.
TARGET_BOARD_INFO_FILE := vendor/phonevault/config/board-info.txt

# Replace Crosshatch's general-purpose VINTF declarations with the appliance
# contract. Retained HAL packages may still contribute reviewed fragments.
# (off in this rung) DEVICE_MANIFEST_FILE := vendor/phonevault/vintf/manifest.xml
# (off in this rung) DEVICE_MATRIX_FILE := vendor/phonevault/vintf/compatibility_matrix.xml
# (off in this rung) DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE := \
# (off in this rung)     vendor/phonevault/vintf/device_framework_matrix.xml

# Merge the appliance fragment after Crosshatch's stock b1c1_defconfig. This
# removes hardware attack surface in the kernel rather than relying solely on
# absent userspace services and firmware.
# (off in this rung) TARGET_KERNEL_CONFIG += phonevault.config
# (off in this rung) TARGET_KERNEL_CONFIG += build20-pstore.config
