# Never disable verification for a Vault OS build. Production keys are
# deliberately kept outside this repository and the Android source volume.
WITH_AVB := true
# Crosshatch's Lineage board file evaluates its WITH_AVB conditional before
# this appliance include and may already have appended `--flags 3`, which tells
# libavb to disable both verification and hashtree enforcement. Remove that
# development default explicitly; userdebug keeps authenticated ADB without
# weakening the boot chain.
BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS := $(filter-out --flags 3,$(BOARD_AVB_MAKE_VBMETA_IMAGE_ARGS))
BOARD_AVB_ALGORITHM := SHA256_RSA4096
BOARD_AVB_KEY_PATH := vendor/phonevault/keys/avb.pem
BOARD_AVB_VBMETA_SYSTEM_ALGORITHM := SHA256_RSA4096
BOARD_AVB_VBMETA_SYSTEM_KEY_PATH := vendor/phonevault/keys/avb.pem

# Project-owned, strictly increasing AVB rollback index (release-version.mk)
# instead of the inherited security-patch timestamp. sign-release.sh refuses a
# release whose index does not exceed the previous signed release manifest.
include vendor/phonevault/config/release-version.mk
BOARD_AVB_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)
BOARD_AVB_VBMETA_SYSTEM_ROLLBACK_INDEX := $(PHONEVAULT_AVB_ROLLBACK_INDEX)

# The upstream common device tree deliberately accepts both Pixel 3 XL
# (crosshatch) and Pixel 3 (blueline). Phone Vault images are built and tested
# only for crosshatch, so fastboot/OTA metadata must fail closed on blueline.
TARGET_BOARD_INFO_FILE := vendor/phonevault/config/board-info.txt

# Replace Crosshatch's general-purpose VINTF declarations with the appliance
# contract. Retained HAL packages may still contribute reviewed fragments.
DEVICE_MANIFEST_FILE := vendor/phonevault/vintf/manifest.xml
DEVICE_MATRIX_FILE := vendor/phonevault/vintf/compatibility_matrix.xml
DEVICE_FRAMEWORK_COMPATIBILITY_MATRIX_FILE := \
    vendor/phonevault/vintf/device_framework_matrix.xml

# Merge the appliance fragment after Crosshatch's stock b1c1_defconfig. This
# removes hardware attack surface in the kernel rather than relying solely on
# absent userspace services and firmware. The fragment equals the boot-tested
# dev-ladder slices A-D (rung 2d-d): DWC3 stays dual-role (a gadget-only build
# never enumerated on USB); host/source roles are refused by the USB HALs and
# the Type-C port is pinned to sink by init instead.
TARGET_KERNEL_CONFIG += phonevault.config
