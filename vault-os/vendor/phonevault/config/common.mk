# Fixed-function signing appliance. Upstream package removal is enforced by
# PhoneVault's Soong `overrides` list and verified against target-files. Make
# package subtraction is intentionally not used: inherited product lists may
# be expanded after this file is evaluated.
#
# This file is RELEASE configuration. Development-only settings (adb as the
# default USB function, insecure adb, pre-authorised adb keys, early-boot adb
# init scripts) live only in vault-os/dev-ladder/rung-*/ and must never be
# copied here; scripts/verify-release-source.sh rejects them.

PRODUCT_PACKAGES += \
    PhoneVault

# Project-owned version and AVB rollback index (bumped once per release).
include vendor/phonevault/config/release-version.mk

# The resource overlay (vendor/phonevault/overlay) is added by the product makefile
# (device/phonevault/crosshatch/vault_crosshatch.mk) ahead of its inherits so it outranks
# Lineage's overlays; adding it here too would list the directory twice.

# NOTE (dev ladder rung 4, vault-os/dev-ladder/README.md "App strip mechanism"): this file is inherited after vendor/lineage/config, so
# Lineage/AOSP opt-out knobs assigned here are evaluated too late and do nothing.
# AudioFX, Aperture and DynamicSystemInstallationService are removed by the
# `overrides` list instead; these lines are kept only as documentation of intent.
# TARGET_DISABLE_LINEAGE_SDK is deliberately NOT set: Lineage's SystemUI and
# Settings use the SDK and LineageSettingsProvider (rung 4 analysis).
PRODUCT_NO_CAMERA := true
PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE := true
TARGET_EXCLUDES_AUDIOFX := true

# FusedLocation and Telecom are not removed with PRODUCT_SYSTEM_SERVER_APPS:
# LocationManagerService requires a direct-boot-aware fused provider at boot
# (FusedLocation stays), and Telecom is removed with the telephony rung via
# the `overrides` list.

PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    config.disable_cameraservice=true \
    config.disable_networktime=true \
    ro.phonevault.offline=true \
    ro.phonevault.version=$(PHONEVAULT_VERSION) \
    persist.sys.usb.config=none

PRODUCT_SYSTEM_PROPERTIES += \
    ro.radio.noril=true

# Vendor HALs must not depend on access to a system-private property namespace.
# This immutable vendor property independently activates their appliance
# restrictions under Treble property isolation.
PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.phonevault.offline=true

# HOME from the first boot: the framework applies etc/preferred-apps before any app runs, so a
# genuine first boot never shows a launcher chooser (device-owner provisioning then makes it
# persistent). Independent of whether a stock launcher is still in the image.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/preferred-apps/phonevault-home.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/preferred-apps/phonevault-home.xml
