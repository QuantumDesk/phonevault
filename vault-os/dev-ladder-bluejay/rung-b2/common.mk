# RUNG b2 (bluejay): b1 + kernel hardening slice 1, all in BoardConfigVault.mk (unused GKI and
# vendor modules left out of the image, usbcore.authorized_default=0). This file = b1:
# factory-boot wake-up fix, no launcher, keyguard clock hidden (frameworks/base 0005 + SystemUI
# overlay), no Lineage "Discover Trust" notification (device/phonevault/bluejay overlay). Radios,
# camera, sensors etc. stay until later rungs. Development image only (userdebug, insecure adb).
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- development only (removed by the user-build rung b8) ---
# build-rung.sh also exports WITH_ADB_INSECURE=true: without it Lineage's common.mk sets
# ro.adb.secure=1 AND PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG (ro.debuggable=0) on userdebug.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.usb.config=adb \
    ro.adb.secure=0 \
    persist.adb.notify=0

# --- development only: pre-authorise the builder's adb host ---
# PV_DEV_ADB_KEY: the builder's adb public key (adb's adbkey.pub). The rung sync script requires it
# and installs it at the in-tree default below; an absolute path in the build environment works
# too. The release config never carries adb keys (verify-release-source.sh refuses them).
PV_DEV_ADB_KEY ?= vendor/phonevault/config/debug_adbkey.pub
ifeq ($(wildcard $(PV_DEV_ADB_KEY)),)
$(error PV_DEV_ADB_KEY: no adb public key at '$(PV_DEV_ADB_KEY)'; set PV_DEV_ADB_KEY to your adb public key (absolute path) and re-run the rung sync)
endif
PRODUCT_ADB_KEYS := $(PV_DEV_ADB_KEY)

# --- Phone Vault branding ---
# The resource overlay is added by device/phonevault/bluejay/vault_bluejay.mk ahead of its
# inherits so it outranks Lineage's overlays; listing it here too would duplicate the directory.
# gs101 enforces generic_system.mk's artifact path requirement: nothing product-specific on
# /system (no PRODUCT_SYSTEM_PROPERTIES, no system/ files). Properties go to /product.
PRODUCT_PRODUCT_PROPERTIES += \
    ro.phonevault.version=0.1.0 \
    ro.phonevault.brand=PhoneVault

# HOME from the first boot: the framework applies etc/preferred-apps before any app runs, so a
# genuine first boot never shows a launcher chooser (device-owner provisioning then makes it
# persistent). b1 also removes the launcher (Android.bp overrides), so HOME has one candidate.
# Android 17's PackageManager Settings reads etc/preferred-apps from every system partition.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/preferred-apps/phonevault-home.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/preferred-apps/phonevault-home.xml

# Rung b1: the signer is never scanned "stopped" (config_stopSystemPackagesByDefault would stop
# it on first boot because it has a launcher activity, and broadcasts skip stopped packages).
# frameworks/base 0003 also unstops the configured owner itself; this is the product-level half.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/sysconfig/phonevault-initial-package-state.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/phonevault-initial-package-state.xml
