# RUNG b1 (bluejay): b0 + factory-boot wake-up fix, no launcher, our AVB dev key
# (BoardConfigVault.mk), keyguard clock hidden (frameworks/base 0005 + SystemUI overlay), no
# Lineage "Discover Trust" notification (device/phonevault/bluejay overlay). Everything else is
# stock Lineage bluejay: radios, camera, sensors etc. stay until b3+. Development image only
# (userdebug, insecure adb).
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

# Pre-authorised dev hosts: the build box (root@cachy-mac) and the owner's Mac.
PRODUCT_ADB_KEYS := vendor/phonevault/config/debug_adbkey.pub

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
