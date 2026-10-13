# RUNG b4a (bluejay): this file = b3. b4a's changes (radios: drivers, services, features) are in
# BoardConfigVault.mk, Android.bp and the device/vendor/kernel-list diffs.
# RUNG b3 (bluejay): b2 + USB lock-down (vendor-google-bluejay.diff: gadget function instances
# limited to AOA (+ adb while debuggable), Type-C port pinned sink/UFP with root-only role nodes;
# device-google-gs101.diff: no android.hardware.usb.host feature). b2: kernel hardening slice 1
# (BoardConfigVault.mk). b1: factory-boot wake-up fix, no launcher, our AVB dev key, keyguard clock
# hidden, no Lineage "Discover Trust". Development image only (userdebug, insecure adb).
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

# Rung b3: the release vendor property that switches the Phone Vault USB policy on in a patched
# USB HAL (crosshatch device patches 0002/0003). On bluejay both USB HALs are Google prebuilts
# (android.hardware.usb{,.gadget}-service.gs101 from CP2A.260705.006) and do not read it: the b3
# policy is enforced by init.gs101.usb.rc / ueventd.rc instead. Set for parity with the release
# intent and for a later source-built HAL; it changes nothing on its own.
PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.phonevault.offline=true

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
