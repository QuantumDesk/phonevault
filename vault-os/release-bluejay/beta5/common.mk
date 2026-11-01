# Phone Vault BETA 4 for the Pixel 6a (bluejay), LineageOS 24.0 / Android 17: product policy.
#
# Installed in the build tree as vendor/phonevault/config/common.mk by release-bluejay/sync-beta.sh
# (the bluejay product, device/phonevault/bluejay/vault_bluejay.mk, inherits it last).
#
# = dev-ladder-bluejay/rung-b4d-1/common.mk (passed on hardware 2026-10-18) with every
# development deviation removed:
#   - no persist.sys.usb.config=adb, ro.adb.secure=0, persist.adb.notify=0;
#   - no PRODUCT_ADB_KEYS / PV_DEV_ADB_KEY: no host is pre-authorised, no adb_keys file ships;
#   - built `user` (build-beta.sh lunches vault_bluejay-cp2a-user, WITH_ADB_INSECURE unset), so
#     Lineage's common.mk sets ro.adb.secure=1 and the build sets ro.debuggable=0, ro.secure=1.
# Everything else (the b1 sysconfig and preferred HOME, b3 offline property, b4a radio-feature
# sysconfig) is the rung's, unchanged. The rest of b2..b4d-1 lives in BoardConfigVault.mk
# (kernel, AVB, cmdline) and in the base rung's Android.bp, overlay and upstream diffs
# (release-bluejay/README.md, "What beta1 carries").
#
# beta2 = beta1 (this file differs only in the version and channel) + the USB charging
# composition fix: config.xml sets config_usbChargingFunctionsAccessory (frameworks-base-a17
# patch 0006), so with adb off the phone enumerates as the accessory instead of trying MTP,
# which b3 removed (release-bluejay/README.md, "beta2").
#
# beta3 = beta2 (the beta3 files are beta2's apart from the beta name, and here the version and
# channel) + the current signer app from main, which reopens a still-attached accessory after a
# lock and on start (stale-session recovery without a replug; release-bluejay/README.md, "beta3").
#
# beta4 = beta3 (the beta4 files are beta3's apart from the beta name, and here the version and
# channel) + the current signer app from main (0.3.1, code 4): a request that arrives on the
# credential locked page is held and shown ("INCOMING REQUEST") across a relock, a dismissed PIN
# prompt no longer wedges the next sensitive action, and the host's USB recovery waits for the
# phone's own re-attach. The AVB rollback index (release-version.mk) is raised above beta3's
# (release-bluejay/README.md, "beta4").
#
# beta5 = beta4 (the beta5 files are beta4's apart from the beta name, and here the version and
# channel) + the current signer app from main (0.3.2, code 5): the system PIN prompt says a request
# is waiting, screen brightness, Power -> Restart, screen timeout / idle lock choices, a short
# "lock after screen off" grace, guessable PINs refused at SET PIN, and the accessory reopened
# after the host gave up on a request (stale descriptor after a bus reset). The AVB rollback index
# (release-version.mk) is raised above beta4's (release-bluejay/README.md, "beta5").
PRODUCT_PACKAGES += \
    PhoneVault

# Project-owned version and AVB rollback index (bumped once per release). The beta names itself
# before the include (release-version.mk only defaults PHONEVAULT_VERSION).
PHONEVAULT_VERSION := 0.1.0-beta5
include vendor/phonevault/config/release-version.mk

# --- release USB / adb policy ---
# adb is never a default USB function. The b3 gadget rc (vendor-google-bluejay.diff) creates the
# ffs.adb instance only on `early-boot && property:ro.debuggable=1`, which a user build never
# satisfies, so adbd has no endpoint even if something asked for it; the signer app (release
# build) also sets DISALLOW_DEBUGGING_FEATURES as device owner.
# Properties go to /product: gs101 enforces generic_system's artifact path requirement, and
# /product is loaded last by init, so this value is also the effective one.
PRODUCT_PRODUCT_PROPERTIES += \
    persist.sys.usb.config=none

# Rung b3: the release vendor property that switches the Phone Vault USB policy on in a patched
# USB HAL (crosshatch device patches 0002/0003). On bluejay both USB HALs are Google prebuilts
# and do not read it: the b3 policy is enforced by init.gs101.usb.rc / ueventd.rc instead.
PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.phonevault.offline=true

# --- Phone Vault branding ---
# The resource overlay is added by device/phonevault/bluejay/vault_bluejay.mk ahead of its
# inherits so it outranks Lineage's overlays; listing it here too would duplicate the directory.
PRODUCT_PRODUCT_PROPERTIES += \
    ro.phonevault.version=$(PHONEVAULT_VERSION) \
    ro.phonevault.brand=PhoneVault \
    ro.phonevault.channel=beta5

# HOME from the first boot (b0/b1): the framework applies etc/preferred-apps before any app runs.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/preferred-apps/phonevault-home.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/preferred-apps/phonevault-home.xml

# b1: the signer is never scanned "stopped" (frameworks/base 0003 unstops the owner itself too).
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/sysconfig/phonevault-initial-package-state.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/phonevault-initial-package-state.xml

# b4a: the Bluetooth/NFC/OMAPI/GPS features are withdrawn (handheld_core_hardware.xml itself
# declares android.hardware.bluetooth, so dropping the feature files is not enough).
PRODUCT_COPY_FILES += \
    device/phonevault/bluejay/sysconfig/phonevault-no-radios.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/phonevault-no-radios.xml
