# Fixed-function signing appliance. Upstream package removal is enforced by
# PhoneVault's Soong `overrides` list and verified against target-files. Make
# package subtraction is intentionally not used: inherited product lists may
# be expanded after this file is evaluated.

PRODUCT_PACKAGES += \
    PhoneVault

PHONEVAULT_VERSION ?= 0.1.0-dev

PRODUCT_PACKAGE_OVERLAYS += \
    vendor/phonevault/overlay

PRODUCT_NO_CAMERA := true
PRODUCT_NO_DYNAMIC_SYSTEM_UPDATE := true
TARGET_EXCLUDES_AUDIOFX := true
TARGET_DISABLE_LINEAGE_SDK := true

# DEBUG-39: FusedLocation+Telecom restored (test system_server boot crash)
#PRODUCT_SYSTEM_SERVER_APPS -= \
#    FusedLocation \
#    Telecom

PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
    config.disable_cameraservice=true \
    config.disable_networktime=true \
    ro.phonevault.offline=true \
    ro.phonevault.version=$(PHONEVAULT_VERSION) \
    persist.sys.usb.config=adb   # DEBUG-38: temporary, revert to none for release

PRODUCT_SYSTEM_PROPERTIES += \
    ro.radio.noril=true

# Vendor HALs must not depend on access to a system-private property namespace.
# This immutable vendor property independently activates their appliance
# restrictions under Treble property isolation.
PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.phonevault.offline=true

# DEBUG-41: early-adb rc to capture the post-fs-data crash (remove for release)
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/zzz-debug-earlyadb.rc:$(TARGET_COPY_OUT_SYSTEM)/etc/init/zzz-debug-earlyadb.rc
