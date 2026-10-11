# DEBUG-47: minimal (base + app) + boot-diagnosis props (adb auto-auth + verbose)
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- boot diagnosis only (to be removed) ---
# Rung 3: the default USB function on this dev image is adb and nothing else (the gadget HAL now
# rejects every composition outside {none, accessory, adb, accessory+adb}; adb only while
# ro.debuggable=1). The user build (rung 5) sets persist.sys.usb.config=none: no gadget function
# until a desktop starts AOA, which links accessory only.
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.usb.config=adb \
    ro.adb.secure=0 \
    persist.adb.notify=0

# Rung 3: activates the appliance USB policy in the vendor USB HALs (release device-crosshatch
# patches 0002/0003 + the rung's port-policy additions): gadget function allowlist, no vendor
# diag/serial/rmnet functions, no host/source role, port reported UFP-only. Same vendor property
# the release common.mk sets; in this tree only those two HALs read it.
PRODUCT_VENDOR_PROPERTIES += \
    ro.vendor.phonevault.offline=true

# --- boot diagnosis: auto-authorize the build host over adb (userdebug only) ---
PRODUCT_ADB_KEYS := vendor/phonevault/config/debug_adbkey.pub

# --- Phone Vault branding ---
# (2d-c3: the resource overlay is added by device/phonevault/crosshatch/vault_crosshatch.mk, ahead
# of Lineage's overlays; listing it here too would duplicate the directory.)
PRODUCT_SYSTEM_PROPERTIES += \
    ro.phonevault.version=0.1.0 \
    ro.phonevault.brand=PhoneVault

# HOME from the first boot: the framework applies etc/preferred-apps before any app runs, so a
# genuine first boot never shows a launcher chooser (device-owner provisioning then makes it
# persistent). Independent of whether a stock launcher is still in the image.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/preferred-apps/phonevault-home.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/preferred-apps/phonevault-home.xml
