# DEBUG-47: minimal (base + app) + boot-diagnosis props (adb auto-auth + verbose)
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- boot diagnosis only (to be removed) ---
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.usb.config=adb \
    ro.adb.secure=0 \
    persist.adb.notify=0

# --- boot diagnosis: auto-authorize the build host over adb (userdebug only) ---
PRODUCT_ADB_KEYS := vendor/phonevault/config/debug_adbkey.pub

# --- Phone Vault branding ---
PRODUCT_PACKAGE_OVERLAYS += vendor/phonevault/overlay
PRODUCT_SYSTEM_PROPERTIES += \
    ro.phonevault.version=0.1.0 \
    ro.phonevault.brand=PhoneVault

# HOME from the first boot: the framework applies etc/preferred-apps before any app runs, so a
# genuine first boot never shows a launcher chooser (device-owner provisioning then makes it
# persistent). Independent of whether a stock launcher is still in the image.
PRODUCT_COPY_FILES += \
    vendor/phonevault/prebuilt/preferred-apps/phonevault-home.xml:$(TARGET_COPY_OUT_SYSTEM)/etc/preferred-apps/phonevault-home.xml
