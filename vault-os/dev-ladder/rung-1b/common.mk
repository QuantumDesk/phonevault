# DEBUG-47: minimal (base + app) + boot-diagnosis props (adb auto-auth + verbose)
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- boot diagnosis only (to be removed) ---
PRODUCT_PROPERTY_OVERRIDES += \
    persist.sys.usb.config=adb \
    ro.adb.secure=0 \
    persist.adb.notify=0 \
    persist.log.tag=V

# --- boot diagnosis: auto-authorize the build host over adb (userdebug only) ---
PRODUCT_ADB_KEYS := vendor/phonevault/config/debug_adbkey.pub

# --- Phone Vault branding ---
PRODUCT_PACKAGE_OVERLAYS += vendor/phonevault/overlay
PRODUCT_SYSTEM_PROPERTIES += \
    ro.phonevault.version=0.1.0 \
    ro.phonevault.brand=PhoneVault
