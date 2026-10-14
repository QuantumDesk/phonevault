# Development rung (crosshatch): minimal product (base + signer app) plus boot-diagnosis
# properties (insecure adb, a pre-authorised adb host, verbose logging). Never a release config.
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- development only (boot diagnosis; the release config has none of this) ---
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
