# Development rung (crosshatch): minimal product (base + signer app) plus boot-diagnosis
# properties (insecure adb, a pre-authorised adb host, verbose logging). Never a release config.
PHONEVAULT_VERSION ?= 0.1.0-dev
PRODUCT_PACKAGES += \
    PhoneVault

# --- development only (boot diagnosis; the release config has none of this) ---
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
