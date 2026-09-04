$(call inherit-product, device/google/crosshatch/lineage_crosshatch.mk)

PRODUCT_BRAND := PhoneVault
PRODUCT_MANUFACTURER := PhoneVault Project
PRODUCT_MODEL := Pixel 3 XL Vault
PRODUCT_NAME := vault_crosshatch
PRODUCT_DEVICE := crosshatch
LINEAGE_BUILD := crosshatch

TARGET_SCREEN_HEIGHT := 2960
TARGET_SCREEN_WIDTH := 1440

PRODUCT_BUILD_PROP_OVERRIDES += \
    DeviceProduct=crosshatch

$(call inherit-product, vendor/google/crosshatch/crosshatch-vendor.mk)

# Appliance removals must be evaluated after every upstream and proprietary
# package list has been inherited.
$(call inherit-product, vendor/phonevault/config/common.mk)
