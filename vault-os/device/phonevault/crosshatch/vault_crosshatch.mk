# Phone Vault resources take precedence over every inherited overlay. The earliest entry in
# PRODUCT_PACKAGE_OVERLAYS wins, and a product's own value set before its first
# inherit-product lands ahead of all inherited ones. Set in common.mk (evaluated last), the
# overlay lost to vendor/lineage/overlay/common: the default wallpaper change never reached
# the image (rung 2d-c/2d-c2 still shipped the old padlock).
PRODUCT_PACKAGE_OVERLAYS += \
    vendor/phonevault/overlay

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
