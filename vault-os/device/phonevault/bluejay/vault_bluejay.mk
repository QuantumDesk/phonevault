# Phone Vault on the Pixel 6a (bluejay, gs101), LineageOS 24.0 / Android 17. See
# vault-os/docs/port-bluejay.md.
#
# Phone Vault resources take precedence over every inherited overlay. The earliest entry in
# PRODUCT_PACKAGE_OVERLAYS wins, and a product's own value set before its first
# inherit-product lands ahead of all inherited ones (crosshatch rung 2d-c3 lesson: otherwise
# vendor/lineage/overlay/common's default_wallpaper wins).
#
# device/phonevault/bluejay/overlay holds what only applies to the Lineage 24.0 tree (the
# lineage-sdk service list, which differs from crosshatch's 22.2); it comes first.
PRODUCT_PACKAGE_OVERLAYS += \
    device/phonevault/bluejay/overlay \
    vendor/phonevault/overlay

# No Lineage Trust interface: the overlay above leaves TrustInterfaceService out of the
# lineage-sdk services (it posts the "Discover Trust" notification on every boot), and this
# withdraws its feature so TrustInterface clients see "unavailable" rather than throwing.
PRODUCT_COPY_FILES += \
    device/phonevault/bluejay/sysconfig/phonevault-no-lineage-trust.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/phonevault-no-lineage-trust.xml

# lineage_bluejay.mk already inherits vendor/google/bluejay/bluejay-vendor.mk (CP2A.260705.006
# blobs); do not inherit it a second time.
$(call inherit-product, device/google/bluejay/lineage_bluejay.mk)

PRODUCT_BRAND := PhoneVault
PRODUCT_MANUFACTURER := PhoneVault Project
PRODUCT_MODEL := Pixel 6a Vault
PRODUCT_NAME := vault_bluejay
PRODUCT_DEVICE := bluejay
LINEAGE_BUILD := bluejay

TARGET_SCREEN_HEIGHT := 2400
TARGET_SCREEN_WIDTH := 1080

# Appliance removals must be evaluated after every upstream and proprietary
# package list has been inherited.
$(call inherit-product, vendor/phonevault/config/common.mk)
