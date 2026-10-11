PRODUCT_MAKEFILES := \
    $(LOCAL_DIR)/vault_bluejay.mk

# Lineage 24.0 (Android 17) release config: vendor/lineage/vars/aosp_target_release = cp2a.
COMMON_LUNCH_CHOICES := \
    vault_bluejay-cp2a-user \
    vault_bluejay-cp2a-userdebug
