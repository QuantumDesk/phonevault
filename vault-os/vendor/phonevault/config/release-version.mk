# Phone Vault release identity: the single project-owned version file.
#
# PHONEVAULT_AVB_ROLLBACK_INDEX is the root vbmeta rollback index of every
# image (BoardConfigVault.mk). Once a relocked phone boots an image, the
# bootloader stores this index in tamper-evident storage and refuses any image
# with a lower one, so an older (vulnerable) signed release cannot be
# reinstalled. It replaces the inherited security-patch-date timestamp, which
# the project does not control and which does not change between two Phone
# Vault releases on the same Lineage base.
#
# Rules (enforced by scripts/sign-release.sh via verify-rollback-index.sh):
#   - bump it for EVERY production release; sign-release refuses an index that
#     is not strictly greater than the one in the previous signed
#     RELEASE-MANIFEST.txt, and refuses a vbmeta whose index differs from this
#     file;
#   - format YYYYMMDDNN (release date + two-digit serial): a decimal integer
#     that stays above the inherited 2026 security-patch timestamps (~1.8e9),
#     so no phone that ever booted a timestamp-indexed image is locked out;
#   - never decrease it, never reuse a value.
PHONEVAULT_VERSION ?= 0.1.0-dev
PHONEVAULT_AVB_ROLLBACK_INDEX := 2026101300
