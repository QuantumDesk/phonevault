#!/usr/bin/env bash
set -euo pipefail

REPOSITORY_ROOT="${1:-$(cd "$(dirname "$0")/../.." && pwd)}"

python3 - "${REPOSITORY_ROOT}" <<'PY'
import pathlib
import re
import sys
import xml.etree.ElementTree as ET

root = pathlib.Path(sys.argv[1]).resolve()
android_ns = "{http://schemas.android.com/apk/res/android}"


def fail(message: str) -> None:
    raise SystemExit(f"owner provisioning policy failed: {message}")


def read(relative: str) -> str:
    path = root / relative
    if not path.is_file():
        fail(f"missing {relative}")
    return path.read_text(encoding="utf-8")


def parse_xml(relative: str) -> ET.Element:
    try:
        return ET.fromstring(read(relative))
    except ET.ParseError as error:
        fail(f"invalid XML in {relative}: {error}")


package_name = "dev.phonevault.signer"
admin_class = ".VaultDeviceAdminReceiver"
home_class = ".MainActivity"
admin_component = f"{package_name}/{admin_class}"

gradle = read("app/build.gradle")
for label, pattern in (
    ("namespace", rf"\bnamespace\s+['\"]{re.escape(package_name)}['\"]"),
    ("applicationId", rf"\bapplicationId\s+['\"]{re.escape(package_name)}['\"]"),
):
    if not re.search(pattern, gradle):
        fail(f"app {label} is not exactly {package_name}")

manifest = parse_xml("app/src/main/AndroidManifest.xml")
feature = next(
    (
        node
        for node in manifest.findall("uses-feature")
        if node.get(android_ns + "name") == "android.hardware.usb.accessory"
    ),
    None,
)
if feature is None or feature.get(android_ns + "required") != "true":
    fail("USB accessory support is not required by the signer manifest")

application = manifest.find("application")
if application is None:
    fail("signer manifest has no application")


def component(tag: str, class_name: str) -> ET.Element:
    node = next(
        (
            candidate
            for candidate in application.findall(tag)
            if candidate.get(android_ns + "name") == class_name
        ),
        None,
    )
    if node is None:
        fail(f"manifest is missing {class_name}")
    return node


home = component("activity", home_class)
if home.get(android_ns + "exported") != "true":
    fail("HOME activity must be exported")
home_filter_valid = False
for intent_filter in home.findall("intent-filter"):
    actions = {
        item.get(android_ns + "name") for item in intent_filter.findall("action")
    }
    categories = {
        item.get(android_ns + "name") for item in intent_filter.findall("category")
    }
    if "android.intent.action.MAIN" in actions and {
        "android.intent.category.HOME",
        "android.intent.category.DEFAULT",
    }.issubset(categories):
        home_filter_valid = True
        break
if not home_filter_valid:
    fail("MainActivity is not an exact MAIN/HOME/DEFAULT target")

receiver = component("receiver", admin_class)
if receiver.get(android_ns + "exported") != "true":
    fail("device-admin receiver must be exported")
if receiver.get(android_ns + "permission") != "android.permission.BIND_DEVICE_ADMIN":
    fail("device-admin receiver lacks BIND_DEVICE_ADMIN")
metadata = {
    item.get(android_ns + "name"): item.get(android_ns + "resource")
    for item in receiver.findall("meta-data")
}
if metadata.get("android.app.device_admin") != "@xml/device_admin":
    fail("device-admin receiver has no exact device-admin metadata")
admin_actions = {
    item.get(android_ns + "name")
    for intent_filter in receiver.findall("intent-filter")
    for item in intent_filter.findall("action")
}
if "android.app.action.DEVICE_ADMIN_ENABLED" not in admin_actions:
    fail("device-admin receiver lacks DEVICE_ADMIN_ENABLED")

device_admin = parse_xml("app/src/main/res/xml/device_admin.xml")
if device_admin.tag != "device-admin" or device_admin.find("uses-policies") is None:
    fail("device_admin.xml is not a valid empty-policy device-admin declaration")

overlay = parse_xml(
    "vault-os/vendor/phonevault/overlay/frameworks/base/core/res/res/values/config.xml"
)
owner_resources = [
    item
    for item in overlay.findall("string")
    if item.get("name") == "config_fixedFunctionDeviceOwner"
]
if len(owner_resources) != 1:
    fail("overlay must define config_fixedFunctionDeviceOwner exactly once")
owner_resource = owner_resources[0]
if (owner_resource.text or "").strip() != admin_component:
    fail(f"configured owner is not exactly {admin_component}")
if owner_resource.get("translatable") != "false":
    fail("configured owner resource must be non-translatable")

blueprint = read("vault-os/vendor/phonevault/prebuilt/Android.bp")
module_start = blueprint.find("android_app_import {")
if module_start < 0:
    fail("PhoneVault android_app_import is missing")
depth = 0
module_end = None
for index in range(module_start, len(blueprint)):
    if blueprint[index] == "{":
        depth += 1
    elif blueprint[index] == "}":
        depth -= 1
        if depth == 0:
            module_end = index + 1
            break
if module_end is None:
    fail("PhoneVault android_app_import is unterminated")
module = blueprint[module_start:module_end]
for field, value in (
    ("name", '"PhoneVault"'),
    ("apk", '"PhoneVault.apk"'),
    ("presigned", "true"),
    ("preprocessed", "true"),
    ("privileged", "false"),
):
    if not re.search(rf"(?m)^\s*{field}:\s*{re.escape(value)},?\s*$", module):
        fail(f"PhoneVault module does not enforce {field}: {value}")

product = read("vault-os/vendor/phonevault/config/common.mk")
if not re.search(r"(?ms)^PRODUCT_PACKAGES\s*\+=.*?^\s*PhoneVault\s*$", product):
    fail("PhoneVault is not installed by the product")
if not re.search(
    r"(?ms)^PRODUCT_PACKAGE_OVERLAYS\s*\+=.*?^\s*vendor/phonevault/overlay\s*$",
    product,
):
    fail("PhoneVault resource overlay is not installed by the product")

policy_patch = read(
    "vault-os/patches/frameworks-base/0003-provision-configured-appliance-owner.patch"
)
added = "\n".join(
    line[1:]
    for line in policy_patch.splitlines()
    if line.startswith("+") and not line.startswith("+++")
)
required_fragments = (
    "provisionConfiguredFixedFunctionOwner();",
    "config_fixedFunctionDeviceOwner",
    "ComponentName.unflattenFromString(configuredComponent)",
    "ownerInfo == null || !ownerInfo.isSystemApp()",
    "ownerInfo.isPrivilegedApp()",
    "mOwners.hasDeviceOwner()",
    "admin.equals(mOwners.getDeviceOwnerComponent())",
    "mOwners.hasProfileOwner(UserHandle.USER_SYSTEM)",
    "hasUserSetupCompleted(UserHandle.USER_SYSTEM)",
    "setActiveAdmin(admin, /* refreshing= */ false, UserHandle.USER_SYSTEM",
    "setDeviceOwner(admin, UserHandle.USER_SYSTEM",
    "} else {\n                mInjector.settingsSecurePutIntForUser(\n                        USER_SETUP_COMPLETE, 1, UserHandle.USER_SYSTEM)",
    "settingsGlobalPutInt(Settings.Global.DEVICE_PROVISIONED, 1)",
    "catch (RuntimeException e)",
)
for fragment in required_fragments:
    if fragment not in added:
        fail(f"framework patch lacks fail-closed invariant: {fragment}")
if added.index("setActiveAdmin(admin") > added.index("setDeviceOwner(admin"):
    fail("framework patch sets device owner before activating the admin")
if added.index("setDeviceOwner(admin") > added.index("settingsSecurePutIntForUser("):
    fail("framework patch completes setup before creating the device owner")
if added.index("hasUserSetupCompleted(UserHandle.USER_SYSTEM)") > added.index(
    "setActiveAdmin(admin"
):
    fail("framework patch checks setup completion after activating the admin")

symbol_patch = read(
    "vault-os/patches/frameworks-base/0004-export-fixed-function-owner-resource.patch"
)
symbol_added = "\n".join(
    line[1:]
    for line in symbol_patch.splitlines()
    if line.startswith("+") and not line.startswith("+++")
)
if '<java-symbol type="string" name="config_fixedFunctionDeviceOwner" />' not in symbol_added:
    fail("framework resource export is missing")

print(
    "Owner provisioning policy passed: ordinary system app, exact admin/HOME "
    "component, and fail-closed first-boot provisioning."
)
PY
