#!/usr/bin/env python3
"""Require package and kernel removals to have release-gate coverage."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
BLUEPRINT = ROOT / "vendor/phonevault/prebuilt/Android.bp"
POLICY = ROOT / "policy/forbidden-target-files.regex"
KERNEL_POLICY = ROOT / "policy/forbidden-kernel-config.regex"
KERNEL_PATCH = (
    ROOT
    / "patches/kernel-crosshatch/0001-add-phonevault-appliance-defconfig.patch"
)
CORE_NETWORK_PATCH = (
    ROOT / "patches/appliance/0013-disable-core-network-daemons.patch"
)
CONNECTIVITY_APEX_PATCH = (
    ROOT / "patches/appliance/0014-strip-connectivity-apex-runtime.patch"
)
CONNECTIVITY_APEX_POLICY = ROOT / "policy/forbidden-connectivity-apex.regex"
MODULAR_SERVICES_PATCH = (
    ROOT / "patches/appliance/0015-disable-modular-consumer-services.patch"
)
TEXT_CLASSIFIER_PATCH = (
    ROOT / "patches/appliance/0018-disable-system-text-classifier-service.patch"
)
APPLIANCE_PATCH_DIR = ROOT / "patches/appliance"
WIRELESS_APEX_PATCH = (
    ROOT / "patches/appliance/0016-strip-wireless-classpath-apexes.patch"
)
WIRELESS_APEX_POLICY = ROOT / "policy/forbidden-wireless-apex.regex"
MEDIA_APEX_PATCH = (
    ROOT / "patches/appliance/0017-strip-media-classpath-apexes.patch"
)
MEDIA_APEX_POLICY = ROOT / "policy/forbidden-media-apex.regex"
DIAGNOSTICS_PATCH = (
    ROOT / "patches/appliance/0019-disable-persistent-system-tracing.patch"
)
DEVICE_AUDIT = ROOT / "scripts/audit-development-device.sh"
PRODUCT_CONFIG = ROOT / "vendor/phonevault/config/common.mk"

blueprint = BLUEPRINT.read_text(encoding="utf-8")
overrides_block = re.search(r"overrides:\s*\[(.*?)\]", blueprint, re.DOTALL)
if overrides_block is None:
    raise SystemExit("PhoneVault overrides list was not found")

overrides = re.findall(r'"([^"]+)"', overrides_block.group(1))
patterns = [
    re.compile(line, re.IGNORECASE)
    for line in POLICY.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
]

uncovered = []
for module in overrides:
    representative_paths = (
        f"SYSTEM/app/{module}/{module}.apk",
        f"SYSTEM/bin/{module}",
        f"VENDOR/bin/{module}",
        f"VENDOR/etc/init/{module}.rc",
    )
    if not any(pattern.search(path) for pattern in patterns for path in representative_paths):
        uncovered.append(module)

if uncovered:
    print("module overrides without target-files policy coverage:", file=sys.stderr)
    print("\n".join(uncovered), file=sys.stderr)
    raise SystemExit(1)

print(f"Forbidden-artifact policy covers all {len(overrides)} module overrides.")

required_network_removals = {
    "bugreport",
    "bugreport_procdump",
    "bugreportz",
    "dnsmasq",
    "dumpstate",
    "ip",
    "iptables",
    "mdnsd",
    "ndc",
    "netd",
    "ping",
    "ping6",
    "ss",
    "tc",
    "com.android.rkpd",
    "com.android.resolv",
}
missing_network_removals = sorted(required_network_removals.difference(overrides))
if missing_network_removals:
    print("missing core network removal overrides:", file=sys.stderr)
    print("\n".join(missing_network_removals), file=sys.stderr)
    raise SystemExit(1)

core_network_patch = CORE_NETWORK_PATCH.read_text(encoding="utf-8")
for required_gate in (
    "+on bpf-progs-loaded && property:ro.phonevault.offline=false",
):
    if required_gate not in core_network_patch:
        raise SystemExit(f"missing immutable core network init gate: {required_gate}")

print("Core network daemons/tools are removed and init starts are appliance-gated.")

required_diagnostic_removals = {
    "dmesgd",
    "heapprofd",
    "heapprofd_client",
    "incident",
    "incident-helper-cmd",
    "incident_report",
    "incidentd",
    "incident_helper",
    "perfetto",
    "perfetto-extras",
    "traced",
    "traced_probes",
}
missing_diagnostic_removals = sorted(required_diagnostic_removals.difference(overrides))
if missing_diagnostic_removals:
    raise SystemExit(
        "missing diagnostic removal overrides: " + ", ".join(missing_diagnostic_removals)
    )
diagnostics_patch = DIAGNOSTICS_PATCH.read_text(encoding="utf-8")
if "-PRODUCT_SYSTEM_PROPERTIES += persist.traced.enable=1" not in diagnostics_patch:
    raise SystemExit("persistent system tracing property is not removed")
device_audit = DEVICE_AUDIT.read_text(encoding="utf-8")
for runtime_token in (
    "dmesgd",
    "heapprofd",
    "incidentd",
    "perfetto",
    "traced(_probes)?",
    "adservices",
    "appsearch",
    "device_lock",
    "healthconnect",
    "on_device_personalization",
    "reboot_readiness",
    "sdk_sandbox",
    "persist\\.traced\\.enable",
):
    if runtime_token not in device_audit:
        raise SystemExit(f"development-device audit lacks runtime rejection: {runtime_token}")

print("Incident, heap-profile, and tracing runtimes are excluded.")

connectivity_apex_patch = CONNECTIVITY_APEX_PATCH.read_text(encoding="utf-8")
connectivity_apex_lines = [
    line
    for line in CONNECTIVITY_APEX_POLICY.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
]
connectivity_apex_patterns = [
    re.compile(line, re.IGNORECASE)
    for line in connectivity_apex_lines
    if not line.startswith("!")
]
connectivity_apex_permitted = [
    re.compile(line[1:]) for line in connectivity_apex_lines if line.startswith("!")
]
# The tethering service application and Cronet native runtime are removed from
# the APEX defaults; the resource-only ServiceConnectivityResources APK stays
# because service-connectivity compiles against its resource identifiers, and
# it is exempted by exact path only.
for removed_apex_default in ('"TetheringNext"', '"cronet_aml_components_cronet_android_cronet"'):
    if not re.search(rf'^-.*{re.escape(removed_apex_default)}', connectivity_apex_patch, re.MULTILINE):
        raise SystemExit(f"connectivity APEX defaults still ship: {removed_apex_default}")
if re.search(r'^-\s+"ServiceConnectivityResources",', connectivity_apex_patch, re.MULTILINE) \
        or '"ServiceConnectivityResources"' not in connectivity_apex_patch:
    raise SystemExit("connectivity APEX patch must retain the resource-only APK explicitly")
tethering_app_path = "priv-app/TetheringNext@BP1A.250505.005/TetheringNext.apk"
resources_app_path = (
    "priv-app/ServiceConnectivityResources@BP1A.250505.005/ServiceConnectivityResources.apk"
)
if not any(pattern.search(tethering_app_path) for pattern in connectivity_apex_patterns):
    raise SystemExit("connectivity APEX policy does not forbid priv-app payloads")
if any(pattern.search(tethering_app_path) for pattern in connectivity_apex_permitted):
    raise SystemExit("connectivity APEX permitted patterns exempt the tethering application")
if not any(pattern.search(resources_app_path) for pattern in connectivity_apex_permitted):
    raise SystemExit("connectivity APEX policy does not exempt the exact resources APK path")
if len(connectivity_apex_permitted) != 1:
    raise SystemExit("connectivity APEX policy must carry exactly one permitted pattern")
required_embedded_removals = {
    "bin/clatd",
    "bin/ethtool",
    "bin/netbpfload",
    "bin/ot-daemon",
    "etc/bpf/clatd.o",
    "etc/bpf/dscpPolicy.o",
    "etc/bpf/netd.o",
    "etc/bpf/offload.o",
    "etc/bpf/offload@mainline.o",
    "etc/bpf/test.o",
    "etc/bpf/test@mainline.o",
    "etc/netbpfload.33rc",
    "etc/netbpfload.35rc",
    "etc/ot-daemon.34rc",
}
for embedded_path in sorted(required_embedded_removals):
    module_name = embedded_path.rsplit("/", 1)[-1]
    if module_name.endswith(".apk"):
        module_name = module_name.removesuffix(".apk")
    if not any(pattern.search(embedded_path) for pattern in connectivity_apex_patterns):
        raise SystemExit(
            f"connectivity APEX removal lacks embedded policy coverage: {embedded_path}"
        )
    if f'-        "{module_name}",' not in connectivity_apex_patch:
        raise SystemExit(
            f"connectivity APEX strip patch does not remove module: {module_name}"
        )

print("Connectivity compatibility APEX runtime removals are policy-covered.")

modular_services_patch = MODULAR_SERVICES_PATCH.read_text(encoding="utf-8")
for required_runtime_gate in (
    "No Bluetooth Service (Phone Vault appliance)",
    "StartWifi",
    "StartStatsCompanion",
    "StarSdkSandboxManagerService",
    "StartAdServicesManagerService",
    "StartOnDevicePersonalizationSystemService",
    "GameManagerService",
    "UwbService",
    "rangingStackEnabled",
    "StartSafetyCenterService",
    "AppSearchModule",
    "HealthConnectManagerService",
    "DeviceLockService",
):
    if required_runtime_gate not in modular_services_patch:
        raise SystemExit(
            f"missing Phone Vault modular service gate: {required_runtime_gate}"
        )
if modular_services_patch.count("+        if (!isPhoneVaultOffline) {") < 2:
    raise SystemExit("modular consumer services are not grouped under offline gates")

text_classifier_patch = TEXT_CLASSIFIER_PATCH.read_text(encoding="utf-8")
required_full_apex_removals = {
    "com.android.adservices",
    "com.android.appsearch",
    "com.android.devicelock",
    "com.android.extservices",
    "com.android.healthfitness",
    "com.android.media.swcodec",
    "com.android.neuralnetworks",
    "com.android.ondevicepersonalization",
    "com.android.resolv",
    "com.android.rkpd",
    "com.android.scheduling",
    "com.android.uwb",
    "com.android.virt",
}
for module in sorted(required_full_apex_removals):
    if module not in overrides:
        raise SystemExit(f"missing full modular product exclusion: {module}")
    representative_path = f"SYSTEM/apex/{module}.apex"
    if not any(pattern.search(representative_path) for pattern in patterns):
        raise SystemExit(f"full modular exclusion lacks artifact policy: {module}")

# The excluded APEXes' boot/system-server jar declarations in
# build/make/target/product/default_art_config.mk are deliberately retained.
# Soong analyzes every source bootclasspath_fragment/systemserverclasspath_fragment
# in the tree whether or not its APEX is installed, and fails the build with
# "... in contents must also be declared in PRODUCT_APEX_BOOT_JARS /
# PRODUCT_APEX_SYSTEM_SERVER_JARS" when a declaration is missing. Runtime
# BOOTCLASSPATH/SYSTEMSERVERCLASSPATH come only from installed APEX classpath
# protos, so an uninstalled module contributes nothing. Exclusion is therefore
# enforced by the PhoneVault module overrides and the target-files artifact
# policy, not by editing the classpath configuration.
for appliance_patch in sorted(APPLIANCE_PATCH_DIR.glob("*.patch")):
    if "default_art_config.mk" in appliance_patch.read_text(encoding="utf-8"):
        raise SystemExit(
            "appliance patch edits Android classpath declarations, which Soong "
            f"rejects for source APEX fragments: {appliance_patch.name}"
        )
if "+        boolean disableSystemTextClassifier = isPhoneVaultOffline ||" not in text_classifier_patch:
    raise SystemExit("external text-classifier service is not appliance-gated")

print("Unused modular APEXes are excluded; classpath declarations are retained for Soong.")

wireless_apex_patch = WIRELESS_APEX_PATCH.read_text(encoding="utf-8")
wireless_apex_lines = [
    line
    for line in WIRELESS_APEX_POLICY.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
]
wireless_apex_patterns = [
    re.compile(line, re.IGNORECASE)
    for line in wireless_apex_lines
    if not line.startswith("!")
]
wireless_apex_permitted = [
    re.compile(line[1:]) for line in wireless_apex_lines if line.startswith("!")
]
# wifi-service compiles against the resource-only ServiceWifiResources APK, so
# it stays in the Wi-Fi APEX and is exempted by exact path only.
if re.search(r'^-\s+"ServiceWifiResources",', wireless_apex_patch, re.MULTILINE) \
        or '"ServiceWifiResources"' not in wireless_apex_patch:
    raise SystemExit("wireless APEX patch must retain the resource-only Wi-Fi resources APK")
wifi_resources_path = "priv-app/ServiceWifiResources@BP1A.250505.005/ServiceWifiResources.apk"
wifi_dialog_path = "priv-app/WifiDialog@BP1A.250505.005/WifiDialog.apk"
if not any(pattern.search(wifi_resources_path) for pattern in wireless_apex_permitted):
    raise SystemExit("wireless APEX policy does not exempt the exact Wi-Fi resources APK path")
if any(pattern.search(wifi_dialog_path) for pattern in wireless_apex_permitted):
    raise SystemExit("wireless APEX permitted patterns exempt a Wi-Fi application")
if len(wireless_apex_permitted) != 1:
    raise SystemExit("wireless APEX policy must carry exactly one permitted pattern")
for retained_wireless_apex in ("com.android.btservices", "com.android.wifi"):
    if retained_wireless_apex in overrides:
        raise SystemExit(
            f"SystemUI-linked wireless classpath APEX was fully excluded: {retained_wireless_apex}"
        )

required_wireless_payload_removals = {
    "Bluetooth": "app/Bluetooth/Bluetooth.apk",
    "libbluetooth_jni": "lib64/libbluetooth_jni.so",
    "bt_stack.conf": "etc/bluetooth/bt_stack.conf",
    "OsuLogin": "app/OsuLogin/OsuLogin.apk",
    "WifiDialog": "app/WifiDialog/WifiDialog.apk",
    "wpa_supplicant_mainline": "bin/wpa_supplicant_mainline",
    "libservice-wifi-jni": "lib64/libservice-wifi-jni.so",
    "mainline_supplicant_rc": "etc/wifi/mainline_supplicant.rc",
}
for module, embedded_path in sorted(required_wireless_payload_removals.items()):
    if not re.search(rf'^-.*"{re.escape(module)}"', wireless_apex_patch, re.MULTILINE):
        raise SystemExit(f"wireless compatibility APEX does not remove: {module}")
    if not any(pattern.search(embedded_path) for pattern in wireless_apex_patterns):
        raise SystemExit(f"wireless APEX removal lacks payload policy: {module}")

print("SystemUI wireless API jars are retained without radio runtime payloads.")

media_apex_patch = MEDIA_APEX_PATCH.read_text(encoding="utf-8")
media_apex_patterns = [
    re.compile(line, re.IGNORECASE)
    for line in MEDIA_APEX_POLICY.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
]
required_media_payload_removals = {
    "MediaProvider": "app/MediaProvider/MediaProvider.apk",
    "Photopicker": "app/Photopicker/Photopicker.apk",
    "libpdfclient": "lib64/libpdfclient.so",
    "media_provider": "bin/media_provider",
    "mediatranscoding": "bin/mediatranscoding",
    "libaacextractor": "lib64/libaacextractor.so",
    "libmediaparser-jni": "lib64/libmediaparser-jni.so",
    "com.android.media-mediatranscoding.rc": "etc/com.android.media-mediatranscoding.rc",
}
for module, embedded_path in sorted(required_media_payload_removals.items()):
    if not re.search(rf'^-.*"{re.escape(module)}"', media_apex_patch, re.MULTILINE):
        raise SystemExit(f"media compatibility APEX does not remove: {module}")
    if not any(pattern.search(embedded_path) for pattern in media_apex_patterns):
        raise SystemExit(f"media APEX removal lacks payload policy: {module}")

print("Media API jars are retained without consumer application/runtime payloads.")

connectivity_native_paths = {
    "libservice-connectivity": "lib64/libservice-connectivity.so",
    "libservice-thread-jni": "lib64/libservice-thread-jni.so",
    "libnetd_updatable": "lib64/libnetd_updatable.so",
    "libframework-connectivity-jni": "lib64/libframework-connectivity-jni.so",
}
for module, embedded_path in sorted(connectivity_native_paths.items()):
    if not re.search(rf'^-.*"{re.escape(module)}"', connectivity_apex_patch, re.MULTILINE):
        raise SystemExit(f"connectivity native-runtime patch does not remove: {module}")
    if not any(pattern.search(embedded_path) for pattern in connectivity_apex_patterns):
        raise SystemExit(f"connectivity native removal lacks payload policy: {module}")

print("Retained connectivity classpath APEX has no application/radio native runtime.")

kernel_patterns = [
    re.compile(line)
    for line in KERNEL_POLICY.read_text(encoding="utf-8").splitlines()
    if line and not line.startswith("#")
]
disabled_kernel_symbols = re.findall(
    r"^\+\# (CONFIG_[A-Z0-9_]+) is not set$",
    KERNEL_PATCH.read_text(encoding="utf-8"),
    re.MULTILINE,
)
if not disabled_kernel_symbols:
    raise SystemExit("Phone Vault kernel fragment removals were not found")

uncovered_kernel_symbols = []
for symbol in disabled_kernel_symbols:
    enabled_forms = (f"{symbol}=y", f"{symbol}=m")
    if not all(
        any(pattern.search(enabled) for pattern in kernel_patterns)
        for enabled in enabled_forms
    ):
        uncovered_kernel_symbols.append(symbol)

if uncovered_kernel_symbols:
    print("disabled kernel symbols without release-policy coverage:", file=sys.stderr)
    print("\n".join(uncovered_kernel_symbols), file=sys.stderr)
    raise SystemExit(1)

print(
    "Forbidden-kernel policy covers all "
    f"{len(disabled_kernel_symbols)} disabled appliance symbols."
)

# Do not reintroduce legacy radio/network property namespaces merely to set
# them to a nominally disabled value. Their owning services and drivers are
# absent, and the final artifact gate requires the properties to be absent too.
product_config = PRODUCT_CONFIG.read_text(encoding="utf-8")
forbidden_product_properties = re.findall(
    r"^\s*(persist\.(?:camera|radio|rcs)(?:\.|=)[^\s\\]*|"
    r"persist\.vendor\.(?:cne|data\.iwlan|debug\.sensors|radio|sys\.modem)"
    r"(?:\.|=)[^\s\\]*)",
    product_config,
    re.IGNORECASE | re.MULTILINE,
)
if forbidden_product_properties:
    print(
        "product config reintroduces forbidden appliance properties:",
        file=sys.stderr,
    )
    print("\n".join(forbidden_product_properties), file=sys.stderr)
    raise SystemExit(1)

print("Product config does not reintroduce removed radio/network properties.")
