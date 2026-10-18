#!/usr/bin/env bash
# On-phone pass criteria for a flashed bluejay rung (b1 … b4d-1, b4d), over adb from the Mac.
#   check-rung.sh RUNG            all checks of RUNG and every rung below it (cumulative)
#   check-rung.sh RUNG --no-usb   skip the USB function-switch probe (it re-enumerates USB)
# Read-only except the b3+ probe, which asks the framework for MTP/RNDIS/MIDI and expects the
# gadget HAL to refuse (the USB connection drops for a few seconds while the framework falls back
# to adb). Never calls `adb root`, never touches the wallet, the PIN or the device owner. Runs on
# macOS's bash 3.2. Exit 1 if any FAIL; WARN lines need a human look (see README, per rung).
# Then run the app suites as usual (tools/dev-device: firstrun/usbsigntest/tokensigntest/
# msgsigntest/credentialtest with PV_THROWAWAY_DEVICE=1) - this script does not replace them.
# It never reboots the phone: the b4d-1/b4d `adb reboot` test is a separate manual step (README).
set -uo pipefail
RUNG="${1:?rung (b1, b2, b3, b4a, b4b, b4c, b4d-1, b4d)}"
PROBE_USB=1; [[ "${2:-}" == --no-usb ]] && PROBE_USB=0
A="${ADB:-adb}"
DIR="$(cd "$(dirname "$0")" && pwd)"
RUNG_DIR="${DIR}/rung-${RUNG}"
[[ -d "${RUNG_DIR}" ]] || { echo "no such rung: ${RUNG_DIR}" >&2; exit 2; }

ORDER="b1 b2 b3 b4a b4b b4c b4d-1 b4d"   # b4d-1 = b4d's radio-daemon half only
rank() { local i=0 r; for r in ${ORDER}; do i=$((i+1)); [[ "$r" == "$1" ]] && { echo $i; return; }; done; echo 0; }
R=$(rank "${RUNG}"); [[ ${R} -gt 0 ]] || { echo "unknown rung ${RUNG}" >&2; exit 2; }
at_least() { [[ ${R} -ge $(rank "$1") ]]; }

FAILS=0; WARNS=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
warn() { echo "WARN  $*"; WARNS=$((WARNS+1)); }
sh_() { "$A" shell "$@" 2>/dev/null | tr -d '\r'; }
prop() { sh_ getprop "$1"; }
wait_adb() { local i; for i in $(seq 1 "${1:-24}"); do "$A" get-state >/dev/null 2>&1 && [[ "$(prop sys.boot_completed)" == 1 ]] && return 0; sleep 5; done; return 1; }

wait_adb 6 || { echo "FAIL  no booted device on adb"; exit 1; }
echo "== rung ${RUNG} on $(prop ro.product.device) $(prop ro.lineage.version) slot $(prop ro.boot.slot_suffix)"

# ---- every rung (b1 checklist) ----
[[ "$(prop ro.product.device)" == bluejay ]] && pass "device bluejay" || fail "not a bluejay"
[[ "$(prop ro.boot.veritymode)" == enforcing ]] && pass "verity enforcing" || fail "ro.boot.veritymode=$(prop ro.boot.veritymode)"
[[ -n "$(prop ro.boot.vbmeta.digest)" ]] && pass "vbmeta digest present (our AVB key)" || fail "no ro.boot.vbmeta.digest"
[[ "$(prop ro.debuggable)" == 1 ]] && pass "dev rung: ro.debuggable=1 (adb kept)" || warn "ro.debuggable=$(prop ro.debuggable)"
owner="$(sh_ dumpsys device_policy | grep -m1 -A2 'Device Owner' | tr '\n' ' ')"
[[ "${owner}" == *dev.phonevault.signer* ]] && pass "device owner dev.phonevault.signer" || fail "device owner: ${owner:-none}"
lock="$(sh_ dumpsys activity activities | grep -m1 -o 'mLockTaskModeState=[A-Z]*')"
[[ "${lock}" == *LOCKED* ]] && pass "kiosk ${lock}" || fail "kiosk: ${lock:-unknown}"
home="$(sh_ cmd package resolve-activity --brief -a android.intent.action.MAIN -c android.intent.category.HOME | tail -1)"
[[ "${home}" == dev.phonevault.signer/* ]] && pass "HOME ${home}" || fail "HOME resolves to ${home:-nothing}"
# crash loops: services init is restarting right now (three samples, 10 s apart), app crashes
loops=""; for i in 1 2 3; do loops="${loops} $(sh_ getprop | grep '\[restarting\]' | sed -E 's/^\[init\.svc\.([^]]*)\].*/\1/' | tr '\n' ' ')"; sleep 10; done
loops="$(echo ${loops} | tr ' ' '\n' | sort -u | tr '\n' ' ')"
if [[ -z "${loops// /}" ]]; then pass "no init service in [restarting]"
elif at_least b4d-1; then fail "services seen restarting: ${loops} (ril-daemon and the radio daemons are gone since b4d-1: nothing may loop)"
else warn "services seen restarting: ${loops} (expected at b4a-b4c: ril-daemon, see README)"; fi
crashes="$(sh_ logcat -b crash -d | grep -c -E 'FATAL EXCEPTION|Fatal signal')"
[[ "${crashes:-0}" -eq 0 ]] && pass "crash buffer empty" || warn "${crashes} crash entries: adb logcat -b crash -d"

# ---- b2: kernel ----
if at_least b2; then
  ad="$(sh_ cat /sys/module/usbcore/parameters/authorized_default)"
  # SELinux keeps the shell user out of /sys/module/usbcore/parameters; without adb root
  # (never used), the kernel command line the bootloader handed over is the evidence.
  if [[ "${ad}" != 0 && "${ad}" != 1 && "${ad}" != -1 ]]; then
    sh_ cat /proc/cmdline | tr ' ' '\n' | grep -qx 'usbcore.authorized_default=0' && ad="0 (from /proc/cmdline)"
  fi
  [[ "${ad}" == 0* ]] && pass "usbcore.authorized_default=${ad}" || fail "usbcore authorized_default=${ad:-unreadable}"
  # removed modules (from this rung's BoardConfigVault.mk): not loaded, not on vendor_dlkm
  mods="$(awk '{ if (sub(/\\$/, "")) printf "%s ", $0; else print }' "${RUNG_DIR}/BoardConfigVault.mk" \
          | grep -E '^PHONEVAULT_KMODS_REMOVED[[:space:]]*(:=|\+=)' | sed -E 's/^[^=]*=//' | tr -s ' ' '\n' | grep '\.ko$')"
  lsmod_out="$(sh_ cat /proc/modules | awk '{print $1}')"
  [[ -n "${lsmod_out}" ]] || lsmod_out="$(sh_ lsmod | awk 'NR>1{print $1}')"
  dlkm="$(sh_ ls /vendor_dlkm/lib/modules)"
  n=0; bad=""
  for ko in ${mods}; do
    n=$((n+1)); m="${ko%.ko}"; m="${m//-/_}"
    echo "${lsmod_out}" | grep -qx "${m}" && bad="${bad} ${m}(loaded)"
    echo "${dlkm}" | grep -qx "${ko}" && bad="${bad} ${ko}(on vendor_dlkm)"
  done
  [[ -z "${bad}" ]] && pass "${n} removed kernel modules absent (lsmod + /vendor_dlkm)" || fail "removed modules present:${bad}"
  [[ -n "${lsmod_out}" ]] && pass "$(echo "${lsmod_out}" | wc -l | tr -d ' ') modules loaded" || warn "/proc/modules unreadable from shell"
  for m in aoc_core goodixfp; do
    echo "${lsmod_out}" | grep -qx "${m}" && pass "kept module ${m} loaded" || warn "kept module ${m} not seen in lsmod"
  done
  if ! at_least b4a; then
    for m in bcmdhd4389 cpif; do echo "${lsmod_out}" | grep -qx "${m}" && pass "${m} still loaded (radios go in b4a)" || warn "${m} not loaded"; done
  fi
fi

# ---- b3: USB ----
if at_least b3; then
  feats="$(sh_ pm list features)"
  echo "${feats}" | grep -q 'feature:android.hardware.usb.host$' && fail "android.hardware.usb.host declared" || pass "no usb.host feature"
  echo "${feats}" | grep -q 'feature:android.hardware.usb.accessory$' && pass "usb.accessory feature kept" || fail "usb.accessory feature missing"
  # Parity marker only: the prebuilt gs101 USB HALs never read it (README, b3). Its absence on
  # the device is a follow-up, not a lock-down failure; the checks below prove the policy.
  [[ "$(prop ro.vendor.phonevault.offline)" == true ]] && pass "ro.vendor.phonevault.offline=true" || warn "ro.vendor.phonevault.offline unset (marker only; nothing reads it on bluejay)"
  pt="$(sh_ cat /sys/class/typec/port0/port_type)"
  if [[ -n "${pt}" ]]; then [[ "${pt}" == *"[sink]"* ]] && pass "port_type ${pt}" || fail "port_type ${pt} (want [sink])"
  else warn "port_type unreadable from shell (dumpsys usb below)"; fi
  ptl="$(sh_ ls -lL /sys/class/typec/port0/port_type)"
  [[ -z "${ptl}" || "${ptl}" == -rw-r--r--*root*root* ]] && pass "port_type node root-only ${ptl:+(${ptl%% *})}" || fail "port_type node: ${ptl}"
  fn="$(sh_ ls /config/usb_gadget/g1/functions | tr '\n' ' ')"
  if [[ -n "${fn// /}" ]]; then
    extra="$(echo ${fn} | tr ' ' '\n' | grep -v -x -E 'accessory\.gs2|ffs\.aoa|ffs\.ctrl|ffs\.adb' | tr '\n' ' ')"
    [[ -z "${extra// /}" ]] && pass "gadget function instances: ${fn}" || fail "extra gadget function instances: ${extra}"
  else warn "/config/usb_gadget unreadable from shell (configfs is root-only on user-facing SELinux)"; fi
  echo "    dumpsys usb port: $(sh_ dumpsys usb | grep -m3 -E 'currentMode|current_mode|mode=|powerRole|dataRole' | tr -s ' ' | tr '\n' ';')"
  [[ "$(prop sys.usb.config)" == *adb* ]] && pass "sys.usb.config=$(prop sys.usb.config)" || warn "sys.usb.config=$(prop sys.usb.config)"
  if [[ ${PROBE_USB} -eq 1 ]]; then
    for f in mtp rndis midi; do
      sh_ svc usb setFunctions "${f}" >/dev/null; sleep 6
      wait_adb 12 || { fail "adb did not come back after setFunctions ${f}"; break; }
      cfg="$(prop sys.usb.config)"; st="$(prop sys.usb.state)"
      [[ "${st}" != *"${f}"* ]] && pass "setFunctions ${f} refused (sys.usb.state=${st}, config=${cfg})" || fail "${f} is active: sys.usb.state=${st}"
    done
    sh_ svc usb resetUsbGadget >/dev/null; sleep 4; wait_adb 12 || true
  fi
  if command -v ioreg >/dev/null 2>&1; then
    # Interfaces the Mac sees on the phone (vendor 0x18d1 = 6353): only vendor-specific (255):
    # adb (ff/42/01) and, while the companion holds it, AOA (ff/ff/00). Mass storage (8), audio
    # (1), CDC (2/10), HID (3), image/PTP (6), video (14), MIDI would mean a function leaked.
    classes="$(ioreg -r -c IOUSBHostInterface -l -w0 2>/dev/null | awk '
      /^\+-o /{ if (v==6353 && c!="") print c; v=""; c="" }
      /"idVendor" = /{ v=$NF } /"bInterfaceClass" = /{ c=$NF }
      END{ if (v==6353 && c!="") print c }' | sort | uniq -c | tr -s ' ' | tr '\n' ';')"
    if [[ -z "${classes}" ]]; then warn "Mac: no phone interfaces visible in ioreg"
    elif echo "${classes}" | tr ';' '\n' | awk 'NF==2 && $2!=255{bad=1} END{exit !bad}'; then fail "Mac sees non-vendor interface classes: ${classes}"
    else pass "Mac sees only vendor-specific interfaces (count class): ${classes}"; fi
  fi
fi

# ---- b4a: radios ----
if at_least b4a; then
  feats="$(sh_ pm list features)"
  leaked="$(echo "${feats}" | grep -E 'feature:android\.hardware\.(bluetooth|nfc|se\.omapi|location\.gps)' | tr '\n' ' ')"
  [[ -z "${leaked}" ]] && pass "no bluetooth/nfc/omapi/gps features" || fail "features still declared: ${leaked}"
  nets="$(sh_ ls /sys/class/net | tr '\n' ' ')"
  echo "${nets}" | grep -q -E '(^| )(wlan|p2p|rmnet|umts)' && fail "radio netdevs present: ${nets}" || pass "no wlan/rmnet netdevs (${nets})"
  [[ -z "$(sh_ ls /sys/class/bluetooth)" ]] && pass "no /sys/class/bluetooth" || fail "/sys/class/bluetooth exists"
  [[ -z "$(sh_ 'ls /dev/umts_* 2>/dev/null')" ]] && pass "no /dev/umts_* (modem interface gone)" || fail "modem device nodes present"
  for s in cpboot-daemon RFS-daemon DM-daemon gpsd lhd scd gnss_service bcmbtlinux init.shared_modem_platform; do
    st="$(prop init.svc.${s})"
    [[ -z "${st}" ]] && pass "service ${s} not defined" || fail "service ${s}: ${st}"
  done
  # Wi-Fi Calling packet router: with the modem gone it crash-loops (124 exits in 5 min on the
  # b4a image). Removed from b4c; b4a/b4b images predate the fix and only get a warning.
  st="$(prop init.svc.pktrouter)"
  if [[ -z "${st}" ]]; then pass "service pktrouter not defined"
  elif at_least b4c; then fail "service pktrouter: ${st}"
  else warn "service pktrouter: ${st} (removed from b4c)"; fi
  svcs="$(sh_ service list)"
  for s in bluetooth_manager nfc; do
    echo "${svcs}" | grep -q -E "^[0-9]+[[:space:]]+${s}:" && fail "system service ${s} registered" || pass "no ${s} system service"
  done
  at_least b4d-1 || echo "    rild: init.svc.ril-daemon=$(prop init.svc.ril-daemon) (kept until b4d-1; no modem behind it)"
  echo "    baseband: gsm.version.baseband='$(prop gsm.version.baseband)' (modem firmware stays on the modem partitions, never booted)"
  # Titan M2 / Trusty stack must be untouched
  tm="$(sh_ getprop | grep -E '^\[init\.svc\.[^]]*(citadel|weaver|keymint|gatekeeper|authsecret|oemlock)[^]]*\]' | tr -d '[]' | tr '\n' ' ')"
  echo "${tm}" | grep -q stopped && fail "Titan/Trusty service stopped: ${tm}" || pass "Titan M2/Trusty services: ${tm}"
fi

# ---- b4b / b4c: app strip ----
check_absent_pkgs() {
  local label="$1"; shift
  local pk; pk="$(sh_ pm list packages | sed 's/^package://')"
  local bad="" p n=0
  for p in "$@"; do n=$((n+1)); echo "${pk}" | grep -qx "${p}" && bad="${bad} ${p}"; done
  [[ -z "${bad}" ]] && pass "${label}: ${n} packages absent ($(echo "${pk}" | wc -l | tr -d ' ') installed)" || fail "${label} still installed:${bad}"
}
if at_least b4b; then
  check_absent_pkgs "b4b app strip" org.lineageos.aperture com.google.android.apps.googlecamera.fishfood \
    org.lineageos.audiofx org.lineageos.camelot org.lineageos.canvas com.android.deskclock org.lineageos.etar \
    com.android.calculator2 org.lineageos.glimpse org.lineageos.jelly org.lineageos.recorder org.lineageos.twelve \
    org.lineageos.updater com.android.avatarpicker org.lineageos.backgrounds com.android.dreams.basic com.android.egg \
    com.android.htmlviewer com.android.wallpaper.livepicker com.android.dreams.phototable com.android.soundpicker \
    com.android.wallpaper com.android.customization.themes com.android.systemui.accessibility.accessibilitymenu \
    com.android.cameraextensions com.android.DeviceAsWebcam com.android.devicediagnostics \
    com.android.providers.downloads.ui com.android.emergency com.android.settings.intelligence com.android.apps.tag
fi
if at_least b4c; then
  check_absent_pkgs "b4c app strip" com.android.calllogbackup com.android.carrierdefaultapp \
    com.android.cellbroadcastreceiver com.android.contacts com.android.dialer com.android.simappdialog com.android.stk \
    com.android.messaging com.android.backupconfirm org.calyxos.backup.contacts com.android.localtransport \
    com.stevesoltys.seedvault com.android.sharedstoragebackup com.android.wallpaperbackup com.android.bips \
    com.android.printservice.recommendation com.android.printspooler com.android.webview com.android.mtp \
    com.android.storagemanager org.lineageos.lineageparts org.lineageos.profiles \
    com.android.systemui.plugin.globalactions.wallet com.android.bluetoothmidiservice com.android.captiveportallogin \
    com.android.certinstaller com.android.companiondevicemanager com.android.credentialmanager com.android.dynsystem \
    com.android.pacprocessor com.android.proxyhandler com.android.se com.android.statementservice com.android.vpndialogs \
    com.android.bookmarkprovider com.android.providers.calendar com.android.providers.contactkeys \
    com.android.providers.partnerbookmarks com.google.android.apps.pixel.nowplaying com.google.android.as.oss \
    com.google.android.as com.google.android.hardwareinfo com.android.hotwordenrollment.okgoogle \
    com.android.hotwordenrollment.xgoogle com.google.android.apps.camera.services com.google.pixel.camera.services
fi
if at_least b4b; then
  pk="$(sh_ pm list packages | sed 's/^package://')"
  for p in com.android.modulemetadata com.android.settings com.android.inputmethod.latin dev.phonevault.signer \
           com.android.systemui com.android.packageinstaller com.android.shell; do
    echo "${pk}" | grep -qx "${p}" && pass "kept ${p}" || fail "MISSING required package ${p}"
  done
  sh_ dumpsys webviewupdate >/dev/null 2>&1; echo "    webviewupdate service: $(sh_ service list | grep -c webviewupdate) (0 when android.software.webview is not declared)"
fi

# ---- b4d-1: rild, vendor radio daemons, radio HAL entries, eSIM app ----
if at_least b4d-1; then
  for s in ril-daemon vendor.google.radioext@1.0 BIP-Channel-Manager secure_element_uicc_hal_service \
           init-radio-sh modem_logging_start; do
    st="$(prop init.svc.${s})"
    [[ -z "${st}" ]] && pass "service ${s} not defined" || fail "service ${s}: ${st}"
  done
  check_absent_pkgs "b4d-1 RIL/eSIM strip" com.samsung.slsi.telephony.oemril \
    com.samsung.slsi.telephony.oem.oemrilhookservice com.google.android.grilservice \
    com.google.euiccpixel com.google.euiccpixel.permissions
  # Nothing asks hwservicemanager (or init, through it) for a radio HAL any more: the b4c log was
  # full of "trying to start it as a lazy HAL" / ctl.interface_start for IRadio/slot1 and
  # IOemSlsiRadioExternal/rilExternal.
  asks="$(sh_ logcat -d -b all | grep -E 'lazy HAL|ctl\.interface_start|interface_start' | grep -c -E 'IRadio|IRadioConfig|ISap|IOemSlsiRadioExternal|radioExternal|ISecureElement/SIM|radioext')"
  [[ "${asks:-0}" -eq 0 ]] && pass "no radio HAL start requests in the log" || fail "${asks} radio HAL start requests: adb logcat -d -b all | grep -E 'lazy HAL|interface_start'"
  bad="$(sh_ logcat -b crash -d | grep -E -o '(euiccpixel|oemril[a-z]*|grilservice)' | sort -u | tr '\n' ' ')"
  [[ -z "${bad// /}" ]] && pass "no eSIM/OEM-RIL process in the crash buffer" || fail "crash buffer names: ${bad}"
fi
if [[ "${RUNG}" == b4d-1 ]]; then
  # b4d-1 keeps the telephony framework, Telecom and Wi-Fi (b4d, which removed them, does not boot).
  pk="$(sh_ pm list packages | sed 's/^package://')"
  for p in com.android.phone com.android.server.telecom com.android.providers.telephony \
           com.android.carrierconfig; do
    echo "${pk}" | grep -qx "${p}" && pass "kept ${p}" || fail "MISSING kept package ${p}"
  done
  svcs="$(sh_ service list)"
  for s in phone isub telecom wifi; do
    echo "${svcs}" | grep -q -E "^[0-9]+[[:space:]]+${s}:" && pass "system service ${s} registered (kept)" || warn "no ${s} system service (kept on purpose; check logcat)"
  done
  feats="$(sh_ pm list features)"
  for f in android.hardware.telephony android.hardware.wifi; do
    echo "${feats}" | grep -q "feature:${f}$" && pass "feature ${f} still declared (unchanged from b4c)" || fail "feature ${f} withdrawn (b4d-1 must not change features)"
  done
  # The b4c loop: com.android.phone "failed to complete startup" ANRs / crashes. b4d-1 must end it.
  ph="$(sh_ logcat -d -b all | grep -c -E 'ANR in com\.android\.phone|failed to complete startup')"
  [[ "${ph:-0}" -eq 0 ]] && pass "no com.android.phone ANR / failed startup" || fail "${ph} com.android.phone ANR/startup-failure lines (README b4d-1: next step)"
  pc="$(sh_ logcat -b crash -d | grep -c -E 'Process: com\.android\.phone|com\.android\.phone.*(died|crash)')"
  [[ "${pc:-0}" -eq 0 ]] && pass "com.android.phone not in the crash buffer" || fail "com.android.phone crashed ${pc}x"
  st="$(prop init.svc.vendor.wifi_hal_legacy)"
  echo "    Wi-Fi HAL: init.svc.vendor.wifi_hal_legacy=${st:-undefined} (kept; no wlan0 since b4a, so 'TIMED_OUT' in logcat is expected noise)"
  echo "    reboot: check-rung never reboots; run the README b4d-1 reboot test (adb reboot -> new boot_id)."
fi

# ---- b4d: telephony + Wi-Fi software ----
if at_least b4d; then
  feats="$(sh_ pm list features)"
  leaked="$(echo "${feats}" | grep -E 'feature:(android\.hardware\.(telephony|wifi)|android\.software\.sip|com\.verizon\.)' | tr '\n' ' ')"
  [[ -z "${leaked}" ]] && pass "no telephony/wifi/sip features" || fail "features still declared: ${leaked}"
  echo "${feats}" | grep -q 'feature:android.software.telecom$' && echo "    android.software.telecom declared (kept: Telecom is in system_server on A17)"
  for s in ril-daemon vendor.google.radioext@1.0 BIP-Channel-Manager secure_element_uicc_hal_service \
           init-radio-sh modem_logging_start vendor.wifi_hal_legacy wpa_supplicant hostapd wificond; do
    st="$(prop init.svc.${s})"
    [[ -z "${st}" ]] && pass "service ${s} not defined" || fail "service ${s}: ${st}"
  done
  svcs="$(sh_ service list)"
  for s in phone isub carrier_config imms wifi wifiscanner wifip2p wifiaware rttmanager; do
    echo "${svcs}" | grep -q -E "^[0-9]+[[:space:]]+${s}:" && fail "system service ${s} registered" || pass "no ${s} system service"
  done
  echo "${svcs}" | grep -q -E "^[0-9]+[[:space:]]+telecom:" && pass "telecom service registered (kept)" || warn "no telecom service (Telecom is kept on purpose; check logcat -s TelecomLoaderService)"
  check_absent_pkgs "b4d telephony/eUICC strip" com.android.phone com.android.providers.telephony \
    com.android.carrierconfig com.android.mms.service com.android.ons com.google.android.iwlan \
    com.samsung.slsi.telephony.oemril com.samsung.slsi.telephony.oem.oemrilhookservice \
    com.google.android.grilservice com.shannon.imsservice com.shannon.rcsservice \
    com.shannon.qualifiednetworksservice com.google.android.carrier com.google.android.carriersetup \
    com.google.android.apps.carrier.carrierwifi com.google.android.wfcactivation \
    com.android.imsserviceentitlement com.google.android.tetheringentitlement com.verizon.services \
    com.vzw.apnlib com.verizon.mips.services com.android.sdm.plugins.connmo com.android.sdm.plugins.dcmo \
    com.android.sdm.plugins.diagmon com.android.omadm.service com.google.omadm.trigger \
    com.google.android.connectivitythermalpowermanager com.google.android.euicc \
    com.google.android.euiccoverlay com.google.euiccpixel com.google.euiccpixel.permissions \
    org.lineageos.settings
  pk="$(sh_ pm list packages | sed 's/^package://')"
  echo "${pk}" | grep -qx com.android.server.telecom && pass "kept com.android.server.telecom (TelecomShim)" || warn "com.android.server.telecom missing (TelecomShim is kept on purpose)"
  # Nothing asks hwservicemanager/servicemanager for a radio or Wi-Fi HAL, no phone ANR/crash.
  asks="$(sh_ logcat -d -b all | grep -c -E 'IRadio|IOemSlsiRadioExternal|radioExternal|IRadioConfig|android\.hardware\.wifi\.IWifi|IWifiExt')"
  [[ "${asks:-0}" -eq 0 ]] && pass "no radio/Wi-Fi HAL lookups in the log" || fail "${asks} log lines still name a radio/Wi-Fi HAL: adb logcat -d -b all | grep -E 'IRadio|radioExternal|IWifi'"
  bad="$(sh_ logcat -b crash -d | grep -E -o '(com\.android\.phone|euicc[a-z]*|oemril[a-z]*|grilservice|shannon\.[a-z]*|connectivitythermalpowermanager)' | sort -u | tr '\n' ' ')"
  [[ -z "${bad// /}" ]] && pass "no telephony/eUICC process in the crash buffer" || fail "crash buffer names: ${bad}"
  anr="$(sh_ dumpsys activity processes | grep -c -E 'com\.android\.phone|euiccpixel')"
  [[ "${anr:-0}" -eq 0 ]] && pass "no phone/euicc process known to ActivityManager" || fail "phone/euicc process present (${anr} lines in dumpsys activity processes)"
  echo "    reboot: check-rung never reboots; run the README b4d reboot test (adb reboot -> new boot)."
fi

echo "== ${FAILS} FAIL, ${WARNS} WARN (rung ${RUNG})"
[[ ${FAILS} -eq 0 ]]
