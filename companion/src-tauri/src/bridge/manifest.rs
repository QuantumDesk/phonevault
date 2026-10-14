//! Native host manifests ("Install browser connection"), pinned to the extension ID.

use super::{CHROME_EXTENSION_ID, FIREFOX_EXTENSION_ID, HOST_NAME};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub struct HostTarget {
    pub browser: &'static str,
    pub app_dir: &'static str,
    pub firefox: bool,
}
pub const HOST_TARGETS: [HostTarget; 5] = [
    HostTarget { browser: "Google Chrome", app_dir: "Google/Chrome", firefox: false },
    HostTarget { browser: "Brave", app_dir: "BraveSoftware/Brave-Browser", firefox: false },
    HostTarget { browser: "Microsoft Edge", app_dir: "Microsoft Edge", firefox: false },
    HostTarget { browser: "Chromium", app_dir: "Chromium", firefox: false },
    HostTarget { browser: "Firefox", app_dir: "Mozilla", firefox: true },
];

pub fn host_manifest(exe: &Path, firefox: bool) -> Value {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "Phone Vault Companion browser connection",
        "path": exe.display().to_string(),
        "type": "stdio",
    });
    if firefox {
        m["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]);
    } else {
        m["allowed_origins"] = json!([format!("chrome-extension://{CHROME_EXTENSION_ID}/")]);
    }
    m
}

fn app_support(home: &Path) -> PathBuf {
    home.join("Library").join("Application Support")
}
pub fn manifest_path(home: &Path, t: &HostTarget) -> PathBuf {
    app_support(home).join(t.app_dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json"))
}

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct HostState {
    pub browser: String,
    pub path: String,
    pub browser_found: bool,
    pub state: &'static str,
}

/// "installed" (points at this app), "outdated" (points elsewhere, e.g. the app moved),
/// "missing", or "foreign" (a file of that name that isn't ours; left alone).
pub fn host_states(home: &Path, exe: &Path) -> Vec<HostState> {
    HOST_TARGETS
        .iter()
        .map(|t| {
            let p = manifest_path(home, t);
            let state = match std::fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
                None if p.exists() => "foreign",
                None => "missing",
                Some(v) if v == host_manifest(exe, t.firefox) => "installed",
                Some(v)
                    if v["name"] == HOST_NAME
                        && (v["allowed_origins"] == host_manifest(exe, false)["allowed_origins"]
                            || v["allowed_extensions"] == host_manifest(exe, true)["allowed_extensions"]) =>
                {
                    "outdated"
                }
                Some(_) => "foreign",
            };
            HostState {
                browser: t.browser.into(),
                path: p.display().to_string(),
                browser_found: app_support(home).join(t.app_dir).is_dir(),
                state,
            }
        })
        .collect()
}

/// The executable the browser should start. Refuses a translocated (quarantined, read-only
/// random path) copy: the manifest would break on the next launch.
pub fn host_exe() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().and_then(std::fs::canonicalize).map_err(|e| e.to_string())?;
    if exe.to_string_lossy().contains("/AppTranslocation/") {
        return Err("macOS is running this copy from a temporary location. Move Phone Vault Companion to Applications, open it from there, and install again.".into());
    }
    Ok(exe)
}

/// Write the host manifest for every supported browser that has a profile on this Mac.
pub fn install_hosts(home: &Path, exe: &Path) -> Result<Vec<HostState>, String> {
    if !exe.is_absolute() {
        return Err("the app path is not absolute".into());
    }
    let mut wrote = 0;
    for t in HOST_TARGETS.iter() {
        if !app_support(home).join(t.app_dir).is_dir() {
            continue;
        }
        let p = manifest_path(home, t);
        if host_states(home, exe).iter().any(|s| s.path == p.display().to_string() && s.state == "foreign") {
            continue;
        }
        let dir = p.parent().ok_or("bad path")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = dir.join(format!(".{HOST_NAME}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&tmp)
            .map_err(|e| e.to_string())?;
        f.write_all(serde_json::to_string_pretty(&host_manifest(exe, t.firefox)).unwrap_or_default().as_bytes())
            .map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
        wrote += 1;
    }
    if wrote == 0 {
        return Err("No Chrome, Brave, Edge, Chromium or Firefox profile was found on this Mac.".into());
    }
    Ok(host_states(home, exe))
}

/// Remove our host manifests (only files that are ours).
pub fn uninstall_hosts(home: &Path, exe: &Path) -> Vec<HostState> {
    for s in host_states(home, exe) {
        if s.state == "installed" || s.state == "outdated" {
            let _ = std::fs::remove_file(&s.path);
        }
    }
    host_states(home, exe)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::tests::tmp;

    #[test]
    fn host_manifests_pin_the_extension_and_install_only_where_a_browser_exists() {
        let home = tmp("home");
        let exe = PathBuf::from("/Applications/Phone Vault Companion.app/Contents/MacOS/companion");
        let m = host_manifest(&exe, false);
        assert_eq!(m["name"], HOST_NAME);
        assert_eq!(m["type"], "stdio");
        assert_eq!(m["path"], exe.display().to_string());
        assert_eq!(m["allowed_origins"], json!([format!("chrome-extension://{CHROME_EXTENSION_ID}/")]));
        assert!(host_manifest(&exe, true)["allowed_extensions"] == json!([FIREFOX_EXTENSION_ID]));
        assert!(install_hosts(&home, &exe).is_err(), "no browser profile at all");
        std::fs::create_dir_all(home.join("Library/Application Support/Google/Chrome")).unwrap();
        std::fs::create_dir_all(home.join("Library/Application Support/Mozilla")).unwrap();
        let states = install_hosts(&home, &exe).unwrap();
        let st = |b: &str| states.iter().find(|s| s.browser == b).unwrap().state;
        assert_eq!((st("Google Chrome"), st("Firefox"), st("Brave")), ("installed", "installed", "missing"));
        let chrome = home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts/dev.phonevault.json");
        let written: Value = serde_json::from_str(&std::fs::read_to_string(&chrome).unwrap()).unwrap();
        assert_eq!(written, m);
        // the app moved: shown as outdated until installed again
        let moved = PathBuf::from("/Users/x/Applications/Phone Vault Companion.app/Contents/MacOS/companion");
        assert_eq!(host_states(&home, &moved).iter().find(|s| s.browser == "Google Chrome").unwrap().state, "outdated");
        // someone else's file of the same name is left alone
        let brave = home.join("Library/Application Support/BraveSoftware/Brave-Browser/NativeMessagingHosts");
        std::fs::create_dir_all(&brave).unwrap();
        std::fs::write(
            brave.join("dev.phonevault.json"),
            r#"{"name":"dev.phonevault","path":"/tmp/evil","allowed_origins":["chrome-extension://zzzz/"]}"#,
        )
        .unwrap();
        install_hosts(&home, &exe).unwrap();
        assert!(std::fs::read_to_string(brave.join("dev.phonevault.json")).unwrap().contains("/tmp/evil"));
        let after = uninstall_hosts(&home, &exe);
        assert!(!chrome.exists());
        assert_eq!(after.iter().find(|s| s.browser == "Brave").unwrap().state, "foreign");
        assert!(brave.join("dev.phonevault.json").exists(), "foreign file not removed");
        let _ = std::fs::remove_dir_all(home);
    }
}
