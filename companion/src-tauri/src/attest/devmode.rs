//! Developer mode: accept development phones (unlocked bootloader, development-signed app) as
//! DEVELOPMENT instead of FAIL. It is state of this Mac, kept in a 0600 file next to the pairing
//! file, and changed only through `set_developer_mode`, which the Settings → Device flow calls
//! after the user types the confirmation phrase. The webview cannot pass it per check: every
//! device check reads it here.

use std::path::{Path, PathBuf};

/// What the user must type to turn Developer mode on (compared exactly, after trimming).
pub const CONFIRMATION: &str = "I FLASHED THIS PHONE";
const FILE: &str = "developer-mode.json";

fn dir() -> Result<PathBuf, String> {
    crate::pairing::dir().map_err(|e| e.0)
}

/// On only when the file exists, is private (0600-style: no group/other bits), and says so.
pub fn enabled_in(dir: &Path) -> bool {
    match crate::btc::store::check_file(&dir.join(FILE)) {
        Ok(Some(text)) => serde_json::from_str::<serde_json::Value>(&text)
            .ok()
            .is_some_and(|v| v.get("version") == Some(&1.into()) && v.get("developerMode") == Some(&true.into())),
        _ => false,
    }
}

pub fn enabled() -> bool {
    dir().is_ok_and(|d| enabled_in(&d))
}

pub fn set_in(dir: &Path, on: bool, confirmation: Option<&str>) -> Result<(), String> {
    if on {
        if confirmation.map(str::trim) != Some(CONFIRMATION) {
            return Err(format!("Type {CONFIRMATION} to turn on Developer mode."));
        }
        crate::btc::store::write_private(dir, FILE, br#"{"version":1,"developerMode":true}"#)
    } else {
        match std::fs::remove_file(dir.join(FILE)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    }
}

pub fn set(on: bool, confirmation: Option<&str>) -> Result<(), String> {
    set_in(&dir()?, on, confirmation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pv-devmode-{}-{}", std::process::id(), uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn off_by_default_and_needs_the_exact_phrase() {
        let d = tmp();
        assert!(!enabled_in(&d));
        assert!(set_in(&d, true, None).is_err());
        assert!(set_in(&d, true, Some("i flashed this phone")).is_err());
        assert!(set_in(&d, true, Some("yes")).is_err());
        assert!(!enabled_in(&d));
        set_in(&d, true, Some("  I FLASHED THIS PHONE ")).unwrap();
        assert!(enabled_in(&d));
        assert_eq!(std::fs::metadata(d.join(FILE)).unwrap().permissions().mode() & 0o777, 0o600);
        set_in(&d, false, None).unwrap();
        assert!(!enabled_in(&d));
        set_in(&d, false, None).unwrap(); // idempotent
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_tampered_or_loose_file_is_off() {
        let d = tmp();
        set_in(&d, true, Some(CONFIRMATION)).unwrap();
        std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(!enabled_in(&d), "readable by others: refused");
        std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(d.join(FILE), r#"{"version":1,"developerMode":"yes"}"#).unwrap();
        assert!(!enabled_in(&d));
        std::fs::write(d.join(FILE), "garbage").unwrap();
        assert!(!enabled_in(&d));
        std::fs::remove_dir_all(&d).unwrap();
    }
}
