//! Per-origin permissions, persisted in `browser-sites.json` (0600).

use super::{normalize_origin, MAX_SITES};
use crate::{verify, wc};
use serde::{Deserialize, Serialize};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Site {
    pub origin: String,
    /// The paired address when the user connected (lowercase). Another pairing = not connected.
    pub address: String,
    /// Networks the user approved for this site, all on wc::ALLOWED_CHAINS; `active` is one of them.
    pub chains: Vec<u64>,
    pub active: u64,
    pub connected_at: u64,
}

impl Site {
    fn valid(&self) -> bool {
        normalize_origin(&self.origin).as_deref() == Ok(self.origin.as_str())
            && verify::is_address(&self.address)
            && !self.chains.is_empty()
            && self.chains.iter().all(|c| wc::chain_allowed(*c))
            && self.chains.contains(&self.active)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct SitesFile {
    version: u32,
    sites: Vec<Site>,
}

pub fn sites_path() -> Option<PathBuf> {
    dirs::config_dir().map(|d| d.join("PhoneVault").join("browser-sites.json"))
}

/// Sites file: 0600 (it is browsing history of a kind); a looser file is ignored, as is any entry
/// that does not validate.
pub fn load_sites(path: &Path) -> Vec<Site> {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return vec![] };
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        return vec![];
    }
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let Ok(file) = serde_json::from_str::<SitesFile>(&text) else { return vec![] };
    let mut out: Vec<Site> = vec![];
    for s in file.sites.into_iter().filter(Site::valid) {
        if !out.iter().any(|o| o.origin == s.origin) && out.len() < MAX_SITES {
            out.push(s);
        }
    }
    out
}

pub fn save_sites(path: &Path, sites: &[Site]) -> Result<(), String> {
    let dir = path.parent().ok_or("bad sites path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".browser-sites.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f =
        std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    let body =
        serde_json::to_vec_pretty(&SitesFile { version: 1, sites: sites.to_vec() }).map_err(|e| e.to_string())?;
    f.write_all(&body).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::tests::{site, tmp};

    #[test]
    fn sites_persist_0600_and_bad_entries_are_dropped() {
        let d = tmp("sites");
        let p = d.join("browser-sites.json");
        let good = site(&[8453], 8453);
        save_sites(&p, std::slice::from_ref(&good)).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_sites(&p), vec![good.clone()]);
        let mut bad = good.clone();
        bad.origin = "http://evil.org".into();
        let mut bad2 = good.clone();
        bad2.origin = "https://b.org".into();
        bad2.chains = vec![56];
        bad2.active = 56;
        let mut bad3 = good.clone();
        bad3.origin = "https://c.org".into();
        bad3.active = 1;
        save_sites(&p, &[good.clone(), bad, bad2, bad3]).unwrap();
        assert_eq!(load_sites(&p), vec![good.clone()]);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_sites(&p).is_empty(), "a group/world-readable file is ignored");
        let _ = std::fs::remove_dir_all(d);
    }
}
