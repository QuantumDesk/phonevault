//! "Move from another wallet": a read-only assistant for leaving Ledger, Trezor, MetaMask or any
//! other wallet WITHOUT bringing its recovery phrase here. The user pastes the old wallet's PUBLIC
//! data (EVM addresses, Bitcoin xpubs or addresses); this scans what it holds on the user's own
//! nodes and Esplora server, shows where each item goes on Phone Vault, and ticks items off as the
//! user sends them from the old wallet. It never asks for a phrase or a key and never signs for the
//! old wallet: secrets pasted by mistake are refused (`source.rs`) and never stored.
//!
//! The session (the pasted entries, and which items were seen holding something, so a re-scan can
//! tell "moved" from "never had any") is public data, kept in `migration.json` (0600) next to the
//! pairing file until the user chooses Forget.

pub mod btc_scan;
pub mod evm;
pub mod source;

use crate::btc::{esplora, store as btc_store, wallet::Net};
use crate::{blocking, eth, pairing, verify, CmdResult};
use serde::{Deserialize, Serialize};
use source::Source;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

const FILE: &str = "migration.json";
const VERSION: u32 = 1;
/// Entries per session at most.
pub const MAX_SOURCES: usize = 20;
/// Items remembered per session at most (a hostile node cannot grow the file without bound).
const MAX_FOUND: usize = 4000;
const MAX_KEY: usize = 300;

/// Where one item stands.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// the old wallet holds it: move it
    Move,
    /// it held it before and doesn't now (for an NFT: Phone Vault holds it)
    Moved,
    /// an NFT that left the old wallet, but not for Phone Vault
    Gone,
    /// never seen holding anything (not shown)
    Empty,
}

impl Status {
    /// `present`: the old wallet holds it now. Records it in `found` the first time.
    pub fn of(present: bool, key: &str, found: &mut BTreeSet<String>) -> Status {
        if present {
            if found.len() < MAX_FOUND && key.len() <= MAX_KEY {
                found.insert(key.to_string());
            }
            Status::Move
        } else if found.contains(key) {
            Status::Moved
        } else {
            Status::Empty
        }
    }
}

// ---------------------------------------------------------------- the session file

#[derive(Serialize, Deserialize, Default, Clone, Debug, PartialEq)]
struct Stored {
    version: u32,
    sources: Vec<String>,
    found: BTreeSet<String>,
    started_at: u64,
    scanned_at: u64,
}

static LOCK: Mutex<()> = Mutex::new(());

fn dir() -> Result<PathBuf, String> {
    pairing::dir().map_err(String::from)
}

fn parse_stored(text: &str) -> Result<Stored, String> {
    let bad = || "the saved migration list is not valid; Forget it and start again".to_string();
    let s: Stored = serde_json::from_str(text).map_err(|_| bad())?;
    if s.version != VERSION || s.sources.len() > MAX_SOURCES || s.found.len() > MAX_FOUND {
        return Err(bad());
    }
    for x in &s.sources {
        if source::parse(x).map(|p| p.id() != x).unwrap_or(true) {
            return Err(bad());
        }
    }
    if s.found.iter().any(|k| k.len() > MAX_KEY || !k.bytes().all(|b| b.is_ascii_graphic())) {
        return Err(bad());
    }
    Ok(s)
}

fn load_in(dir: &Path) -> Result<Option<Stored>, String> {
    btc_store::check_file(&dir.join(FILE))?.map(|t| parse_stored(&t)).transpose()
}

fn save_in(dir: &Path, s: &Stored) -> Result<(), String> {
    btc_store::write_private(dir, FILE, serde_json::to_string_pretty(s).map_err(|e| e.to_string())?.as_bytes())
}

fn forget_in(dir: &Path) -> Result<(), String> {
    let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
    match std::fs::remove_file(dir.join(FILE)) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Does item `key` belong to the entry `id`?
fn key_of(key: &str, id: &str) -> bool {
    match key.split(':').collect::<Vec<_>>().as_slice() {
        ["evm", _, addr, ..] => *addr == id,
        ["btc", rest @ ..] => rest.join(":") == id,
        _ => false,
    }
}

/// Replace the entries (validated, de-duplicated); items of entries that stay are kept.
fn set_sources_in(dir: &Path, inputs: &[String], own: &Own, now: u64) -> Result<(Stored, Vec<Source>), String> {
    if inputs.len() > MAX_SOURCES {
        return Err(format!("At most {MAX_SOURCES} entries at a time."));
    }
    let mut parsed: Vec<Source> = Vec::new();
    for (i, x) in inputs.iter().enumerate() {
        let p = source::parse(x).map_err(|e| format!("Line {}: {e}", i + 1))?;
        own.check(&p).map_err(|e| format!("Line {}: {e}", i + 1))?;
        if !parsed.iter().any(|q| q.id() == p.id()) {
            parsed.push(p);
        }
    }
    if parsed.is_empty() {
        return Err("Paste at least one address or extended public key.".into());
    }
    let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
    let old = load_in(dir)?.unwrap_or_default();
    let sources: Vec<String> = parsed.iter().map(|p| p.id().to_string()).collect();
    let found = old.found.into_iter().filter(|k| sources.iter().any(|id| key_of(k, id))).collect();
    let s = Stored {
        version: VERSION,
        sources,
        found,
        started_at: if old.started_at == 0 { now } else { old.started_at },
        scanned_at: old.scanned_at,
    };
    save_in(dir, &s)?;
    Ok((s, parsed))
}

/// Add what a scan saw to the session (re-read under the lock: scans run side by side).
fn record_in(dir: &Path, found: BTreeSet<String>, now: u64) -> Result<(), String> {
    let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
    let Some(mut s) = load_in(dir)? else { return Ok(()) };
    for k in found {
        if s.found.len() >= MAX_FOUND {
            break;
        }
        if s.sources.iter().any(|id| key_of(&k, id)) {
            s.found.insert(k);
        }
    }
    s.scanned_at = now;
    save_in(dir, &s)
}

/// The Phone Vault accounts, so an entry that is already one of them is refused.
#[derive(Default)]
struct Own {
    evm: Vec<String>,
    xpubs: Vec<bitcoin::bip32::Xpub>,
}

impl Own {
    fn load() -> Own {
        let evm = pairing::list().map(|p| p.accounts.into_iter().map(|a| a.address.to_ascii_lowercase()).collect());
        let xpubs = btc_store::load().map(|p| p.accounts.iter().filter_map(|a| a.xpub.parse().ok()).collect());
        Own { evm: evm.unwrap_or_default(), xpubs: xpubs.unwrap_or_default() }
    }
    fn check(&self, s: &Source) -> Result<(), String> {
        let mine = match s {
            Source::Evm { id, .. } => self.evm.contains(id),
            Source::Xpub { id, .. } => {
                source::xpub_of(id).is_ok_and(|x| self.xpubs.iter().any(|y| y.public_key == x.public_key))
            }
            Source::BtcAddress { .. } => false,
        };
        if mine {
            return Err("That is one of your Phone Vault accounts, not the old wallet.".into());
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- commands

#[derive(Serialize)]
pub struct SessionView {
    sources: Vec<Source>,
    started_at: u64,
    scanned_at: u64,
    path: String,
}

fn view(dir: &Path, s: &Stored) -> SessionView {
    SessionView {
        sources: s.sources.iter().filter_map(|x| source::parse(x).ok()).collect(),
        started_at: s.started_at,
        scanned_at: s.scanned_at,
        path: dir.join(FILE).display().to_string(),
    }
}

/// Check one pasted entry (as the user types).
#[tauri::command]
pub(crate) fn migrate_check(input: String) -> CmdResult<Source> {
    if input.len() > 4 * source::MAX_INPUT {
        return Err("That is too long for an address or a public key.".into());
    }
    let s = source::parse(&input)?;
    Own::load().check(&s)?;
    Ok(s)
}

/// The saved session, if any.
#[tauri::command]
pub(crate) async fn migrate_session() -> CmdResult<Option<SessionView>> {
    blocking(|| {
        let d = dir()?;
        let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
        Ok(load_in(&d)?.map(|s| view(&d, &s)))
    })
    .await
}

/// Save the entries of the old wallet (public data only).
#[tauri::command]
pub(crate) async fn migrate_save(sources: Vec<String>) -> CmdResult<SessionView> {
    blocking(move || {
        if sources.iter().any(|s| s.len() > 4 * source::MAX_INPUT) {
            return Err("An entry is too long for an address or a public key.".into());
        }
        let d = dir()?;
        let (s, _) = set_sources_in(&d, &sources, &Own::load(), crate::history::now())?;
        Ok(view(&d, &s))
    })
    .await
}

/// Delete the session file.
#[tauri::command]
pub(crate) async fn migrate_forget() -> CmdResult<()> {
    blocking(|| forget_in(&dir()?)).await
}

#[derive(Serialize)]
pub struct EvmDestination {
    address: String,
    label: String,
}

#[derive(Serialize)]
pub struct BtcDestination {
    network: Net,
    network_name: &'static str,
    unit: &'static str,
    id: String,
    label: String,
    kind_name: &'static str,
    native_segwit: bool,
    address: String,
    index: u32,
    path: String,
    verified: bool,
    balance_sats: i64,
}

#[derive(Serialize)]
pub struct Destinations {
    evm: Option<EvmDestination>,
    btc: Vec<BtcDestination>,
}

/// Where things go: the active EVM account, and per Bitcoin network the next receive address of
/// the Native SegWit account (the shown one if it is Native SegWit, else the first; another type
/// only when there is no Native SegWit account).
#[tauri::command]
pub(crate) async fn migrate_destinations() -> CmdResult<Destinations> {
    blocking(|| {
        let p = pairing::list()?;
        let evm = p
            .active_account()
            .map(|a| EvmDestination { address: verify::checksum(&a.address), label: a.label.clone() });
        let all = btc_store::load()?;
        let mut btc = Vec::new();
        for net in [Net::Bitcoin, Net::Testnet, Net::Signet] {
            let on: Vec<_> = all.accounts.iter().filter(|a| a.network == net).collect();
            let active = all.active.get(net.wire());
            let native = |a: &btc_store::StoredAccount| a.kind == crate::btc::wallet::Kind::P2wpkh;
            let pick = on
                .iter()
                .find(|a| native(a) && Some(&a.id) == active)
                .or_else(|| on.iter().find(|a| native(a)))
                .or_else(|| on.iter().find(|a| Some(&a.id) == active))
                .or_else(|| on.first());
            let Some(s) = pick else { continue };
            let a = s.account()?;
            let c = btc_store::load_cache(&s.id)?;
            let index = c.next[0];
            btc.push(BtcDestination {
                network: net,
                network_name: net.name(),
                unit: net.unit(),
                id: s.id.clone(),
                label: s.label.clone(),
                kind_name: s.kind.name(),
                native_segwit: native(s),
                address: a.derive(0, index)?.address.to_string(),
                index,
                path: format!("m/{}/0/{index}", a.path()).replace('\'', "h"),
                verified: c.verified.contains(&index),
                balance_sats: (c.confirmed() as i64).saturating_add(c.unconfirmed()),
            });
        }
        Ok(Destinations { evm, btc })
    })
    .await
}

fn session_entry(id: &str) -> Result<(PathBuf, Source, BTreeSet<String>), String> {
    let d = dir()?;
    let s = {
        let _g = LOCK.lock().map_err(|_| "lock poisoned")?;
        load_in(&d)?
    }
    .ok_or("Save the list of old addresses first.")?;
    if !s.sources.iter().any(|x| x == id) {
        return Err("That entry isn't in the saved list.".into());
    }
    let src = source::parse(id)?;
    Ok((d, src, s.found))
}

/// Scan one old EVM address on the node `rpc_url` (its chain). `deep`: also search logs for NFTs
/// and approvals (slower); a quick re-scan re-checks only what was found before.
#[tauri::command]
pub(crate) async fn migrate_scan_evm(rpc_url: String, address: String, deep: bool) -> CmdResult<evm::Report> {
    blocking(move || {
        let id = address.trim().to_ascii_lowercase();
        let (d, src, mut found) = session_entry(&id)?;
        let Source::Evm { .. } = src else { return Err("That entry is not an EVM address.".into()) };
        let dest = pairing::load()?.ok_or(pairing::NOT_PAIRED)?.to_ascii_lowercase();
        let rpc = eth::Rpc::new(&rpc_url)?;
        let report = evm::scan(&rpc, &id, &dest, &mut found, deep)?;
        record_in(&d, found, crate::history::now())?;
        Ok(report)
    })
    .await
}

#[derive(Serialize)]
pub struct BtcReport {
    source: String,
    network: Net,
    network_name: &'static str,
    unit: &'static str,
    server: String,
    /// per script type (an extended key); empty for a single address
    types: Vec<btc_scan::TypeTotal>,
    confirmed_sats: u64,
    unconfirmed_sats: i64,
    status: Status,
}

/// Scan one old Bitcoin entry (an extended public key or an address) on the configured Esplora server.
#[tauri::command]
pub(crate) async fn migrate_scan_btc(source: String) -> CmdResult<BtcReport> {
    blocking(move || {
        let (d, src, mut found) = session_entry(source.trim())?;
        let net = match &src {
            Source::Xpub { network, .. } | Source::BtcAddress { network, .. } => *network,
            Source::Evm { .. } => return Err("That entry is not a Bitcoin entry.".into()),
        };
        let server = btc_store::load()?.server(net);
        let client = esplora::Client::new(net, server.as_deref())?;
        let report = scan_btc(&src, net, &client, &mut found)?;
        record_in(&d, found, crate::history::now())?;
        Ok(BtcReport { server: client.host(), ..report })
    })
    .await
}

fn scan_btc(
    src: &Source,
    net: Net,
    server: &dyn crate::btc::scan::Source,
    found: &mut BTreeSet<String>,
) -> Result<BtcReport, String> {
    let (types, confirmed, unconfirmed) = match src {
        Source::Xpub { id, types, .. } => {
            let t = btc_scan::scan_key(&source::xpub_of(id)?, types, net, server)?;
            let c = t.iter().map(|x| x.confirmed_sats).sum::<u64>();
            let u = t.iter().map(|x| x.unconfirmed_sats).sum::<i64>();
            (t, c, u)
        }
        Source::BtcAddress { id, .. } => {
            let (c, u, _) = btc_scan::scan_address(id, server)?;
            (Vec::new(), c, u)
        }
        Source::Evm { .. } => return Err("not a Bitcoin entry".into()),
    };
    let total = i64::try_from(confirmed).unwrap_or(i64::MAX).saturating_add(unconfirmed);
    let key = format!("btc:{}", src.id());
    Ok(BtcReport {
        source: src.id().to_string(),
        network: net,
        network_name: net.name(),
        unit: net.unit(),
        server: String::new(),
        types,
        confirmed_sats: confirmed,
        unconfirmed_sats: unconfirmed,
        status: Status::of(total >= btc_scan::DUST_SATS as i64, &key, found),
    })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::btc::esplora::{AddressInfo, Stats, Tx};
    use std::os::unix::fs::PermissionsExt;

    const OLD: &str = "0x70997970c51812dc3a010c7d01b50e0d17dc79c8";
    const ADDR: &str = "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("pv-migrate-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn session_is_private_validated_and_forgettable() {
        let d = tmp();
        assert_eq!(load_in(&d).unwrap(), None);
        let inputs = vec![OLD.to_string(), format!(" {OLD} "), ADDR.to_uppercase()];
        let (s, parsed) = set_sources_in(&d, &inputs, &Own::default(), 100).unwrap();
        assert_eq!(s.sources, vec![OLD.to_string(), ADDR.to_string()], "trimmed, de-duplicated, canonical");
        assert_eq!(parsed.len(), 2);
        let mode = std::fs::metadata(d.join(FILE)).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(load_in(&d).unwrap().unwrap().started_at, 100);

        // what scans see is kept for entries that stay, dropped for entries that go
        let found =
            BTreeSet::from([format!("evm:1:{OLD}:native"), format!("btc:{ADDR}"), "evm:1:0xother:native".into()]);
        record_in(&d, found, 200).unwrap();
        let s = load_in(&d).unwrap().unwrap();
        assert_eq!((s.found.len(), s.scanned_at), (2, 200));
        let (s, _) = set_sources_in(&d, &[OLD.into()], &Own::default(), 300).unwrap();
        assert_eq!(s.found, BTreeSet::from([format!("evm:1:{OLD}:native")]));
        assert_eq!(s.started_at, 100);

        // secrets and bad lines are refused with the line number; nothing changes
        let phrase = "abandon ".repeat(11) + "about";
        let e = set_sources_in(&d, &[OLD.into(), phrase], &Own::default(), 400).unwrap_err();
        assert!(e.starts_with("Line 2: ") && e.contains("recovery phrase"), "{e}");
        assert!(set_sources_in(&d, &[], &Own::default(), 400).is_err());
        assert!(set_sources_in(&d, &vec![OLD.to_string(); MAX_SOURCES + 1], &Own::default(), 400).is_err());
        assert_eq!(load_in(&d).unwrap().unwrap().sources, vec![OLD.to_string()]);
        // one of the user's own Phone Vault accounts is not an old wallet
        let own = Own { evm: vec![OLD.into()], xpubs: vec![] };
        assert!(set_sources_in(&d, &[OLD.into()], &own, 400).unwrap_err().contains("Phone Vault accounts"));

        // a readable-by-others or hand-edited file is not used
        std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_in(&d).is_err());
        std::fs::set_permissions(d.join(FILE), std::fs::Permissions::from_mode(0o600)).unwrap();
        let text = std::fs::read_to_string(d.join(FILE)).unwrap();
        let tampered = text.replace(OLD, "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi");
        btc_store::write_private(&d, FILE, tampered.as_bytes()).unwrap();
        assert!(load_in(&d).is_err());

        forget_in(&d).unwrap();
        assert_eq!(load_in(&d).unwrap(), None);
        forget_in(&d).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn keys_belong_to_their_entry() {
        assert!(key_of(&format!("evm:8453:{OLD}:0xabc"), OLD));
        assert!(!key_of(&format!("evm:8453:{OLD}x:native"), OLD));
        assert!(key_of(&format!("btc:{ADDR}"), ADDR));
        assert!(!key_of("btc:", ADDR));
        assert!(!key_of("nonsense", ADDR));
    }

    struct One(u64);
    impl crate::btc::scan::Source for One {
        fn address(&self, a: &str) -> Result<AddressInfo, String> {
            let chain_stats = Stats { funded_txo_sum: self.0, tx_count: 1, ..Stats::default() };
            Ok(AddressInfo { address: a.into(), chain_stats, mempool_stats: Stats::default() })
        }
        fn txs(&self, _: &str) -> Result<Vec<Tx>, String> {
            Ok(vec![])
        }
    }

    #[test]
    fn bitcoin_entries_tick_off_when_emptied() {
        let src = source::parse(ADDR).unwrap();
        let mut found = BTreeSet::new();
        let r = scan_btc(&src, Net::Bitcoin, &One(150_000), &mut found).unwrap();
        assert_eq!((r.confirmed_sats, r.status), (150_000, Status::Move));
        let r = scan_btc(&src, Net::Bitcoin, &One(300), &mut found).unwrap();
        assert_eq!(r.status, Status::Moved, "dust left behind counts as moved");
        let mut fresh = BTreeSet::new();
        assert_eq!(scan_btc(&src, Net::Bitcoin, &One(0), &mut fresh).unwrap().status, Status::Empty);
    }
}
