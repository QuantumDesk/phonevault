//! Background Bitcoin watcher (same thread model as `watcher.rs`): every paired account is
//! refreshed on a modest schedule (the one shown per network every 2 minutes, others every 10),
//! with a full gap-limit scan at most every 30 minutes and light scans in between. New incoming
//! payments notify (Settings → Notifications), the UI hears `btc-changed`, and the menu bar shows
//! the Bitcoin balance. Only the configured Esplora server is contacted.

use super::{store, tx, wallet::Net};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

pub static WAKE: AtomicBool = AtomicBool::new(false);
const SHOWN_EVERY: Duration = Duration::from_secs(120);
const OTHERS_EVERY: Duration = Duration::from_secs(600);

fn notify(app: &AppHandle, body: &str) {
    use tauri_plugin_notification::NotificationExt;
    let _ = app.notification().builder().title("Phone Vault").body(body).show();
}

pub fn start(app: AppHandle) {
    let _ = std::thread::Builder::new().name("btc-watcher".into()).spawn(move || {
        let mut due: HashMap<String, Instant> = HashMap::new();
        // let the window and the EVM watcher start first
        std::thread::sleep(Duration::from_secs(8));
        loop {
            let woke = WAKE.swap(false, Ordering::SeqCst);
            let Ok(all) = store::load() else { std::thread::sleep(Duration::from_secs(5)); continue };
            for s in &all.accounts {
                let shown = all.active.get(s.network.wire()) == Some(&s.id);
                let every = if shown { SHOWN_EVERY } else { OTHERS_EVERY };
                if !(woke && shown) && due.get(&s.id).is_some_and(|t| t.elapsed() < every) { continue; }
                due.insert(s.id.clone(), Instant::now());
                if let Ok((incoming, _)) = super::refresh(&s.id, false) {
                    if crate::watcher::notify_enabled() {
                        for e in incoming.iter().take(3) {
                            let state = if e.status == "confirmed" { "" } else { " (unconfirmed)" };
                            notify(&app, &format!("Received {} {} on {}{state}.", tx::format_btc(e.net.unsigned_abs()), s.network.unit(), s.network.name()));
                        }
                    }
                    let _ = app.emit("btc-changed", serde_json::json!({"id": s.id}));
                }
            }
            // menu bar: Bitcoin (mainnet) across the paired accounts
            let mut total: Option<i64> = None;
            for s in all.accounts.iter().filter(|a| a.network == Net::Bitcoin) {
                if let Ok(c) = store::load_cache(&s.id) { if c.initial_done { *total.get_or_insert(0) += c.confirmed() as i64 + c.unconfirmed(); } }
            }
            crate::tray::set_btc_balance(&app, total.map(|t| t.max(0) as u64));
            let _ = crate::price::spot("BTC");
            for _ in 0..10 { if WAKE.load(Ordering::SeqCst) { break; } std::thread::sleep(Duration::from_secs(1)); }
        }
    });
}
