//! App wiring (the managed bridge, alerts, start-up) and the Tauri commands.

use super::*;
use crate::pairing;
use serde::{Deserialize, Serialize};

static APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// The bridge the app manages: permissions in the config dir, the paired address from the
/// pairing file, a `bridge-changed` event to the webview on every change.
pub fn create() -> Arc<Bridge> {
    use tauri::Emitter;
    Bridge::with_alerts(
        sites_path(),
        Box::new(|| pairing::load().ok().flatten()),
        Box::new(|| {
            if let Some(app) = APP.get() {
                let _ = app.emit("bridge-changed", ());
            }
        }),
        Box::new(on_alert),
    )
}

fn on_alert(alert: Alert) {
    use tauri::Emitter;
    let Some(app) = APP.get() else { return };
    match alert {
        Alert::Queued { origin, connect, method } => on_queued(app, &origin, connect, &method),
        // Shown in the app (Connections); no notification, so a site cannot spam the desktop.
        Alert::Blocked { origin, message } => {
            let _ = app.emit("bridge-blocked", json!({"origin": origin, "message": message}));
        }
        Alert::ShowWindow => crate::tray::show_main(app),
    }
}

/// A site's request now waits for the user: show the window, and post a notification in case
/// the window can't come forward (another Space, full screen). Nothing from the site's request
/// beyond its origin and method name goes into the notification.
fn on_queued(app: &tauri::AppHandle, origin: &str, connect: bool, method: &str) {
    use tauri_plugin_notification::NotificationExt;
    crate::tray::show_main(app);
    let host = origin.strip_prefix("https://").unwrap_or(origin);
    let what = if connect {
        "wants to connect".to_string()
    } else {
        match method {
            "eth_sendTransaction" => "wants you to send a transaction".into(),
            "wallet_switchEthereumChain" | "wallet_addEthereumChain" => "wants to switch network".into(),
            m if m.contains("sign") || m.contains("Sign") => "wants a signature".into(),
            _ => "is waiting for you".into(),
        }
    };
    let _ = app
        .notification()
        .builder()
        .title("Phone Vault")
        .body(format!("{host} {what}. Review it in Phone Vault Companion."))
        .show();
}

/// Called from setup: remember the handle for events and start listening.
pub fn start(app: &tauri::AppHandle, bridge: &Arc<Bridge>) {
    let _ = APP.set(app.clone());
    match socket_path() {
        Some(p) => {
            let _ = bridge.serve(&p);
        }
        None => {
            bridge.lock().listen_error = Some("no config directory".into());
        }
    }
}

#[derive(Serialize)]
pub struct BridgeStatus {
    pub listening: bool,
    pub error: Option<String>,
    pub socket: String,
    pub extension_id: String,
    pub firefox_id: String,
    pub connections: usize,
    pub hosts: Vec<HostState>,
    pub sites: Vec<SiteOut>,
    pub exe: String,
    pub exe_error: Option<String>,
}

fn status_of(b: &Bridge) -> BridgeStatus {
    let (listening, error) = b.listening();
    let exe = host_exe();
    let home = dirs::home_dir();
    let hosts = match (&home, &exe) {
        (Some(h), Ok(e)) => host_states(h, e),
        _ => vec![],
    };
    BridgeStatus {
        listening: listening.is_some(),
        error,
        socket: listening.map(|p| p.display().to_string()).unwrap_or_default(),
        extension_id: CHROME_EXTENSION_ID.into(),
        firefox_id: FIREFOX_EXTENSION_ID.into(),
        connections: b.connection_count(),
        hosts,
        sites: b.sites(),
        exe: exe.as_ref().map(|p| p.display().to_string()).unwrap_or_default(),
        exe_error: exe.err(),
    }
}

type St<'a> = tauri::State<'a, Arc<Bridge>>;

#[tauri::command]
pub fn bridge_status(b: St<'_>) -> BridgeStatus {
    status_of(&b)
}

#[tauri::command]
pub fn bridge_pending(b: St<'_>) -> Vec<PendingOut> {
    b.pending()
}

#[derive(Deserialize)]
pub struct RpcErrorIn {
    code: i64,
    message: String,
}

#[tauri::command]
pub fn bridge_respond(b: St<'_>, id: u64, result: Option<Value>, error: Option<RpcErrorIn>) -> Result<(), String> {
    b.respond(id, result, error.map(|e| rpc(e.code, e.message)))
}

#[tauri::command]
pub fn bridge_approve_connect(b: St<'_>, id: u64, chains: Vec<u64>) -> Result<(), String> {
    b.approve_connect(id, &chains)
}

#[tauri::command]
pub fn bridge_update_site(
    b: St<'_>,
    origin: String,
    chains: Option<Vec<u64>>,
    active: Option<u64>,
) -> Result<(), String> {
    b.update_site(&origin, chains, active)
}

#[tauri::command]
pub fn bridge_revoke(b: St<'_>, origin: String) {
    b.revoke(&origin)
}

#[tauri::command]
pub fn bridge_set_nodes(b: St<'_>, nodes: HashMap<String, String>) -> Result<(), String> {
    let parsed = nodes.into_iter().filter_map(|(k, v)| k.parse::<u64>().ok().map(|c| (c, v))).collect();
    b.set_nodes(parsed)
}

/// "Install browser connection": writes the native host manifests (user action only).
#[tauri::command]
pub fn bridge_install(b: St<'_>) -> Result<BridgeStatus, String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    install_hosts(&home, &host_exe()?)?;
    Ok(status_of(&b))
}

#[tauri::command]
pub fn bridge_uninstall(b: St<'_>) -> Result<BridgeStatus, String> {
    let home = dirs::home_dir().ok_or("no home directory")?;
    uninstall_hosts(&home, &host_exe()?);
    Ok(status_of(&b))
}
