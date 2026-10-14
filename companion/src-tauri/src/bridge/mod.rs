//! Browser extension bridge: the Phone Vault extension is one more dApp transport, next to
//! WalletConnect. Nothing here talks to the phone or can produce a signature. Requests that need
//! the user (connect, sign, send, switch to a new network) are queued for the webview, which shows
//! the same cards as for WalletConnect and runs the same verified commands (`wc_prepare` →
//! `send::sign_start` → `broadcast_verified`, `signing::sign_message` / `sign_typed_data`).
//! Design and threat model: vault-os/docs/browser-extension.md.
//!
//! Transport: Chrome/Firefox native messaging. The browser starts this same executable as the
//! "native host" (`native_host_main`) for the pinned extension only; the host relays length-prefixed
//! JSON frames between the browser (stdin/stdout) and the running companion over a Unix socket in
//! the companion's 0700 config directory. No TCP port is opened, so web pages and other machines
//! cannot reach the bridge at all; the companion additionally checks that the socket peer is the
//! same user and the same executable.
//!
//! What lives here:
//! * frame codec, origin normalization, request validation, per-origin rate limits and size caps;
//! * per-origin permissions (`browser-sites.json`, 0600): connected account, approved networks,
//!   active network. The account is always the PAIRED address read from the pairing file; a site
//!   connected under another pairing is treated as not connected;
//! * method policy, reusing `wc.rs` (`route`, `normalize_tx`): the same allow-list and parameter
//!   checks as WalletConnect, plus read-only node calls forwarded to the user's node for that network;
//! * native host manifests ("Install browser connection"), pinned to the extension ID.
//!
//! Layout: this file holds the `Bridge` and its webview-side API; `requests` handles frames from
//! the extension, `server` the socket, `frame`/`origin`/`sites`/`policy`/`state`/`proxy` the pieces
//! above, `host` the native host relay, `manifest` the host manifests, `commands` the Tauri wiring.

mod commands;
mod frame;
mod host;
mod manifest;
mod origin;
mod policy;
mod proxy;
mod requests;
mod server;
mod sites;
mod state;

pub use commands::*;
pub use frame::{read_frame, write_frame};
pub use host::{native_host_caller, native_host_main, socket_path};
pub use manifest::{
    host_exe, host_manifest, host_states, install_hosts, manifest_path, uninstall_hosts, HostState, HostTarget,
    HOST_TARGETS,
};
pub use origin::{normalize_origin, origin_host, origin_is_local, registrable_domain};
pub use policy::{check_result, connected, decide, Decision};
pub use proxy::sanitize_node_reply;
pub use server::{allowed_caller, same_file};
pub use sites::{load_sites, save_sites, sites_path, Site};
pub use state::{Alert, Backoff, PendingKind, PendingOut, SiteOut};

use state::Pending;

use crate::{verify, wc};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Native messaging host name (also the manifest file name).
pub const HOST_NAME: &str = "dev.phonevault";
/// The extension's ID, pinned by the public key in extension/manifest (`key`). Chrome refuses to
/// start the host for any other extension; the companion checks it again.
pub const CHROME_EXTENSION_ID: &str = "fbomijndbpoddicmbngledanaafapmlk";
/// Firefox add-on ID (browser_specific_settings.gecko.id).
pub const FIREFOX_EXTENSION_ID: &str = "browser-extension@phonevault.dev";

/// Largest frame accepted from the extension (Chrome allows 64 MiB; nothing legitimate is near this).
pub const MAX_IN_FRAME: usize = 512 * 1024;
/// Largest frame sent to the extension. Chrome drops the host for a message over 1 MiB.
pub const MAX_OUT_FRAME: usize = 1024 * 1024 - 8 * 1024;
/// Network a site sees before it is connected (the app's default network).
pub const DEFAULT_CHAIN: u64 = 8453;
/// Requests waiting for the user, per site, per registrable domain (all of a site's subdomains
/// together, see `registrable_domain`) and in total. More are refused (-32005).
pub const MAX_PENDING_PER_ORIGIN: usize = 4;
pub const MAX_PENDING_PER_DOMAIN: usize = 8;
pub const MAX_PENDING_TOTAL: usize = 16;
/// After the user rejects a connection, new connection requests from the same registrable domain
/// are refused at once (4001, no window, no notification) for this long, doubling on every further
/// rejection up to the maximum; an approved connection resets it.
pub const CONNECT_BACKOFF_START: Duration = Duration::from_secs(30);
pub const CONNECT_BACKOFF_MAX: Duration = Duration::from_secs(600);
/// A connection request the site withdraws itself before the user answers (the extension sends
/// "cancel" when the tab reloads or navigates) counts towards the same backoff, starting shorter:
/// otherwise a page that reloads in a loop could raise the window and notify without limit.
pub const CONNECT_WITHDRAWN_BACKOFF_START: Duration = Duration::from_secs(10);
/// A waiting request brings the window forward and posts a notification (Alert::Queued) at most
/// this often per registrable domain, until the user answers one of that domain's requests.
pub const QUEUED_ALERT_EVERY: Duration = Duration::from_secs(30);
/// A refused sign-in for another site is shown in the app at most this often per site.
const BLOCKED_NOTICE_EVERY: Duration = Duration::from_secs(10);
/// The extension popup's "Open Phone Vault Companion" brings the window forward at most this often.
const SHOW_WINDOW_EVERY: Duration = Duration::from_secs(2);
/// Node calls in flight at once, all sites together.
const MAX_PROXY_INFLIGHT: usize = 16;
/// Token bucket per site: bursts of 60, 20 requests per second sustained.
const BUCKET_CAPACITY: f64 = 60.0;
const BUCKET_REFILL_PER_SEC: f64 = 20.0;
const MAX_SITES: usize = 500;

/// Read-only calls forwarded to the user's node for the site's network, for connected sites only.
pub const READ_ONLY_METHODS: [&str; 16] = [
    "eth_blockNumber",
    "eth_call",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_gasPrice",
    "eth_getBalance",
    "eth_getBlockByHash",
    "eth_getBlockByNumber",
    "eth_getCode",
    "eth_getLogs",
    "eth_getStorageAt",
    "eth_getTransactionByHash",
    "eth_getTransactionCount",
    "eth_getTransactionReceipt",
    "eth_maxPriorityFeePerGas",
    "eth_getBlockTransactionCountByNumber",
];
/// Methods that put a card in front of the user (after the `wc.rs` checks pass).
pub const PROMPT_METHODS: [&str; 4] =
    ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain"];

const LIMITED: i64 = -32005;
const USER_REJECTED: i64 = 4001;
const ALREADY_PENDING: i64 = -32002;
const INVALID_REQUEST: i64 = -32600;

fn rpc(code: i64, message: impl Into<String>) -> wc::RpcError {
    wc::RpcError { code, message: message.into() }
}
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

struct Conn {
    writer: Arc<Mutex<UnixStream>>,
}

#[derive(Default)]
struct Inner {
    sites: Vec<Site>,
    pending: Vec<Pending>,
    conns: HashMap<u64, Conn>,
    buckets: HashMap<String, (f64, Instant)>,
    nodes: HashMap<u64, String>,
    /// node URL → chain it answered for (checked once per URL before forwarding)
    node_chain: HashMap<String, u64>,
    listening: Option<PathBuf>,
    listen_error: Option<String>,
    /// registrable domain → connection backoff after a rejection
    backoff: HashMap<String, Backoff>,
    /// origin → when a refused sign-in was last shown in the app
    blocked_shown: HashMap<String, Instant>,
    /// registrable domain → when a waiting request last raised the window and notified
    queued_alerted: HashMap<String, Instant>,
    last_show_window: Option<Instant>,
}

type Paired = Box<dyn Fn() -> Option<String> + Send + Sync>;
type Notify = Box<dyn Fn() + Send + Sync>;
type Alerts = Box<dyn Fn(Alert) + Send + Sync>;

pub struct Bridge {
    inner: Mutex<Inner>,
    store: Option<PathBuf>,
    paired: Paired,
    notify: Notify,
    alerts: Alerts,
    next_id: AtomicU64,
    next_conn: AtomicU64,
    proxies: Arc<AtomicUsize>,
}

impl Bridge {
    /// `store`: where permissions persist (None = memory only, for tests). `paired`: the pinned
    /// signer address (lowercase), read fresh for every decision. `notify`: the webview should refresh.
    pub fn new(store: Option<PathBuf>, paired: Paired, notify: Notify) -> Arc<Bridge> {
        Self::with_alerts(store, paired, notify, Box::new(|_| {}))
    }

    /// As `new`, with `alerts` for the window/notification side effects (the app wires on_alert).
    pub fn with_alerts(store: Option<PathBuf>, paired: Paired, notify: Notify, alerts: Alerts) -> Arc<Bridge> {
        let sites = store.as_deref().map(load_sites).unwrap_or_default();
        Arc::new(Bridge {
            inner: Mutex::new(Inner { sites, ..Default::default() }),
            store,
            paired,
            notify,
            alerts,
            next_id: AtomicU64::new(1),
            next_conn: AtomicU64::new(1),
            proxies: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn persist(&self, inner: &Inner) {
        if let Some(p) = &self.store {
            let _ = save_sites(p, &inner.sites);
        }
    }
    fn paired(&self) -> Option<String> {
        (self.paired)().map(|p| p.to_ascii_lowercase())
    }

    fn send_to(writer: &Arc<Mutex<UnixStream>>, msg: &Value) {
        let mut body = serde_json::to_vec(msg).unwrap_or_default();
        if body.len() > MAX_OUT_FRAME {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            body = serde_json::to_vec(&json!({"type": "response", "id": id, "error": {"code": LIMITED, "message": "The answer is too large to pass to the browser."}})).unwrap_or_default();
        }
        if let Ok(mut w) = writer.lock() {
            let _ = write_frame(&mut *w, &body, MAX_OUT_FRAME);
        }
    }

    fn reply(&self, conn: u64, ext_id: u64, outcome: Result<Value, Value>) {
        let writer = self.lock().conns.get(&conn).map(|c| c.writer.clone());
        let Some(w) = writer else { return };
        let msg = match outcome {
            Ok(result) => json!({"type": "response", "id": ext_id, "result": result}),
            Err(error) => json!({"type": "response", "id": ext_id, "error": error}),
        };
        Self::send_to(&w, &msg);
    }

    fn reply_err(&self, conn: u64, ext_id: u64, e: wc::RpcError) {
        self.reply(conn, ext_id, Err(json!({"code": e.code, "message": e.message})));
    }

    /// Push an EIP-1193 event to every tab of `origin` (the extension routes by origin).
    fn emit(&self, origin: &str, name: &str, data: Value) {
        let writers: Vec<_> = self.lock().conns.values().map(|c| c.writer.clone()).collect();
        let msg = json!({"type": "event", "origin": origin, "name": name, "data": data});
        for w in writers {
            Self::send_to(&w, &msg);
        }
    }

    // ------------------------------------------------ webview side

    pub fn pending(&self) -> Vec<PendingOut> {
        self.lock()
            .pending
            .iter()
            .map(|p| PendingOut {
                id: p.id,
                kind: p.kind,
                origin: p.origin.clone(),
                host: origin_host(&p.origin),
                local: origin_is_local(&p.origin),
                method: p.method.clone(),
                params: p.params.clone(),
                chain_id: p.chain,
                created: p.created,
            })
            .collect()
    }

    fn take_pending(&self, id: u64) -> Option<Pending> {
        let mut g = self.lock();
        let i = g.pending.iter().position(|p| p.id == id)?;
        Some(g.pending.remove(i))
    }

    /// Answer a request card. `error` = rejected or failed; `result` must have the shape the
    /// verified pipeline produces for that method (see `check_result`).
    pub fn respond(&self, id: u64, result: Option<Value>, error: Option<wc::RpcError>) -> Result<(), String> {
        let p = {
            let g = self.lock();
            g.pending.iter().find(|p| p.id == id).cloned()
        }
        .ok_or("the site is no longer waiting for this request")?;
        // The user answered this site family: its next request may alert again at once.
        self.lock().queued_alerted.remove(&registrable_domain(&p.origin));
        match (result, error) {
            (_, Some(e)) => {
                let code = if (-32768..=4999).contains(&e.code) { e.code } else { wc::INTERNAL };
                let message: String = e.message.chars().take(500).collect();
                self.take_pending(id);
                if p.kind == PendingKind::Connect && code == USER_REJECTED {
                    // The user said no: new connects from this site family wait out a backoff.
                    let mut g = self.lock();
                    let domain = registrable_domain(&p.origin);
                    let next = Backoff::after_rejection(g.backoff.get(&domain).copied(), Instant::now());
                    g.backoff.insert(domain, next);
                    if g.backoff.len() > MAX_SITES {
                        let now = Instant::now();
                        g.backoff.retain(|_, b| b.remaining(now).is_some());
                    }
                }
                self.reply_err(p.conn, p.ext_id, rpc(code, message));
            }
            (Some(r), None) => {
                if p.kind == PendingKind::Connect {
                    return Err("a connection is approved with bridge_approve_connect".into());
                }
                check_result(&p.method, &r)?;
                self.take_pending(id);
                self.reply(p.conn, p.ext_id, Ok(r));
            }
            (None, None) => {
                if p.method != "wallet_switchEthereumChain" {
                    return Err("no result".into());
                }
                self.take_pending(id);
                self.reply(p.conn, p.ext_id, Ok(Value::Null));
            }
        }
        (self.notify)();
        Ok(())
    }

    /// Refuse a waiting request (or connection) with a JSON-RPC error.
    pub fn reject(&self, id: u64, code: i64, message: &str) -> Result<(), String> {
        self.respond(id, None, Some(rpc(code, message)))
    }

    /// The user approved "<site> wants to connect" for these networks (first = active).
    pub fn approve_connect(&self, id: u64, chains: &[u64]) -> Result<(), String> {
        let paired = self.paired().ok_or("pair your phone first")?;
        let mut list: Vec<u64> = vec![];
        for &c in chains {
            if !wc::chain_allowed(c) {
                return Err(format!("your phone has no reviewed profile for chain {c}"));
            }
            if !list.contains(&c) {
                list.push(c);
            }
        }
        if list.is_empty() {
            return Err("choose at least one network".into());
        }
        let p = {
            let g = self.lock();
            g.pending
                .iter()
                .find(|p| p.id == id && p.kind == PendingKind::Connect)
                .cloned()
                .ok_or("the site is no longer waiting for this connection")?
        };
        {
            let mut g = self.lock();
            g.sites.retain(|s| s.origin != p.origin);
            if g.sites.len() >= MAX_SITES {
                g.sites.remove(0);
            }
            g.sites.push(Site {
                origin: p.origin.clone(),
                address: paired.clone(),
                active: list[0],
                chains: list.clone(),
                connected_at: now_secs(),
            });
            g.pending.retain(|x| x.id != id);
            g.backoff.remove(&registrable_domain(&p.origin));
            g.queued_alerted.remove(&registrable_domain(&p.origin));
            self.persist(&g);
        }
        let account = verify::checksum(&paired);
        self.reply(p.conn, p.ext_id, Ok(json!([account])));
        self.emit(&p.origin, "chainChanged", json!(verify::to_quantity(list[0] as u128)));
        self.emit(&p.origin, "accountsChanged", json!([account]));
        (self.notify)();
        Ok(())
    }

    /// Change a connected site's approved networks and/or active network.
    pub fn update_site(&self, origin: &str, chains: Option<Vec<u64>>, active: Option<u64>) -> Result<(), String> {
        let origin = normalize_origin(origin)?;
        let changed_to = {
            let mut g = self.lock();
            let site = g.sites.iter_mut().find(|s| s.origin == origin).ok_or("this site is not connected")?;
            let mut next = site.clone();
            if let Some(list) = chains {
                if list.is_empty() || list.iter().any(|c| !wc::chain_allowed(*c)) {
                    return Err("networks must be ones your phone has a reviewed profile for".into());
                }
                next.chains = vec![];
                for c in list {
                    if !next.chains.contains(&c) {
                        next.chains.push(c);
                    }
                }
            }
            if let Some(a) = active {
                if !next.chains.contains(&a) {
                    return Err(format!("{} is not approved for this site", wc::chain_name(a)));
                }
                next.active = a;
            }
            if !next.chains.contains(&next.active) {
                next.active = next.chains[0];
            }
            let moved = (next.active != site.active).then_some(next.active);
            *site = next;
            self.persist(&g);
            moved
        };
        if let Some(c) = changed_to {
            self.emit(&origin, "chainChanged", json!(verify::to_quantity(c as u128)));
        }
        (self.notify)();
        Ok(())
    }

    /// Forget a site: it must ask to connect again. Its waiting requests are refused.
    pub fn revoke(&self, origin: &str) {
        let Ok(origin) = normalize_origin(origin) else { return };
        let dropped: Vec<Pending> = {
            let mut g = self.lock();
            g.sites.retain(|s| s.origin != origin);
            self.persist(&g);
            let (gone, keep): (Vec<_>, Vec<_>) =
                std::mem::take(&mut g.pending).into_iter().partition(|p| p.origin == origin);
            g.pending = keep;
            gone
        };
        for p in dropped {
            self.reply_err(p.conn, p.ext_id, rpc(wc::UNAUTHORIZED, "Disconnected in Phone Vault."));
        }
        self.emit(&origin, "accountsChanged", json!([]));
        (self.notify)();
    }

    /// Node per network, from the app's settings (https only).
    pub fn set_nodes(&self, nodes: HashMap<u64, String>) -> Result<(), String> {
        let mut clean = HashMap::new();
        for (chain, url) in nodes {
            if !wc::chain_allowed(chain) {
                continue;
            }
            if !url.starts_with("https://") || url.len() > 512 {
                return Err(format!("the node for chain {chain} must be an https:// URL"));
            }
            clean.insert(chain, url);
        }
        self.lock().nodes = clean;
        Ok(())
    }

    pub fn sites(&self) -> Vec<SiteOut> {
        let paired = self.paired();
        self.lock()
            .sites
            .iter()
            .map(|s| SiteOut {
                origin: s.origin.clone(),
                host: origin_host(&s.origin),
                local: origin_is_local(&s.origin),
                chains: s.chains.clone(),
                active: s.active,
                connected_at: s.connected_at,
                address: verify::checksum(&s.address),
                current_pairing: paired.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(&s.address)),
            })
            .collect()
    }

    pub fn connection_count(&self) -> usize {
        self.lock().conns.len()
    }
    pub fn listening(&self) -> (Option<PathBuf>, Option<String>) {
        let g = self.lock();
        (g.listening.clone(), g.listen_error.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    pub(super) const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
    pub(super) const OTHER: &str = "0x1111111111111111111111111111111111111111";

    pub(super) fn site(chains: &[u64], active: u64) -> Site {
        Site {
            origin: "https://app.example.org".into(),
            address: ME.into(),
            chains: chains.to_vec(),
            active,
            connected_at: 1,
        }
    }
    pub(super) fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pvb-{}-{}-{name}", std::process::id(), now_secs()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    // ------------------------------------------------ the socket end to end (same process = same exe)

    struct Client {
        s: UnixStream,
    }
    impl Client {
        fn connect(path: &Path, caller: &str) -> Client {
            let mut s = UnixStream::connect(path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            write_frame(&mut s, json!({"type": "relay_hello", "caller": caller}).to_string().as_bytes(), 4096).unwrap();
            Client { s }
        }
        fn send(&mut self, v: Value) {
            write_frame(&mut self.s, v.to_string().as_bytes(), MAX_IN_FRAME).unwrap();
        }
        fn raw(&mut self) -> Value {
            serde_json::from_slice(&read_frame(&mut self.s, MAX_OUT_FRAME).unwrap().unwrap()).unwrap()
        }
        /// Next frame, skipping "queued" notices (checked on their own below).
        fn recv(&mut self) -> Value {
            loop {
                let v = self.raw();
                if v["type"] != "queued" {
                    return v;
                }
            }
        }
        /// Next response (skipping events).
        fn response(&mut self) -> Value {
            loop {
                let v = self.recv();
                if v["type"] == "response" {
                    return v;
                }
            }
        }
        fn req(&mut self, id: u64, origin: &str, method: &str, params: Value) -> Value {
            self.send(json!({"type": "request", "id": id, "origin": origin, "method": method, "params": params}));
            self.response()
        }
    }

    fn wait_for(mut f: impl FnMut() -> bool) {
        for _ in 0..200 {
            if f() {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        panic!("timed out");
    }

    #[test]
    fn socket_flow_connect_sign_reject_revoke() {
        let d = std::env::temp_dir().join(format!("pvb{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("b.sock");
        let bridge = Bridge::new(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}));
        bridge.serve(&sock).unwrap();
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(
            Bridge::new(None, Box::new(|| None), Box::new(|| {})).serve(&sock).is_err(),
            "a second instance must not steal the socket"
        );

        // a relay speaking for another extension is dropped
        let mut wrong = Client::connect(&sock, "chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/");
        wrong.send(json!({"type": "hello"}));
        assert!(read_frame(&mut wrong.s, MAX_OUT_FRAME).map(|f| f.is_none()).unwrap_or(true));

        let mut c = Client::connect(&sock, &format!("chrome-extension://{CHROME_EXTENSION_ID}/"));
        c.send(json!({"type": "hello"}));
        assert_eq!(c.recv()["ok"], true);
        let o = "https://app.example.org";
        assert_eq!(c.req(1, o, "eth_chainId", json!([]))["result"], "0x2105");
        assert_eq!(c.req(2, o, "eth_accounts", json!([]))["result"], json!([]));
        assert_eq!(c.req(3, o, "personal_sign", json!(["hi", ME]))["error"]["code"], wc::UNAUTHORIZED);
        assert_eq!(c.req(4, "http://evil.org", "eth_chainId", json!([]))["error"]["code"], INVALID_REQUEST);

        // connect: queued for the user; a second connect from the same site is refused meanwhile
        c.send(json!({"type": "request", "id": 5, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(c.raw(), json!({"type": "queued", "id": 5}), "the extension is told the request waits for the user");
        assert_eq!(c.req(6, o, "eth_requestAccounts", json!([]))["error"]["code"], ALREADY_PENDING);
        let p = bridge.pending()[0].clone();
        assert_eq!((p.kind, p.host.as_str()), (PendingKind::Connect, "app.example.org"));
        assert!(bridge.respond(p.id, Some(json!([ME])), None).is_err(), "accounts are never supplied by the webview");
        assert!(bridge.approve_connect(p.id, &[56]).is_err(), "networks off the allow-list");
        bridge.approve_connect(p.id, &[10, 8453]).unwrap();
        let mut got = vec![];
        for _ in 0..3 {
            got.push(c.recv());
        }
        let resp = got.iter().find(|v| v["type"] == "response").unwrap();
        assert_eq!((resp["id"].as_u64(), resp["result"].clone()), (Some(5), json!([verify::checksum(ME)])));
        assert!(got
            .iter()
            .any(|v| v["type"] == "event" && v["name"] == "chainChanged" && v["data"] == "0xa" && v["origin"] == o));
        assert!(got.iter().any(|v| v["type"] == "event" && v["name"] == "accountsChanged"));
        assert_eq!(c.req(7, o, "eth_chainId", json!([]))["result"], "0xa");

        // proxy without a configured node: refused, not hung
        assert_eq!(c.req(8, o, "eth_blockNumber", json!([]))["error"]["code"], wc::CHAIN_DISCONNECTED);

        // a sign request is queued, the webview rejects it, the site gets 4001
        c.send(
            json!({"type": "request", "id": 9, "origin": o, "method": "personal_sign", "params": ["0x48656c6c6f", ME]}),
        );
        wait_for(|| bridge.pending().len() == 1);
        let p = bridge.pending()[0].clone();
        assert_eq!((p.kind, p.method.as_str(), p.chain_id), (PendingKind::Request, "personal_sign", 10));
        assert!(bridge.respond(p.id, Some(json!("0x1234")), None).is_err(), "malformed signature refused");
        bridge.respond(p.id, None, Some(rpc(4001, "User rejected the request."))).unwrap();
        let r = c.response();
        assert_eq!((r["id"].as_u64(), r["error"]["code"].as_i64()), (Some(9), Some(4001)));

        // switching to an approved network is immediate and announced
        c.send(json!({"type": "request", "id": 10, "origin": o, "method": "wallet_switchEthereumChain", "params": [{"chainId": "0x2105"}]}));
        let mut saw_event = false;
        loop {
            let v = c.recv();
            if v["type"] == "event" {
                saw_event |= v["data"] == "0x2105";
            } else {
                assert_eq!(v["id"], 10);
                assert!(v["result"].is_null());
                break;
            }
        }
        let _ = saw_event; // the event may follow the response; checked through state:
        assert_eq!(c.req(11, o, "eth_chainId", json!([]))["result"], "0x2105");

        // pending caps per site
        for i in 0..MAX_PENDING_PER_ORIGIN as u64 {
            c.send(json!({"type": "request", "id": 100 + i, "origin": o, "method": "personal_sign", "params": ["0x01", ME]}));
        }
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_ORIGIN);
        assert_eq!(c.req(200, o, "personal_sign", json!(["0x01", ME]))["error"]["code"], LIMITED);
        // cancel (tab closed) removes one
        c.send(json!({"type": "cancel", "id": 100}));
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_ORIGIN - 1);

        // revoke: waiting requests are refused, the site is told, and it is not connected any more
        bridge.revoke(o);
        let mut refused = 0;
        loop {
            let v = c.recv();
            if v["type"] == "response" {
                assert_eq!(v["error"]["code"], wc::UNAUTHORIZED);
                refused += 1;
            } else if v["name"] == "accountsChanged" {
                assert_eq!(v["data"], json!([]));
                break;
            }
        }
        assert_eq!(refused, MAX_PENDING_PER_ORIGIN - 1);
        assert_eq!(c.req(12, o, "eth_accounts", json!([]))["result"], json!([]));

        // a sign-in message for another site never reaches the user, and the app is told once
        c.send(json!({"type": "request", "id": 30, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.approve_connect(bridge.pending()[0].id, &[1]).unwrap();
        assert_eq!(c.response()["id"], 30);
        let siwe = |domain: &str| {
            format!("{domain} wants you to sign in with your Ethereum account:\n{ME}\n\nURI: https://{domain}\nVersion: 1\nChain ID: 1\nNonce: 1\nIssued At: 2021-09-30T16:25:24Z")
        };
        let r = c.req(31, o, "personal_sign", json!([siwe("opensea.io"), ME]));
        assert_eq!(r["error"]["code"], wc::UNAUTHORIZED);
        assert!(
            r["error"]["message"]
                .as_str()
                .unwrap()
                .starts_with("Blocked: app.example.org asked you to sign in to opensea.io"),
            "{r}"
        );
        assert!(bridge.pending().is_empty());
        let _ = c.req(32, o, "personal_sign", json!([siwe("opensea.io"), ME]));
        // the matching site's own sign-in is queued as usual
        c.send(json!({"type": "request", "id": 33, "origin": o, "method": "personal_sign", "params": [siwe("app.example.org"), ME]}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.reject(bridge.pending()[0].id, 4001, "no").unwrap();
        assert_eq!(c.response()["id"], 33);
        bridge.revoke(o);
        loop {
            let v = c.recv();
            if v["name"] == "accountsChanged" {
                break;
            }
        }

        // closing the connection drops what it left waiting
        c.send(json!({"type": "request", "id": 13, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        drop(c);
        wait_for(|| bridge.pending().is_empty() && bridge.connection_count() == 0);
        let _ = std::fs::remove_dir_all(d);
    }

    fn alert_log() -> (Arc<Mutex<Vec<Alert>>>, Alerts) {
        let log = Arc::new(Mutex::new(vec![]));
        let l = log.clone();
        (log, Box::new(move |a| l.lock().unwrap().push(a)))
    }

    #[test]
    fn rejected_connects_back_off_per_domain_without_alerts() {
        let d = std::env::temp_dir().join(format!("pvk{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("k.sock");
        let (log, alerts) = alert_log();
        let bridge = Bridge::with_alerts(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}), alerts);
        bridge.serve(&sock).unwrap();
        let mut c = Client::connect(&sock, &format!("chrome-extension://{CHROME_EXTENSION_ID}/"));
        let o = "https://app.spam.example";
        let queued = |log: &Arc<Mutex<Vec<Alert>>>| {
            log.lock().unwrap().iter().filter(|a| matches!(a, Alert::Queued { .. })).count()
        };

        // first connect: queued, alerted; the user rejects it
        c.send(json!({"type": "request", "id": 1, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(queued(&log), 1);
        bridge.reject(bridge.pending()[0].id, 4001, "User rejected the request.").unwrap();
        assert_eq!(c.response()["error"]["code"], 4001);

        // during the backoff: refused at once, nothing queued, no window or notification —
        // from the same origin and from another subdomain of the same site
        for (id, origin) in [(2, o), (3, "https://other.spam.example"), (4, o)] {
            let r = c.req(id, origin, "eth_requestAccounts", json!([]));
            assert_eq!(r["error"]["code"], 4001, "{origin}");
            assert!(r["error"]["message"].as_str().unwrap().contains("spam.example"));
        }
        assert!(bridge.pending().is_empty());
        assert_eq!(queued(&log), 1, "no alert during the backoff");
        // other sites and non-connect calls are unaffected
        assert_eq!(c.req(5, o, "eth_chainId", json!([]))["result"], "0x2105");
        c.send(json!({"type": "request", "id": 6, "origin": "https://fine.example", "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.reject(bridge.pending()[0].id, -32603, "not a user rejection").unwrap();
        assert_eq!(c.response()["id"], 6);
        c.send(json!({"type": "request", "id": 7, "origin": "https://fine.example", "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.reject(bridge.pending()[0].id, -32603, "x").unwrap();
        assert_eq!(c.response()["id"], 7);

        // the backoff runs out: asked again, rejected again → the next penalty doubled
        let dom = registrable_domain(o);
        assert_eq!(bridge.lock().backoff[&dom].next, Duration::from_secs(60));
        bridge.lock().backoff.get_mut(&dom).unwrap().until = Instant::now();
        c.send(json!({"type": "request", "id": 8, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.reject(bridge.pending()[0].id, 4001, "no").unwrap();
        assert_eq!(c.response()["id"], 8);
        let b = bridge.lock().backoff[&dom];
        assert!(b.remaining(Instant::now()).unwrap() > Duration::from_secs(50), "second rejection: 60 s");
        assert_eq!(b.next, Duration::from_secs(120));

        // an approval resets it
        bridge.lock().backoff.get_mut(&dom).unwrap().until = Instant::now();
        c.send(json!({"type": "request", "id": 9, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.approve_connect(bridge.pending()[0].id, &[8453]).unwrap();
        assert_eq!(c.response()["id"], 9);
        assert!(!bridge.lock().backoff.contains_key(&dom));
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn queued_alerts_are_rate_limited_per_domain_until_the_user_answers() {
        let d = std::env::temp_dir().join(format!("pvq{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("q.sock");
        let (log, alerts) = alert_log();
        let bridge = Bridge::with_alerts(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}), alerts);
        bridge.serve(&sock).unwrap();
        let mut c = Client::connect(&sock, &format!("chrome-extension://{CHROME_EXTENSION_ID}/"));
        let queued = |log: &Arc<Mutex<Vec<Alert>>>| {
            log.lock().unwrap().iter().filter(|a| matches!(a, Alert::Queued { .. })).count()
        };
        let o = "https://app.loop.example";
        c.send(json!({"type": "request", "id": 1, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        bridge.approve_connect(bridge.pending()[0].id, &[8453]).unwrap();
        assert_eq!(c.response()["id"], 1);
        assert_eq!(queued(&log), 1);

        // a connected site queues and withdraws sign requests in a loop: one alert, not one each
        for id in 10..20u64 {
            c.send(
                json!({"type": "request", "id": id, "origin": o, "method": "personal_sign", "params": ["0x01", ME]}),
            );
            wait_for(|| bridge.pending().len() == 1);
            c.send(json!({"type": "cancel", "id": id}));
            wait_for(|| bridge.pending().is_empty());
        }
        assert_eq!(queued(&log), 2, "one more alert for the whole loop");
        // another site family is not affected
        c.send(json!({"type": "request", "id": 30, "origin": "https://other.example", "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(queued(&log), 3);
        bridge.reject(bridge.pending()[0].id, -32603, "x").unwrap();
        assert_eq!(c.response()["id"], 30);

        // once the user answers one of the site's requests, its next request alerts at once
        c.send(json!({"type": "request", "id": 40, "origin": o, "method": "personal_sign", "params": ["0x01", ME]}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(queued(&log), 3, "still within the window");
        bridge.reject(bridge.pending()[0].id, 4001, "no").unwrap();
        assert_eq!(c.response()["id"], 40);
        c.send(json!({"type": "request", "id": 41, "origin": o, "method": "personal_sign", "params": ["0x01", ME]}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(queued(&log), 4);
        // and the window expires on its own
        c.send(json!({"type": "cancel", "id": 41}));
        wait_for(|| bridge.pending().is_empty());
        bridge.lock().queued_alerted.insert(registrable_domain(o), Instant::now() - QUEUED_ALERT_EVERY);
        c.send(json!({"type": "request", "id": 42, "origin": o, "method": "personal_sign", "params": ["0x01", ME]}));
        wait_for(|| bridge.pending().len() == 1);
        assert_eq!(queued(&log), 5);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn withdrawn_connects_back_off_from_ten_seconds() {
        let t0 = Instant::now();
        let w = Backoff::after_withdrawal(None, t0);
        assert_eq!(
            (w.until - t0, w.next, w.withdrawn),
            (CONNECT_WITHDRAWN_BACKOFF_START, Duration::from_secs(20), true)
        );
        let w2 = Backoff::after_withdrawal(Some(w), t0);
        assert_eq!((w2.until - t0, w2.next), (Duration::from_secs(20), Duration::from_secs(40)));
        // a rejection after withdrawals never backs off less than a first rejection
        let r = Backoff::after_rejection(Some(w), t0);
        assert_eq!((r.until - t0, r.next, r.withdrawn), (CONNECT_BACKOFF_START, Duration::from_secs(60), false));
        let mut b = None;
        for _ in 0..10 {
            b = Some(Backoff::after_withdrawal(b, t0));
        }
        assert_eq!(b.unwrap().next, CONNECT_BACKOFF_MAX);
    }

    #[test]
    fn pending_cap_per_registrable_domain_and_show_window() {
        let d = std::env::temp_dir().join(format!("pvd{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("d.sock");
        let (log, alerts) = alert_log();
        let bridge = Bridge::with_alerts(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}), alerts);
        bridge.serve(&sock).unwrap();
        let mut c = Client::connect(&sock, &format!("chrome-extension://{CHROME_EXTENSION_ID}/"));
        // one connect from each of many subdomains: only MAX_PENDING_PER_DOMAIN wait
        for i in 0..MAX_PENDING_PER_DOMAIN as u64 {
            c.send(json!({"type": "request", "id": i, "origin": format!("https://s{i}.flood.example"), "method": "eth_requestAccounts", "params": []}));
        }
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_DOMAIN);
        assert_eq!(c.req(100, "https://s99.flood.example", "eth_requestAccounts", json!([]))["error"]["code"], LIMITED);
        // another site still gets through
        c.send(json!({"type": "request", "id": 101, "origin": "https://other.example", "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_DOMAIN + 1);

        // the popup's "Open Phone Vault Companion": answered, throttled
        c.send(json!({"type": "show_window", "id": 500}));
        assert_eq!(c.response()["result"], true);
        c.send(json!({"type": "show_window", "id": 501}));
        assert_eq!(c.response()["result"], false, "throttled");
        assert_eq!(log.lock().unwrap().iter().filter(|a| **a == Alert::ShowWindow).count(), 1);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn rate_limit_over_the_socket() {
        let d = std::env::temp_dir().join(format!("pvr{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("r.sock");
        let bridge = Bridge::new(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}));
        bridge.serve(&sock).unwrap();
        let mut c = Client::connect(&sock, &format!("chrome-extension://{CHROME_EXTENSION_ID}/"));
        let o = "https://spam.example";
        // send from another thread: the server answers while the burst is still arriving
        let mut w = c.s.try_clone().unwrap();
        let sender = std::thread::spawn(move || {
            for i in 0..200u64 {
                write_frame(
                    &mut w,
                    json!({"type": "request", "id": i, "origin": o, "method": "eth_chainId", "params": []})
                        .to_string()
                        .as_bytes(),
                    MAX_IN_FRAME,
                )
                .unwrap();
            }
        });
        let limited = (0..200).filter(|_| c.response().get("error").is_some()).count();
        sender.join().unwrap();
        assert!(limited >= 100, "most of a 200-request burst is refused ({limited})");
        // another site is unaffected
        assert_eq!(c.req(999, "https://other.example", "eth_chainId", json!([]))["result"], "0x2105");
        let _ = std::fs::remove_dir_all(d);
    }
}
