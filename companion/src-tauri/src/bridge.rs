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

use crate::{pairing, verify, wc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
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
/// Requests waiting for the user, per site and in total. More are refused (-32005).
pub const MAX_PENDING_PER_ORIGIN: usize = 4;
pub const MAX_PENDING_TOTAL: usize = 16;
/// Node calls in flight at once, all sites together.
const MAX_PROXY_INFLIGHT: usize = 16;
/// Token bucket per site: bursts of 60, 20 requests per second sustained.
const BUCKET_CAPACITY: f64 = 60.0;
const BUCKET_REFILL_PER_SEC: f64 = 20.0;
const MAX_SITES: usize = 500;

/// Read-only calls forwarded to the user's node for the site's network, for connected sites only.
pub const READ_ONLY_METHODS: [&str; 16] = [
    "eth_blockNumber", "eth_call", "eth_estimateGas", "eth_feeHistory", "eth_gasPrice", "eth_getBalance",
    "eth_getBlockByHash", "eth_getBlockByNumber", "eth_getCode", "eth_getLogs", "eth_getStorageAt",
    "eth_getTransactionByHash", "eth_getTransactionCount", "eth_getTransactionReceipt", "eth_maxPriorityFeePerGas",
    "eth_getBlockTransactionCountByNumber",
];
/// Methods that put a card in front of the user (after the `wc.rs` checks pass).
pub const PROMPT_METHODS: [&str; 4] = ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain"];

const LIMITED: i64 = -32005;
const ALREADY_PENDING: i64 = -32002;
const INVALID_REQUEST: i64 = -32600;

fn rpc(code: i64, message: impl Into<String>) -> wc::RpcError { wc::RpcError { code, message: message.into() } }
fn now_secs() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

// ---------------------------------------------------------------- frames

/// Native messaging framing: a 32-bit length in native byte order, then that many bytes of UTF-8
/// JSON. The same framing is used on the companion socket. `Ok(None)` is a clean end of stream.
pub fn read_frame(r: &mut impl Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > max { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame of {n} bytes exceeds {max}"))); }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame(w: &mut impl Write, body: &[u8], max: usize) -> std::io::Result<()> {
    if body.len() > max { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame of {} bytes exceeds {max}", body.len()))); }
    let mut buf = Vec::with_capacity(body.len() + 4);
    buf.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

// ---------------------------------------------------------------- origins

/// The site's origin as the browser reported it (`MessageSender.origin` in the extension, never a
/// value from the page). Accepted: `https://host[:port]`, and `http://` only for localhost,
/// 127.0.0.1 and [::1] (local development). Hosts must be ASCII (IDNs arrive in punycode).
pub fn normalize_origin(s: &str) -> Result<String, String> {
    if s.is_empty() || s.len() > 270 { return Err("origin missing or too long".into()); }
    let lower = s.to_ascii_lowercase();
    let (scheme, rest) = lower.split_once("://").ok_or("origin has no scheme")?;
    if scheme != "https" && scheme != "http" { return Err(format!("{scheme}: pages are not supported")); }
    if rest.is_empty() || rest.bytes().any(|b| matches!(b, b'/' | b'?' | b'#' | b'@' | b'\\' | b'%') || b <= b' ' || b >= 0x7f) {
        return Err("origin must be scheme://host[:port] only".into());
    }
    let (host, port) = if rest.starts_with('[') {
        let end = rest.find(']').ok_or("bad IPv6 origin")?;
        (&rest[..=end], &rest[end + 1..])
    } else {
        match rest.find(':') { Some(i) => (&rest[..i], &rest[i..]), None => (rest, "") }
    };
    if !port.is_empty() {
        let digits = port.strip_prefix(':').ok_or("bad port")?;
        if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) || digits.starts_with('0') { return Err("bad port".into()); }
        if digits.parse::<u32>().map_err(|_| "bad port")? > 65535 { return Err("bad port".into()); }
    }
    let local = matches!(host, "localhost" | "127.0.0.1" | "[::1]");
    if host.starts_with('[') && host != "[::1]" { return Err("IPv6 literal origins are not supported".into()); }
    if !host.starts_with('[') {
        if host.is_empty() || host.len() > 253 { return Err("bad host".into()); }
        for label in host.split('.') {
            if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') || !label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
                return Err(format!("bad host {host:?}"));
            }
        }
    }
    if scheme == "http" && !local { return Err("plain http:// sites are refused; only https:// (and localhost for development)".into()); }
    Ok(format!("{scheme}://{host}{port}"))
}

/// "app.uniswap.org" from "https://app.uniswap.org" (port kept when present).
pub fn origin_host(origin: &str) -> String { origin.split_once("://").map(|(_, h)| h.to_string()).unwrap_or_else(|| origin.to_string()) }
pub fn origin_is_local(origin: &str) -> bool { origin.starts_with("http://") }

fn valid_method(m: &str) -> bool { !m.is_empty() && m.len() <= 64 && m.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') }

// ---------------------------------------------------------------- sites (permissions)

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
            && self.address.len() == 42 && self.address.starts_with("0x") && self.address[2..].bytes().all(|b| b.is_ascii_hexdigit())
            && !self.chains.is_empty() && self.chains.iter().all(|c| wc::chain_allowed(*c)) && self.chains.contains(&self.active)
    }
}

#[derive(Serialize, Deserialize, Default)]
struct SitesFile { version: u32, sites: Vec<Site> }

pub fn sites_path() -> Option<PathBuf> { dirs::config_dir().map(|d| d.join("PhoneVault").join("browser-sites.json")) }

/// Sites file: 0600 (it is browsing history of a kind); a looser file is ignored, as is any entry
/// that does not validate.
pub fn load_sites(path: &Path) -> Vec<Site> {
    let Ok(meta) = std::fs::symlink_metadata(path) else { return vec![] };
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 { return vec![]; }
    let Ok(text) = std::fs::read_to_string(path) else { return vec![] };
    let Ok(file) = serde_json::from_str::<SitesFile>(&text) else { return vec![] };
    let mut out: Vec<Site> = vec![];
    for s in file.sites.into_iter().filter(Site::valid) {
        if !out.iter().any(|o| o.origin == s.origin) && out.len() < MAX_SITES { out.push(s); }
    }
    out
}

pub fn save_sites(path: &Path, sites: &[Site]) -> Result<(), String> {
    let dir = path.parent().ok_or("bad sites path")?;
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    let tmp = dir.join(format!(".browser-sites.{}.tmp", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp).map_err(|e| e.to_string())?;
    let body = serde_json::to_vec_pretty(&SitesFile { version: 1, sites: sites.to_vec() }).map_err(|e| e.to_string())?;
    f.write_all(&body).and_then(|_| f.sync_all()).map_err(|e| e.to_string())?;
    drop(f);
    std::fs::rename(&tmp, path).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------- policy

/// What to do with one request. Pure: decided from the method, params, the site's permission and
/// the paired address. `wc.rs` supplies the method allow-list and parameter rules.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Answer(Value),
    Error(wc::RpcError),
    /// Forward to the user's node for this network.
    Proxy { chain: u64 },
    /// Show "<site> wants to connect".
    Connect,
    /// Show a request card (sign, send, switch to a network the site doesn't have yet).
    Prompt { chain: u64 },
    /// Switch to a network the user already approved for this site; no card needed.
    SwitchNow { chain: u64 },
    /// The site disconnects itself (wallet_revokePermissions).
    Revoke,
}

/// The site's permission, if it is connected under the current pairing.
pub fn connected<'a>(site: Option<&'a Site>, paired: Option<&str>) -> Option<&'a Site> {
    match (site, paired) { (Some(s), Some(p)) if s.address.eq_ignore_ascii_case(p) => Some(s), _ => None }
}

pub fn decide(method: &str, params: &Value, site: Option<&Site>, paired: Option<&str>) -> Decision {
    let conn = connected(site, paired);
    let chain = conn.map(|s| s.active).unwrap_or(DEFAULT_CHAIN);
    let unauthorized = || Decision::Error(rpc(wc::UNAUTHORIZED, "Not connected: ask for the account first (eth_requestAccounts) and approve it in Phone Vault."));
    if !params.is_array() { return Decision::Error(rpc(wc::INVALID_PARAMS, "params must be an array")); }
    match method {
        "eth_chainId" => Decision::Answer(json!(verify::to_quantity(chain as u128))),
        "net_version" => Decision::Answer(json!(chain.to_string())),
        "eth_accounts" => Decision::Answer(match (conn, paired) { (Some(_), Some(p)) => json!([verify::checksum(p)]), _ => json!([]) }),
        "eth_requestAccounts" => match (conn, paired) {
            (_, None) => Decision::Error(rpc(wc::UNAUTHORIZED, "Phone Vault is not paired with a phone yet. Pair it in the Phone Vault Companion app first.")),
            (Some(_), Some(p)) => Decision::Answer(json!([verify::checksum(p)])),
            (None, Some(_)) => Decision::Connect,
        },
        "wallet_getPermissions" => Decision::Answer(if conn.is_some() { json!([{"parentCapability": "eth_accounts", "caveats": []}]) } else { json!([]) }),
        "wallet_revokePermissions" => if site.is_some() { Decision::Revoke } else { Decision::Answer(Value::Null) },
        m if READ_ONLY_METHODS.contains(&m) => if conn.is_some() { Decision::Proxy { chain } } else { unauthorized() },
        m if PROMPT_METHODS.contains(&m) => {
            let (Some(s), Some(p)) = (conn, paired) else { return unauthorized() };
            if m == "eth_sendTransaction" {
                return match wc::normalize_tx(params, p, chain) { Ok(_) => Decision::Prompt { chain }, Err(e) => Decision::Error(e) };
            }
            match wc::route(m, params, chain, &s.chains, p) {
                Ok(wc::Prepared::SwitchChain { chain_id, in_session, .. }) =>
                    if chain_id == s.active { Decision::Answer(Value::Null) } else if in_session { Decision::SwitchNow { chain: chain_id } } else { Decision::Prompt { chain } },
                Ok(_) => Decision::Prompt { chain },
                Err(e) => Decision::Error(e),
            }
        }
        // eth_sign, eth_signTransaction, wallet_addEthereumChain and everything unknown: wc.rs's refusals.
        m => match wc::route(m, params, chain, &[], "0x0000000000000000000000000000000000000000") {
            Err(e) => Decision::Error(e),
            Ok(_) => Decision::Error(rpc(wc::UNSUPPORTED_METHOD, format!("{m} is not supported by Phone Vault"))),
        },
    }
}

/// Token bucket. Returns false when the site is over its rate.
fn take_token(bucket: &mut (f64, Instant), now: Instant) -> bool {
    let elapsed = now.saturating_duration_since(bucket.1).as_secs_f64();
    bucket.0 = (bucket.0 + elapsed * BUCKET_REFILL_PER_SEC).min(BUCKET_CAPACITY);
    bucket.1 = now;
    if bucket.0 >= 1.0 { bucket.0 -= 1.0; true } else { false }
}

/// What the webview may send back for a request: only result shapes the verified pipeline
/// produces (a 32-byte transaction hash, a 65-byte signature, null for a network switch).
pub fn check_result(method: &str, result: &Value) -> Result<(), String> {
    let hex_of = |v: &Value, bytes: usize| v.as_str().is_some_and(|s| s.len() == 2 + 2 * bytes && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit()));
    let ok = match method {
        "eth_sendTransaction" => hex_of(result, 32),
        "personal_sign" | "eth_signTypedData_v4" => hex_of(result, 65),
        "wallet_switchEthereumChain" => result.is_null(),
        _ => false,
    };
    if ok { Ok(()) } else { Err(format!("refusing to send an unexpected result for {method}")) }
}

// ---------------------------------------------------------------- state

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind { Connect, Request }

#[derive(Clone, Debug)]
struct Pending { id: u64, conn: u64, ext_id: u64, origin: String, method: String, params: Value, chain: u64, kind: PendingKind, created: u64 }

/// A waiting request, as the webview sees it.
#[derive(Serialize, Clone, Debug)]
pub struct PendingOut { pub id: u64, pub kind: PendingKind, pub origin: String, pub host: String, pub local: bool, pub method: String, pub params: Value, pub chain_id: u64, pub created: u64 }

struct Conn { writer: Arc<Mutex<UnixStream>> }

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
}

type Paired = Box<dyn Fn() -> Option<String> + Send + Sync>;
type Notify = Box<dyn Fn() + Send + Sync>;

pub struct Bridge {
    inner: Mutex<Inner>,
    store: Option<PathBuf>,
    paired: Paired,
    notify: Notify,
    next_id: AtomicU64,
    next_conn: AtomicU64,
    proxies: Arc<AtomicUsize>,
}

#[derive(Serialize, Clone, Debug)]
pub struct SiteOut { pub origin: String, pub host: String, pub local: bool, pub chains: Vec<u64>, pub active: u64, pub connected_at: u64, pub address: String, pub current_pairing: bool }

impl Bridge {
    /// `store`: where permissions persist (None = memory only, for tests). `paired`: the pinned
    /// signer address (lowercase), read fresh for every decision. `notify`: the webview should refresh.
    pub fn new(store: Option<PathBuf>, paired: Paired, notify: Notify) -> Arc<Bridge> {
        let sites = store.as_deref().map(load_sites).unwrap_or_default();
        Arc::new(Bridge {
            inner: Mutex::new(Inner { sites, ..Default::default() }), store, paired, notify,
            next_id: AtomicU64::new(1), next_conn: AtomicU64::new(1), proxies: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn lock(&self) -> MutexGuard<'_, Inner> { self.inner.lock().unwrap_or_else(|p| p.into_inner()) }
    fn persist(&self, inner: &Inner) { if let Some(p) = &self.store { let _ = save_sites(p, &inner.sites); } }
    fn paired(&self) -> Option<String> { (self.paired)().map(|p| p.to_ascii_lowercase()) }

    fn send_to(writer: &Arc<Mutex<UnixStream>>, msg: &Value) {
        let mut body = serde_json::to_vec(msg).unwrap_or_default();
        if body.len() > MAX_OUT_FRAME {
            let id = msg.get("id").cloned().unwrap_or(Value::Null);
            body = serde_json::to_vec(&json!({"type": "response", "id": id, "error": {"code": LIMITED, "message": "The answer is too large to pass to the browser."}})).unwrap_or_default();
        }
        if let Ok(mut w) = writer.lock() { let _ = write_frame(&mut *w, &body, MAX_OUT_FRAME); }
    }

    fn reply(&self, conn: u64, ext_id: u64, outcome: Result<Value, Value>) {
        let writer = self.lock().conns.get(&conn).map(|c| c.writer.clone());
        let Some(w) = writer else { return };
        let msg = match outcome { Ok(result) => json!({"type": "response", "id": ext_id, "result": result}), Err(error) => json!({"type": "response", "id": ext_id, "error": error}) };
        Self::send_to(&w, &msg);
    }

    fn reply_err(&self, conn: u64, ext_id: u64, e: wc::RpcError) { self.reply(conn, ext_id, Err(json!({"code": e.code, "message": e.message}))); }

    /// Push an EIP-1193 event to every tab of `origin` (the extension routes by origin).
    fn emit(&self, origin: &str, name: &str, data: Value) {
        let writers: Vec<_> = self.lock().conns.values().map(|c| c.writer.clone()).collect();
        let msg = json!({"type": "event", "origin": origin, "name": name, "data": data});
        for w in writers { Self::send_to(&w, &msg); }
    }

    // ------------------------------------------------ requests from the extension

    /// One frame from a relay connection (already past the peer and caller checks).
    pub fn on_message(self: &Arc<Self>, conn: u64, msg: &Value) {
        match msg.get("type").and_then(Value::as_str) {
            Some("hello") => {
                let w = self.lock().conns.get(&conn).map(|c| c.writer.clone());
                if let Some(w) = w { Self::send_to(&w, &json!({"type": "hello", "ok": true, "version": 1, "app": "Phone Vault Companion", "paired": self.paired().is_some()})); }
            }
            Some("request") => self.on_request(conn, msg),
            Some("cancel") => {
                let Some(ext_id) = msg.get("id").and_then(Value::as_u64) else { return };
                let removed = { let mut g = self.lock(); let n = g.pending.len(); g.pending.retain(|p| !(p.conn == conn && p.ext_id == ext_id)); n != g.pending.len() };
                if removed { (self.notify)(); }
            }
            Some("site_status") => {
                // Popup: is this site connected? (origin from the active tab, set by the extension)
                let id = msg.get("id").and_then(Value::as_u64).unwrap_or(0);
                let Ok(origin) = msg.get("origin").and_then(Value::as_str).ok_or(String::new()).and_then(normalize_origin) else { return self.reply_err(conn, id, rpc(INVALID_REQUEST, "invalid origin")) };
                let paired = self.paired();
                let g = self.lock();
                let site = connected(g.sites.iter().find(|s| s.origin == origin), paired.as_deref()).cloned();
                drop(g);
                self.reply(conn, id, Ok(json!({"paired": paired.is_some(), "connected": site.is_some(), "chain": site.map(|s| s.active)})));
            }
            _ => {}
        }
    }

    fn on_request(self: &Arc<Self>, conn: u64, msg: &Value) {
        let Some(ext_id) = msg.get("id").and_then(Value::as_u64).filter(|i| *i < (1 << 53)) else { return };
        let origin = match msg.get("origin").and_then(Value::as_str).ok_or_else(|| "no origin".to_string()).and_then(normalize_origin) {
            Ok(o) => o,
            Err(e) => return self.reply_err(conn, ext_id, rpc(INVALID_REQUEST, format!("refused origin: {e}"))),
        };
        let method = msg.get("method").and_then(Value::as_str).unwrap_or("");
        if !valid_method(method) { return self.reply_err(conn, ext_id, rpc(INVALID_REQUEST, "invalid method name")); }
        let params = match msg.get("params") { None | Some(Value::Null) => json!([]), Some(p) => p.clone() };
        let paired = self.paired();

        let site = {
            let mut g = self.lock();
            let bucket = g.buckets.entry(origin.clone()).or_insert((BUCKET_CAPACITY, Instant::now()));
            if !take_token(bucket, Instant::now()) {
                drop(g);
                return self.reply_err(conn, ext_id, rpc(LIMITED, "Too many requests from this site. Slow down."));
            }
            if g.buckets.len() > 4 * MAX_SITES { let keep = origin.clone(); g.buckets.retain(|k, _| *k == keep); }
            g.sites.iter().find(|s| s.origin == origin).cloned()
        };

        match decide(method, &params, site.as_ref(), paired.as_deref()) {
            Decision::Answer(v) => self.reply(conn, ext_id, Ok(v)),
            Decision::Error(e) => self.reply_err(conn, ext_id, e),
            Decision::Revoke => { self.revoke(&origin); self.reply(conn, ext_id, Ok(Value::Null)); }
            Decision::SwitchNow { chain } => {
                let _ = self.update_site(&origin, None, Some(chain));
                self.reply(conn, ext_id, Ok(Value::Null));
            }
            d @ (Decision::Connect | Decision::Prompt { .. }) => {
                let (kind, chain) = match d { Decision::Prompt { chain } => (PendingKind::Request, chain), _ => (PendingKind::Connect, DEFAULT_CHAIN) };
                let mut g = self.lock();
                if kind == PendingKind::Connect && g.pending.iter().any(|p| p.origin == origin && p.kind == PendingKind::Connect) {
                    drop(g);
                    return self.reply_err(conn, ext_id, rpc(ALREADY_PENDING, "A connection request from this site is already waiting in Phone Vault."));
                }
                if g.pending.iter().filter(|p| p.origin == origin).count() >= MAX_PENDING_PER_ORIGIN || g.pending.len() >= MAX_PENDING_TOTAL {
                    drop(g);
                    return self.reply_err(conn, ext_id, rpc(LIMITED, "Too many requests are waiting in Phone Vault. Answer or reject them first."));
                }
                let id = self.next_id.fetch_add(1, Ordering::SeqCst);
                g.pending.push(Pending { id, conn, ext_id, origin: origin.clone(), method: method.to_string(), params, chain, kind, created: now_secs() });
                let writer = g.conns.get(&conn).map(|c| c.writer.clone());
                drop(g);
                // Tell the extension this one waits for the user (badge), and bring the app forward.
                if let Some(w) = writer { Self::send_to(&w, &json!({"type": "queued", "id": ext_id})); }
                (self.notify)();
                on_queued(&origin, kind == PendingKind::Connect, method);
            }
            Decision::Proxy { chain } => {
                let url = self.lock().nodes.get(&chain).cloned();
                let Some(url) = url else { return self.reply_err(conn, ext_id, rpc(wc::CHAIN_DISCONNECTED, format!("No node is set for {} in Phone Vault.", wc::chain_name(chain)))) };
                if self.proxies.fetch_add(1, Ordering::SeqCst) >= MAX_PROXY_INFLIGHT {
                    self.proxies.fetch_sub(1, Ordering::SeqCst);
                    return self.reply_err(conn, ext_id, rpc(LIMITED, "Too many node requests in flight. Try again."));
                }
                let me = self.clone();
                let method = method.to_string();
                std::thread::spawn(move || {
                    let known = me.lock().node_chain.get(&url).copied();
                    let out = proxy_call(&url, chain, known, &method, &params);
                    if let Ok((_, Some(c))) = &out { me.lock().node_chain.insert(url.clone(), *c); }
                    me.proxies.fetch_sub(1, Ordering::SeqCst);
                    me.reply(conn, ext_id, out.map(|(v, _)| v));
                });
            }
        }
    }

    // ------------------------------------------------ webview side

    pub fn pending(&self) -> Vec<PendingOut> {
        self.lock().pending.iter().map(|p| PendingOut {
            id: p.id, kind: p.kind, origin: p.origin.clone(), host: origin_host(&p.origin), local: origin_is_local(&p.origin),
            method: p.method.clone(), params: p.params.clone(), chain_id: p.chain, created: p.created,
        }).collect()
    }

    fn take_pending(&self, id: u64) -> Option<Pending> {
        let mut g = self.lock();
        let i = g.pending.iter().position(|p| p.id == id)?;
        Some(g.pending.remove(i))
    }

    /// Answer a request card. `error` = rejected or failed; `result` must have the shape the
    /// verified pipeline produces for that method (see `check_result`).
    pub fn respond(&self, id: u64, result: Option<Value>, error: Option<wc::RpcError>) -> Result<(), String> {
        let p = { let g = self.lock(); g.pending.iter().find(|p| p.id == id).cloned() }.ok_or("the site is no longer waiting for this request")?;
        match (result, error) {
            (_, Some(e)) => {
                let code = if (-32768..=4999).contains(&e.code) { e.code } else { wc::INTERNAL };
                let message: String = e.message.chars().take(500).collect();
                self.take_pending(id);
                self.reply_err(p.conn, p.ext_id, rpc(code, message));
            }
            (Some(r), None) => {
                if p.kind == PendingKind::Connect { return Err("a connection is approved with bridge_approve_connect".into()); }
                check_result(&p.method, &r)?;
                self.take_pending(id);
                self.reply(p.conn, p.ext_id, Ok(r));
            }
            (None, None) => {
                if p.method != "wallet_switchEthereumChain" { return Err("no result".into()); }
                self.take_pending(id);
                self.reply(p.conn, p.ext_id, Ok(Value::Null));
            }
        }
        (self.notify)();
        Ok(())
    }

    /// Refuse a waiting request (or connection) with a JSON-RPC error.
    pub fn reject(&self, id: u64, code: i64, message: &str) -> Result<(), String> { self.respond(id, None, Some(rpc(code, message))) }

    /// The user approved "<site> wants to connect" for these networks (first = active).
    pub fn approve_connect(&self, id: u64, chains: &[u64]) -> Result<(), String> {
        let paired = self.paired().ok_or("pair your phone first")?;
        let mut list: Vec<u64> = vec![];
        for &c in chains {
            if !wc::chain_allowed(c) { return Err(format!("your phone has no reviewed profile for chain {c}")); }
            if !list.contains(&c) { list.push(c); }
        }
        if list.is_empty() { return Err("choose at least one network".into()); }
        let p = {
            let g = self.lock();
            g.pending.iter().find(|p| p.id == id && p.kind == PendingKind::Connect).cloned().ok_or("the site is no longer waiting for this connection")?
        };
        {
            let mut g = self.lock();
            g.sites.retain(|s| s.origin != p.origin);
            if g.sites.len() >= MAX_SITES { g.sites.remove(0); }
            g.sites.push(Site { origin: p.origin.clone(), address: paired.clone(), active: list[0], chains: list.clone(), connected_at: now_secs() });
            g.pending.retain(|x| x.id != id);
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
                if list.is_empty() || list.iter().any(|c| !wc::chain_allowed(*c)) { return Err("networks must be ones your phone has a reviewed profile for".into()); }
                next.chains = vec![];
                for c in list { if !next.chains.contains(&c) { next.chains.push(c); } }
            }
            if let Some(a) = active {
                if !next.chains.contains(&a) { return Err(format!("{} is not approved for this site", wc::chain_name(a))); }
                next.active = a;
            }
            if !next.chains.contains(&next.active) { next.active = next.chains[0]; }
            let moved = (next.active != site.active).then_some(next.active);
            *site = next;
            self.persist(&g);
            moved
        };
        if let Some(c) = changed_to { self.emit(&origin, "chainChanged", json!(verify::to_quantity(c as u128))); }
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
            let (gone, keep): (Vec<_>, Vec<_>) = std::mem::take(&mut g.pending).into_iter().partition(|p| p.origin == origin);
            g.pending = keep;
            gone
        };
        for p in dropped { self.reply_err(p.conn, p.ext_id, rpc(wc::UNAUTHORIZED, "Disconnected in Phone Vault.")); }
        self.emit(&origin, "accountsChanged", json!([]));
        (self.notify)();
    }

    /// Node per network, from the app's settings (https only).
    pub fn set_nodes(&self, nodes: HashMap<u64, String>) -> Result<(), String> {
        let mut clean = HashMap::new();
        for (chain, url) in nodes {
            if !wc::chain_allowed(chain) { continue; }
            if !url.starts_with("https://") || url.len() > 512 { return Err(format!("the node for chain {chain} must be an https:// URL")); }
            clean.insert(chain, url);
        }
        self.lock().nodes = clean;
        Ok(())
    }

    pub fn sites(&self) -> Vec<SiteOut> {
        let paired = self.paired();
        self.lock().sites.iter().map(|s| SiteOut {
            origin: s.origin.clone(), host: origin_host(&s.origin), local: origin_is_local(&s.origin), chains: s.chains.clone(), active: s.active,
            connected_at: s.connected_at, address: verify::checksum(&s.address), current_pairing: paired.as_deref().is_some_and(|p| p.eq_ignore_ascii_case(&s.address)),
        }).collect()
    }

    pub fn connection_count(&self) -> usize { self.lock().conns.len() }
    pub fn listening(&self) -> (Option<PathBuf>, Option<String>) { let g = self.lock(); (g.listening.clone(), g.listen_error.clone()) }

    // ------------------------------------------------ socket server

    /// Listen on `path` (in a 0700 directory, socket 0600). Refuses to take over a socket another
    /// running companion still serves.
    pub fn serve(self: &Arc<Self>, path: &Path) -> Result<(), String> {
        let result = (|| {
            let dir = path.parent().ok_or("bad socket path")?;
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
            if let Ok(meta) = std::fs::symlink_metadata(path) {
                if !meta.file_type().is_socket() { return Err(format!("{} exists and is not a socket", path.display())); }
                if UnixStream::connect(path).is_ok() { return Err("another Phone Vault Companion is already serving the browser connection".into()); }
                std::fs::remove_file(path).map_err(|e| e.to_string())?;
            }
            let listener = UnixListener::bind(path).map_err(|e| format!("could not open {}: {e}", path.display()))?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|e| e.to_string())?;
            Ok(listener)
        })();
        let listener = match result {
            Ok(l) => { let mut g = self.lock(); g.listening = Some(path.to_path_buf()); g.listen_error = None; l }
            Err(e) => { let mut g = self.lock(); g.listening = None; g.listen_error = Some(e.clone()); return Err(e); }
        };
        let me = self.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let me = me.clone();
                std::thread::spawn(move || me.handle_conn(stream));
            }
        });
        Ok(())
    }

    fn handle_conn(self: Arc<Self>, stream: UnixStream) {
        if peer_check(&stream).is_err() { return; }
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let mut reader = match stream.try_clone() { Ok(r) => r, Err(_) => return };
        // First frame: the relay says which extension Chrome/Firefox started it for.
        let caller = match read_frame(&mut reader, 4096) {
            Ok(Some(b)) => serde_json::from_slice::<Value>(&b).ok().filter(|v| v["type"] == "relay_hello").and_then(|v| v["caller"].as_str().map(str::to_string)),
            _ => None,
        };
        if !caller.is_some_and(|c| allowed_caller(&c)) { return; }
        let _ = reader.set_read_timeout(None);
        let id = self.next_conn.fetch_add(1, Ordering::SeqCst);
        self.lock().conns.insert(id, Conn { writer: Arc::new(Mutex::new(stream)) });
        (self.notify)();
        loop {
            match read_frame(&mut reader, MAX_IN_FRAME) {
                Ok(Some(body)) => {
                    if let Ok(v) = serde_json::from_slice::<Value>(&body) { self.on_message(id, &v); }
                }
                _ => break,
            }
        }
        { let mut g = self.lock(); g.conns.remove(&id); g.pending.retain(|p| p.conn != id); }
        (self.notify)();
    }
}

/// Callers the relay may speak for: the pinned Chrome extension or the Firefox add-on.
pub fn allowed_caller(caller: &str) -> bool {
    caller == format!("chrome-extension://{CHROME_EXTENSION_ID}/") || caller == format!("firefox:{FIREFOX_EXTENSION_ID}")
}

/// The socket peer must be this user and this executable (the relay is this binary started by the
/// browser as the native host). Defence in depth: same-user code could still start the relay itself,
/// which is why nothing the bridge accepts can sign without the phone.
fn peer_check(stream: &UnixStream) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();
        let (mut uid, mut gid) = (0, 0);
        if unsafe { libc::getpeereid(fd, &mut uid, &mut gid) } != 0 || uid != unsafe { libc::getuid() } { return Err("socket peer is another user".into()); }
        let mut pid: libc::c_int = 0;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        if unsafe { libc::getsockopt(fd, libc::SOL_LOCAL, libc::LOCAL_PEERPID, &mut pid as *mut _ as *mut libc::c_void, &mut len) } != 0 { return Err("no peer pid".into()); }
        let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
        let n = unsafe { libc::proc_pidpath(pid, buf.as_mut_ptr() as *mut libc::c_void, buf.len() as u32) };
        if n <= 0 { return Err("no peer path".into()); }
        let peer = PathBuf::from(std::ffi::OsStr::from_bytes(&buf[..n as usize]));
        let me = std::env::current_exe().map_err(|e| e.to_string())?;
        if !same_file(&peer, &me) { return Err(format!("socket peer {} is not this app", peer.display())); }
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    { let _ = stream; Ok(()) }
}

pub fn same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) { (Ok(x), Ok(y)) => x == y, _ => false }
}

// ---------------------------------------------------------------- node proxy

/// Forward one read-only call to the user's node. The node must answer for the site's network
/// (checked once per URL). Returns (result, chain the node was verified for) or a JSON-RPC error
/// object (with the node's revert `data` when small, so dApps can decode it).
fn proxy_call(url: &str, chain: u64, known_chain: Option<u64>, method: &str, params: &Value) -> Result<(Value, Option<u64>), Value> {
    let fail = |m: String| json!({"code": wc::INTERNAL, "message": m});
    let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(20)).build().map_err(|e| fail(e.to_string()))?;
    let post = |method: &str, params: &Value| -> Result<Value, Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        let resp = client.post(url).json(&body).send().map_err(|e| fail(format!("node unreachable: {e}")))?;
        let mut bytes = vec![];
        resp.take(MAX_OUT_FRAME as u64 + 1).read_to_end(&mut bytes).map_err(|e| fail(e.to_string()))?;
        if bytes.len() > MAX_OUT_FRAME - 1024 { return Err(json!({"code": LIMITED, "message": "The node's answer is too large to pass to the browser."})); }
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| fail("node returned non-JSON".into()))?;
        sanitize_node_reply(&v)
    };
    let verified = match known_chain {
        Some(c) => c,
        None => {
            let c = post("eth_chainId", &json!([]))?;
            let id = c.as_str().and_then(|s| s.strip_prefix("0x")).and_then(|h| u64::from_str_radix(h, 16).ok()).ok_or_else(|| fail("node gave a bad chain id".into()))?;
            id
        }
    };
    if verified != chain { return Err(fail(format!("the node set for {} answers for chain {verified}; check it in Phone Vault Settings", wc::chain_name(chain)))); }
    Ok((post(method, params)?, Some(verified)))
}

/// Keep only `result`, or `error.{code,message,data}` with bounded sizes.
pub fn sanitize_node_reply(v: &Value) -> Result<Value, Value> {
    if let Some(e) = v.get("error") {
        let code = e.get("code").and_then(Value::as_i64).filter(|c| (-32768..=4999).contains(c)).unwrap_or(wc::INTERNAL);
        let message: String = e.get("message").and_then(Value::as_str).unwrap_or("node error").chars().take(500).collect();
        let mut out = json!({"code": code, "message": message});
        if let Some(d) = e.get("data").and_then(Value::as_str).filter(|d| d.len() <= 16 * 1024) { out["data"] = json!(d); }
        return Err(out);
    }
    v.get("result").cloned().ok_or_else(|| json!({"code": wc::INTERNAL, "message": "node returned no result"}))
}

// ---------------------------------------------------------------- native host (relay)

pub fn socket_path() -> Option<PathBuf> {
    #[cfg(debug_assertions)]
    if let Some(p) = std::env::var_os("PHONEVAULT_BRIDGE_SOCKET") { return Some(PathBuf::from(p)); }
    dirs::config_dir().map(|d| d.join("PhoneVault").join("bridge.sock"))
}

/// Chrome starts the host with the calling extension's origin as the first argument
/// ("chrome-extension://<id>/"); Firefox with the manifest path and then the add-on ID.
pub fn native_host_caller(args: &[String]) -> Option<String> {
    let a1 = args.get(1)?;
    if a1.starts_with("chrome-extension://") { return Some(a1.clone()); }
    if a1.ends_with(".json") { if let Some(id) = args.get(2) { if id == FIREFOX_EXTENSION_ID { return Some(format!("firefox:{id}")); } } }
    None
}

/// Run as the native messaging host: relay frames between the browser (stdin/stdout) and the
/// running companion. Never parses or acts on requests itself.
pub fn native_host_main(caller: String) -> i32 {
    let mut out = std::io::stdout();
    if !allowed_caller(&caller) {
        let _ = write_frame(&mut out, br#"{"type":"hello","ok":false,"error":"wrong_extension","message":"This browser connection is installed for a different extension ID."}"#, MAX_OUT_FRAME);
        return 1;
    }
    let stream = socket_path().and_then(|p| UnixStream::connect(p).ok());
    let Some(mut sock) = stream else {
        let _ = write_frame(&mut out, br#"{"type":"hello","ok":false,"error":"companion_not_running","message":"Phone Vault Companion is not running. Open it on this Mac."}"#, MAX_OUT_FRAME);
        return 0;
    };
    let hello = json!({"type": "relay_hello", "caller": caller}).to_string();
    if write_frame(&mut sock, hello.as_bytes(), 4096).is_err() { return 1; }
    let mut from_app = match sock.try_clone() { Ok(s) => s, Err(_) => return 1 };
    std::thread::spawn(move || {
        let mut out = std::io::stdout();
        loop {
            match read_frame(&mut from_app, MAX_OUT_FRAME) {
                Ok(Some(b)) => { if write_frame(&mut out, &b, MAX_OUT_FRAME).is_err() { std::process::exit(0); } }
                _ => std::process::exit(0),
            }
        }
    });
    let mut input = std::io::stdin();
    loop {
        match read_frame(&mut input, MAX_IN_FRAME) {
            Ok(Some(b)) => { if write_frame(&mut sock, &b, MAX_IN_FRAME).is_err() { return 0; } }
            Ok(None) => return 0,
            Err(_) => return 1,
        }
    }
}

// ---------------------------------------------------------------- host manifests

pub struct HostTarget { pub browser: &'static str, pub app_dir: &'static str, pub firefox: bool }
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
    if firefox { m["allowed_extensions"] = json!([FIREFOX_EXTENSION_ID]); }
    else { m["allowed_origins"] = json!([format!("chrome-extension://{CHROME_EXTENSION_ID}/")]); }
    m
}

fn app_support(home: &Path) -> PathBuf { home.join("Library").join("Application Support") }
pub fn manifest_path(home: &Path, t: &HostTarget) -> PathBuf { app_support(home).join(t.app_dir).join("NativeMessagingHosts").join(format!("{HOST_NAME}.json")) }

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct HostState { pub browser: String, pub path: String, pub browser_found: bool, pub state: &'static str }

/// "installed" (points at this app), "outdated" (points elsewhere, e.g. the app moved),
/// "missing", or "foreign" (a file of that name that isn't ours; left alone).
pub fn host_states(home: &Path, exe: &Path) -> Vec<HostState> {
    HOST_TARGETS.iter().map(|t| {
        let p = manifest_path(home, t);
        let state = match std::fs::read_to_string(&p).ok().and_then(|s| serde_json::from_str::<Value>(&s).ok()) {
            None if p.exists() => "foreign",
            None => "missing",
            Some(v) if v == host_manifest(exe, t.firefox) => "installed",
            Some(v) if v["name"] == HOST_NAME && (v["allowed_origins"] == host_manifest(exe, false)["allowed_origins"] || v["allowed_extensions"] == host_manifest(exe, true)["allowed_extensions"]) => "outdated",
            Some(_) => "foreign",
        };
        HostState { browser: t.browser.into(), path: p.display().to_string(), browser_found: app_support(home).join(t.app_dir).is_dir(), state }
    }).collect()
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
    if !exe.is_absolute() { return Err("the app path is not absolute".into()); }
    let mut wrote = 0;
    for t in HOST_TARGETS.iter() {
        if !app_support(home).join(t.app_dir).is_dir() { continue; }
        let p = manifest_path(home, t);
        if host_states(home, exe).iter().any(|s| s.path == p.display().to_string() && s.state == "foreign") { continue; }
        let dir = p.parent().ok_or("bad path")?;
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
        let tmp = dir.join(format!(".{HOST_NAME}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        let mut f = std::fs::OpenOptions::new().write(true).create_new(true).mode(0o644).open(&tmp).map_err(|e| e.to_string())?;
        f.write_all(serde_json::to_string_pretty(&host_manifest(exe, t.firefox)).unwrap_or_default().as_bytes()).map_err(|e| e.to_string())?;
        drop(f);
        std::fs::rename(&tmp, &p).map_err(|e| e.to_string())?;
        wrote += 1;
    }
    if wrote == 0 { return Err("No Chrome, Brave, Edge, Chromium or Firefox profile was found on this Mac.".into()); }
    Ok(host_states(home, exe))
}

/// Remove our host manifests (only files that are ours).
pub fn uninstall_hosts(home: &Path, exe: &Path) -> Vec<HostState> {
    for s in host_states(home, exe) { if s.state == "installed" || s.state == "outdated" { let _ = std::fs::remove_file(&s.path); } }
    host_states(home, exe)
}

// ---------------------------------------------------------------- app wiring + commands

static APP: std::sync::OnceLock<tauri::AppHandle> = std::sync::OnceLock::new();

/// The bridge the app manages: permissions in the config dir, the paired address from the
/// pairing file, a `bridge-changed` event to the webview on every change.
pub fn create() -> Arc<Bridge> {
    use tauri::Emitter;
    Bridge::new(
        sites_path(),
        Box::new(|| pairing::load().ok().flatten()),
        Box::new(|| { if let Some(app) = APP.get() { let _ = app.emit("bridge-changed", ()); } }),
    )
}

/// A site's request now waits for the user: show the window, and post a notification in case
/// the window can't come forward (another Space, full screen). Nothing from the site's request
/// beyond its origin and method name goes into the notification.
fn on_queued(origin: &str, connect: bool, method: &str) {
    let Some(app) = APP.get() else { return };
    use tauri_plugin_notification::NotificationExt;
    crate::tray::show_main(app);
    let host = origin.strip_prefix("https://").unwrap_or(origin);
    let what = if connect { "wants to connect".to_string() } else {
        match method {
            "eth_sendTransaction" => "wants you to send a transaction".into(),
            "wallet_switchEthereumChain" | "wallet_addEthereumChain" => "wants to switch network".into(),
            m if m.contains("sign") || m.contains("Sign") => "wants a signature".into(),
            _ => "is waiting for you".into(),
        }
    };
    let _ = app.notification().builder().title("Phone Vault").body(format!("{host} {what}. Review it in Phone Vault Companion.")).show();
}

/// Called from setup: remember the handle for events and start listening.
pub fn start(app: &tauri::AppHandle, bridge: &Arc<Bridge>) {
    let _ = APP.set(app.clone());
    match socket_path() {
        Some(p) => { let _ = bridge.serve(&p); }
        None => { bridge.lock().listen_error = Some("no config directory".into()); }
    }
}

#[derive(Serialize)]
pub struct BridgeStatus {
    pub listening: bool, pub error: Option<String>, pub socket: String, pub extension_id: String, pub firefox_id: String,
    pub connections: usize, pub hosts: Vec<HostState>, pub sites: Vec<SiteOut>, pub exe: String, pub exe_error: Option<String>,
}

fn status_of(b: &Bridge) -> BridgeStatus {
    let (listening, error) = b.listening();
    let exe = host_exe();
    let home = dirs::home_dir();
    let hosts = match (&home, &exe) { (Some(h), Ok(e)) => host_states(h, e), _ => vec![] };
    BridgeStatus {
        listening: listening.is_some(), error, socket: listening.map(|p| p.display().to_string()).unwrap_or_default(),
        extension_id: CHROME_EXTENSION_ID.into(), firefox_id: FIREFOX_EXTENSION_ID.into(), connections: b.connection_count(), hosts, sites: b.sites(),
        exe: exe.as_ref().map(|p| p.display().to_string()).unwrap_or_default(), exe_error: exe.err(),
    }
}

type St<'a> = tauri::State<'a, Arc<Bridge>>;

#[tauri::command]
pub fn bridge_status(b: St<'_>) -> BridgeStatus { status_of(&b) }

#[tauri::command]
pub fn bridge_pending(b: St<'_>) -> Vec<PendingOut> { b.pending() }

#[derive(Deserialize)]
pub struct RpcErrorIn { code: i64, message: String }

#[tauri::command]
pub fn bridge_respond(b: St<'_>, id: u64, result: Option<Value>, error: Option<RpcErrorIn>) -> Result<(), String> {
    b.respond(id, result, error.map(|e| rpc(e.code, e.message)))
}

#[tauri::command]
pub fn bridge_approve_connect(b: St<'_>, id: u64, chains: Vec<u64>) -> Result<(), String> { b.approve_connect(id, &chains) }

#[tauri::command]
pub fn bridge_update_site(b: St<'_>, origin: String, chains: Option<Vec<u64>>, active: Option<u64>) -> Result<(), String> { b.update_site(&origin, chains, active) }

#[tauri::command]
pub fn bridge_revoke(b: St<'_>, origin: String) { b.revoke(&origin) }

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

#[cfg(test)]
mod tests {
    use super::*;
    const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
    const OTHER: &str = "0x1111111111111111111111111111111111111111";

    fn site(chains: &[u64], active: u64) -> Site { Site { origin: "https://app.example.org".into(), address: ME.into(), chains: chains.to_vec(), active, connected_at: 1 } }
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("pvb-{}-{}-{name}", std::process::id(), now_secs()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn origins() {
        assert_eq!(normalize_origin("https://app.uniswap.org").unwrap(), "https://app.uniswap.org");
        assert_eq!(normalize_origin("HTTPS://App.Uniswap.ORG").unwrap(), "https://app.uniswap.org");
        assert_eq!(normalize_origin("https://example.org:8443").unwrap(), "https://example.org:8443");
        assert_eq!(normalize_origin("http://localhost:5173").unwrap(), "http://localhost:5173");
        assert_eq!(normalize_origin("http://127.0.0.1:8080").unwrap(), "http://127.0.0.1:8080");
        assert_eq!(normalize_origin("http://[::1]:3000").unwrap(), "http://[::1]:3000");
        assert_eq!(normalize_origin("https://xn--uniswp-9za.org").unwrap(), "https://xn--uniswp-9za.org", "punycode passes (shown as such)");
        for bad in ["", "null", "app.uniswap.org", "http://app.uniswap.org", "file:///etc/passwd", "chrome-extension://abc", "javascript:alert(1)",
            "https://app.uniswap.org/", "https://app.uniswap.org/path", "https://user@app.uniswap.org", "https://app.uniswap.org?x", "https://app.uniswap.org#x",
            "https://ápp.org", "https://app uniswap.org", "https://-bad.org", "https://a..b", "https://x.org:0", "https://x.org:65536", "https://x.org:08",
            "https://x.org:", "https://[2001:db8::1]", "http://localhost.evil.org", "https://x.org%2f"] {
            assert!(normalize_origin(bad).is_err(), "{bad:?} must be refused");
        }
        assert_eq!(origin_host("https://app.uniswap.org"), "app.uniswap.org");
        assert!(origin_is_local("http://localhost:1"));
        assert!(!origin_is_local("https://localhost"));
    }

    #[test]
    fn frames_round_trip_and_cap() {
        let mut buf = vec![];
        write_frame(&mut buf, br#"{"a":1}"#, 100).unwrap();
        assert_eq!(&buf[..4], &7u32.to_ne_bytes());
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 100).unwrap().unwrap(), br#"{"a":1}"#);
        assert!(read_frame(&mut r, 100).unwrap().is_none(), "clean EOF");
        assert!(write_frame(&mut vec![], &[0u8; 101], 100).is_err());
        let mut big = (1_000_000u32).to_ne_bytes().to_vec();
        big.extend_from_slice(b"xx");
        assert!(read_frame(&mut &big[..], 1000).is_err(), "oversize length refused before reading");
        let mut short = 10u32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut &short[..], 100).is_err(), "truncated body");
    }

    #[test]
    fn unconnected_sites_learn_nothing_and_can_only_ask_to_connect() {
        let p = Some(ME);
        assert_eq!(decide("eth_chainId", &json!([]), None, p), Decision::Answer(json!("0x2105")));
        assert_eq!(decide("net_version", &json!([]), None, p), Decision::Answer(json!("8453")));
        assert_eq!(decide("eth_accounts", &json!([]), None, p), Decision::Answer(json!([])));
        assert_eq!(decide("wallet_getPermissions", &json!([]), None, p), Decision::Answer(json!([])));
        assert_eq!(decide("eth_requestAccounts", &json!([]), None, p), Decision::Connect);
        for m in ["eth_sendTransaction", "personal_sign", "eth_signTypedData_v4", "wallet_switchEthereumChain", "eth_call", "eth_getBalance", "eth_blockNumber"] {
            assert!(matches!(decide(m, &json!([]), None, p), Decision::Error(e) if e.code == wc::UNAUTHORIZED), "{m}");
        }
        // not paired at all
        assert!(matches!(decide("eth_requestAccounts", &json!([]), None, None), Decision::Error(e) if e.code == wc::UNAUTHORIZED));
        // a site connected under another pairing is not connected
        let s = site(&[8453], 8453);
        assert_eq!(decide("eth_accounts", &json!([]), Some(&s), Some(OTHER)), Decision::Answer(json!([])));
        assert_eq!(decide("eth_requestAccounts", &json!([]), Some(&s), Some(OTHER)), Decision::Connect);
        assert!(matches!(decide("personal_sign", &json!(["hi", OTHER]), Some(&s), Some(OTHER)), Decision::Error(e) if e.code == wc::UNAUTHORIZED));
    }

    #[test]
    fn connected_sites_follow_the_walletconnect_rules() {
        let s = site(&[8453, 1], 1);
        let p = Some(ME);
        let d = |m: &str, params: Value| decide(m, &params, Some(&s), p);
        assert_eq!(d("eth_chainId", json!([])), Decision::Answer(json!("0x1")));
        assert_eq!(d("eth_accounts", json!([])), Decision::Answer(json!([verify::checksum(ME)])));
        assert_eq!(d("eth_requestAccounts", json!([])), Decision::Answer(json!([verify::checksum(ME)])));
        assert_eq!(d("eth_getBalance", json!([ME, "latest"])), Decision::Proxy { chain: 1 });
        assert_eq!(d("eth_call", json!([{"to": OTHER, "data": "0x"}, "latest"])), Decision::Proxy { chain: 1 });
        assert_eq!(d("personal_sign", json!(["0x48656c6c6f", ME])), Decision::Prompt { chain: 1 });
        assert_eq!(d("eth_sendTransaction", json!([{"from": ME, "to": OTHER, "value": "0x1"}])), Decision::Prompt { chain: 1 });
        // parameter checks happen before anything is queued
        assert!(matches!(d("eth_sendTransaction", json!([{"from": OTHER, "to": OTHER}])), Decision::Error(e) if e.code == wc::UNAUTHORIZED));
        assert!(matches!(d("eth_sendTransaction", json!([{"to": OTHER, "chainId": "0x2105"}])), Decision::Error(e) if e.code == wc::INVALID_PARAMS));
        assert!(matches!(d("personal_sign", json!(["hi", OTHER])), Decision::Error(e) if e.code == wc::UNAUTHORIZED));
        assert!(matches!(d("eth_signTypedData_v4", json!([ME, "{\"types\":{}}"])), Decision::Error(_)));
        // refused outright, as for WalletConnect
        for m in ["eth_sign", "eth_signTransaction", "wallet_addEthereumChain", "eth_getEncryptionPublicKey", "wallet_sendCalls", "wallet_requestPermissions", "eth_subscribe", "debug_traceTransaction"] {
            assert!(matches!(d(m, json!([])), Decision::Error(e) if e.code == wc::UNSUPPORTED_METHOD), "{m}");
        }
        // network switching: same → no-op, approved → immediate, new allowed → card, unknown → 4902
        assert_eq!(d("wallet_switchEthereumChain", json!([{"chainId": "0x1"}])), Decision::Answer(Value::Null));
        assert_eq!(d("wallet_switchEthereumChain", json!([{"chainId": "0x2105"}])), Decision::SwitchNow { chain: 8453 });
        assert_eq!(d("wallet_switchEthereumChain", json!([{"chainId": "0xa"}])), Decision::Prompt { chain: 1 });
        assert!(matches!(d("wallet_switchEthereumChain", json!([{"chainId": "0x38"}])), Decision::Error(e) if e.code == wc::UNRECOGNIZED_CHAIN));
        assert_eq!(d("wallet_revokePermissions", json!([{"eth_accounts": {}}])), Decision::Revoke);
        // params must be an array
        assert!(matches!(d("eth_chainId", json!({})), Decision::Error(e) if e.code == wc::INVALID_PARAMS));
    }

    #[test]
    fn rate_limit_bucket() {
        let t0 = Instant::now();
        let mut b = (BUCKET_CAPACITY, t0);
        let allowed = (0..100).filter(|_| take_token(&mut b, t0)).count();
        assert_eq!(allowed, BUCKET_CAPACITY as usize);
        assert!(!take_token(&mut b, t0));
        assert!(take_token(&mut b, t0 + Duration::from_millis(100)), "refills at 20/s");
    }

    #[test]
    fn results_the_webview_may_return() {
        assert!(check_result("eth_sendTransaction", &json!(format!("0x{}", "ab".repeat(32)))).is_ok());
        assert!(check_result("eth_sendTransaction", &json!(format!("0x{}", "ab".repeat(65)))).is_err());
        assert!(check_result("personal_sign", &json!(format!("0x{}", "0f".repeat(65)))).is_ok());
        assert!(check_result("personal_sign", &json!("0xdeadbeef")).is_err());
        assert!(check_result("eth_signTypedData_v4", &json!(null)).is_err());
        assert!(check_result("wallet_switchEthereumChain", &json!(null)).is_ok());
        assert!(check_result("eth_accounts", &json!([ME])).is_err(), "accounts never come from the webview");
    }

    #[test]
    fn node_replies_are_trimmed() {
        assert_eq!(sanitize_node_reply(&json!({"jsonrpc": "2.0", "id": 1, "result": "0x10", "extra": 1})).unwrap(), json!("0x10"));
        let e = sanitize_node_reply(&json!({"error": {"code": 3, "message": "execution reverted", "data": "0x08c379a0"}})).unwrap_err();
        assert_eq!(e, json!({"code": 3, "message": "execution reverted", "data": "0x08c379a0"}));
        let e = sanitize_node_reply(&json!({"error": {"code": 99999, "message": "x".repeat(2000), "data": {"obj": 1}}})).unwrap_err();
        assert_eq!(e["code"], wc::INTERNAL);
        assert_eq!(e["message"].as_str().unwrap().len(), 500);
        assert!(e.get("data").is_none());
        assert!(sanitize_node_reply(&json!({})).is_err());
    }

    #[test]
    fn sites_persist_0600_and_bad_entries_are_dropped() {
        let d = tmp("sites");
        let p = d.join("browser-sites.json");
        let good = site(&[8453], 8453);
        save_sites(&p, &[good.clone()]).unwrap();
        assert_eq!(std::fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        assert_eq!(load_sites(&p), vec![good.clone()]);
        let mut bad = good.clone(); bad.origin = "http://evil.org".into();
        let mut bad2 = good.clone(); bad2.origin = "https://b.org".into(); bad2.chains = vec![56]; bad2.active = 56;
        let mut bad3 = good.clone(); bad3.origin = "https://c.org".into(); bad3.active = 1;
        save_sites(&p, &[good.clone(), bad, bad2, bad3]).unwrap();
        assert_eq!(load_sites(&p), vec![good.clone()]);
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_sites(&p).is_empty(), "a group/world-readable file is ignored");
        let _ = std::fs::remove_dir_all(d);
    }

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
        std::fs::write(brave.join("dev.phonevault.json"), r#"{"name":"dev.phonevault","path":"/tmp/evil","allowed_origins":["chrome-extension://zzzz/"]}"#).unwrap();
        install_hosts(&home, &exe).unwrap();
        assert!(std::fs::read_to_string(brave.join("dev.phonevault.json")).unwrap().contains("/tmp/evil"));
        let after = uninstall_hosts(&home, &exe);
        assert!(!chrome.exists());
        assert_eq!(after.iter().find(|s| s.browser == "Brave").unwrap().state, "foreign");
        assert!(brave.join("dev.phonevault.json").exists(), "foreign file not removed");
        let _ = std::fs::remove_dir_all(home);
    }

    #[test]
    fn native_host_callers() {
        let a = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let chrome = format!("chrome-extension://{CHROME_EXTENSION_ID}/");
        assert_eq!(native_host_caller(&a(&["companion", &chrome])), Some(chrome.clone()));
        assert!(allowed_caller(&chrome));
        assert!(!allowed_caller("chrome-extension://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/"));
        assert_eq!(native_host_caller(&a(&["companion", "/x/dev.phonevault.json", FIREFOX_EXTENSION_ID])), Some(format!("firefox:{FIREFOX_EXTENSION_ID}")));
        assert_eq!(native_host_caller(&a(&["companion", "/x/dev.phonevault.json", "evil@x"])), None);
        assert_eq!(native_host_caller(&a(&["companion"])), None);
        assert_eq!(native_host_caller(&a(&["companion", "--some-flag"])), None);
    }

    // ------------------------------------------------ the socket end to end (same process = same exe)

    struct Client { s: UnixStream }
    impl Client {
        fn connect(path: &Path, caller: &str) -> Client {
            let mut s = UnixStream::connect(path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            write_frame(&mut s, json!({"type": "relay_hello", "caller": caller}).to_string().as_bytes(), 4096).unwrap();
            Client { s }
        }
        fn send(&mut self, v: Value) { write_frame(&mut self.s, v.to_string().as_bytes(), MAX_IN_FRAME).unwrap(); }
        fn raw(&mut self) -> Value { serde_json::from_slice(&read_frame(&mut self.s, MAX_OUT_FRAME).unwrap().unwrap()).unwrap() }
        /// Next frame, skipping "queued" notices (checked on their own below).
        fn recv(&mut self) -> Value { loop { let v = self.raw(); if v["type"] != "queued" { return v; } } }
        /// Next response (skipping events).
        fn response(&mut self) -> Value { loop { let v = self.recv(); if v["type"] == "response" { return v; } } }
        fn req(&mut self, id: u64, origin: &str, method: &str, params: Value) -> Value {
            self.send(json!({"type": "request", "id": id, "origin": origin, "method": method, "params": params}));
            self.response()
        }
    }

    fn wait_for(mut f: impl FnMut() -> bool) { for _ in 0..200 { if f() { return; } std::thread::sleep(Duration::from_millis(10)); } panic!("timed out"); }

    #[test]
    fn socket_flow_connect_sign_reject_revoke() {
        let d = std::env::temp_dir().join(format!("pvb{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let sock = d.join("b.sock");
        let bridge = Bridge::new(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}));
        bridge.serve(&sock).unwrap();
        assert_eq!(std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777, 0o600);
        assert!(Bridge::new(None, Box::new(|| None), Box::new(|| {})).serve(&sock).is_err(), "a second instance must not steal the socket");

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
        for _ in 0..3 { got.push(c.recv()); }
        let resp = got.iter().find(|v| v["type"] == "response").unwrap();
        assert_eq!((resp["id"].as_u64(), resp["result"].clone()), (Some(5), json!([verify::checksum(ME)])));
        assert!(got.iter().any(|v| v["type"] == "event" && v["name"] == "chainChanged" && v["data"] == "0xa" && v["origin"] == o));
        assert!(got.iter().any(|v| v["type"] == "event" && v["name"] == "accountsChanged"));
        assert_eq!(c.req(7, o, "eth_chainId", json!([]))["result"], "0xa");

        // proxy without a configured node: refused, not hung
        assert_eq!(c.req(8, o, "eth_blockNumber", json!([]))["error"]["code"], wc::CHAIN_DISCONNECTED);

        // a sign request is queued, the webview rejects it, the site gets 4001
        c.send(json!({"type": "request", "id": 9, "origin": o, "method": "personal_sign", "params": ["0x48656c6c6f", ME]}));
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
        loop { let v = c.recv(); if v["type"] == "event" { saw_event |= v["data"] == "0x2105"; } else { assert_eq!(v["id"], 10); assert!(v["result"].is_null()); break; } }
        let _ = saw_event; // the event may follow the response; checked through state:
        assert_eq!(c.req(11, o, "eth_chainId", json!([]))["result"], "0x2105");

        // pending caps per site
        for i in 0..MAX_PENDING_PER_ORIGIN as u64 { c.send(json!({"type": "request", "id": 100 + i, "origin": o, "method": "personal_sign", "params": ["0x01", ME]})); }
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_ORIGIN);
        assert_eq!(c.req(200, o, "personal_sign", json!(["0x01", ME]))["error"]["code"], LIMITED);
        // cancel (tab closed) removes one
        c.send(json!({"type": "cancel", "id": 100}));
        wait_for(|| bridge.pending().len() == MAX_PENDING_PER_ORIGIN - 1);

        // revoke: waiting requests are refused, the site is told, and it is not connected any more
        bridge.revoke(o);
        let mut refused = 0;
        loop { let v = c.recv(); if v["type"] == "response" { assert_eq!(v["error"]["code"], wc::UNAUTHORIZED); refused += 1; } else if v["name"] == "accountsChanged" { assert_eq!(v["data"], json!([])); break; } }
        assert_eq!(refused, MAX_PENDING_PER_ORIGIN - 1);
        assert_eq!(c.req(12, o, "eth_accounts", json!([]))["result"], json!([]));

        // closing the connection drops what it left waiting
        c.send(json!({"type": "request", "id": 13, "origin": o, "method": "eth_requestAccounts", "params": []}));
        wait_for(|| bridge.pending().len() == 1);
        drop(c);
        wait_for(|| bridge.pending().is_empty() && bridge.connection_count() == 0);
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
        let sender = std::thread::spawn(move || for i in 0..200u64 {
            write_frame(&mut w, json!({"type": "request", "id": i, "origin": o, "method": "eth_chainId", "params": []}).to_string().as_bytes(), MAX_IN_FRAME).unwrap();
        });
        let limited = (0..200).filter(|_| c.response().get("error").is_some()).count();
        sender.join().unwrap();
        assert!(limited >= 100, "most of a 200-request burst is refused ({limited})");
        // another site is unaffected
        assert_eq!(c.req(999, "https://other.example", "eth_chainId", json!([]))["result"], "0x2105");
        let _ = std::fs::remove_dir_all(d);
    }
}
