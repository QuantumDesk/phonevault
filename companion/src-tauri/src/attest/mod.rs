//! Device attestation: is the phone on USB genuine Phone Vault firmware running the genuine
//! Phone Vault app, with its keys in the Titan M? (vault-os/docs/device-attestation.md)
//!
//! Protocol (one USB exchange, same framing as every other request):
//!
//! ```text
//! → {"id":"…","method":"attest","challenge":"<32 random bytes, lowercase hex>"}
//! ← {"id":"…","status":"ok","version":"1","address":"0x<40 hex>",
//!    "securityLevel":"StrongBox"|"TrustedEnvironment",
//!    "certificates":"<base64 DER leaf>,<base64 DER>,…,<base64 DER root>",
//!    "signature":"0x<DER ECDSA>"}
//! ```
//!
//! The phone generates a fresh EC P-256 key in StrongBox (TEE only if StrongBox fails) with
//! `setAttestationChallenge(challenge)`, signs the binding message below with it, returns the
//! key's attestation chain, and deletes the key. The wallet key is never used: the address is
//! bound by the attested key's signature, and that signature is trusted because the chain proves
//! the key lives in secure hardware, belongs to `dev.phonevault.signer` signed by our key, and was
//! created on a locked phone booting our firmware. (The doc explains why not an EIP-191 wallet
//! signature: it would be a wallet-key signature without a tap on the phone.)
//!
//! ```text
//! binding = "PhoneVault-attest-v1" ‖ 0x00 ‖ len(challenge) (1 byte) ‖ challenge ‖ address (20 bytes)
//! signature = ECDSA-P256-SHA256(attested key, binding), DER
//! ```

pub mod chain;
pub mod der;
pub mod devmode;
pub mod keydesc;
pub mod policy;
pub mod revocation;
#[cfg(test)]
mod tests;

use crate::{aoa, blocking, verify, CmdResult};
use base64::Engine;
use keydesc::SecurityLevel;
use policy::{Assessment, Policy, Verdict};
use ring::rand::SecureRandom;
use serde::Serialize;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DOMAIN: &[u8] = b"PhoneVault-attest-v1";
pub const CHALLENGE_BYTES: usize = 32;
pub const MIN_CHALLENGE: usize = 16;
pub const MAX_CHALLENGE: usize = 64;
/// How long a verdict stands for one USB connection before it is asked again.
const CACHE_TTL: Duration = Duration::from_secs(15 * 60);
/// StrongBox key generation takes a few seconds; a locked phone holds the request until unlock.
const PHONE_TIMEOUT: Duration = Duration::from_secs(45);
const MAX_SIGNATURE_BYTES: usize = 80;

/// The message the attested key signs. Fixed layout, length-prefixed challenge, raw address.
pub fn binding_message(challenge: &[u8], address: &[u8; 20]) -> Vec<u8> {
    assert!(challenge.len() <= u8::MAX as usize);
    let mut m = Vec::with_capacity(DOMAIN.len() + 2 + challenge.len() + 20);
    m.extend_from_slice(DOMAIN);
    m.push(0);
    m.push(challenge.len() as u8);
    m.extend_from_slice(challenge);
    m.extend_from_slice(address);
    m
}

pub fn request(id: &str, challenge: &[u8]) -> Value {
    json!({"id": id, "method": "attest", "challenge": hex::encode(challenge)})
}

#[derive(Debug, Clone)]
pub struct PhoneAttestation {
    /// lowercase 0x + 40 hex
    pub address: String,
    pub address_bytes: [u8; 20],
    pub security_level: SecurityLevel,
    pub certificates: Vec<Vec<u8>>,
    pub signature: Vec<u8>,
}

#[derive(Debug)]
pub enum Answer { Attestation(PhoneAttestation), Refused(String) }

/// Schema-exact parse of the phone's answer. `Err` means a malformed answer (a FAIL).
pub fn parse_response(request: &Value, response: &Value) -> Result<Answer, String> {
    let obj = response.as_object().ok_or("the phone's answer is not an object")?;
    if obj.get("id") != request.get("id") { return Err("the phone's answer is for a different request".into()); }
    let s = |k: &str| obj.get(k).and_then(Value::as_str);
    if s("status") == Some("error") {
        let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
        if keys != ["error", "id", "status"] { return Err("malformed error answer".into()); }
        return Ok(Answer::Refused(s("error").unwrap_or("error").chars().take(300).collect()));
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
    if keys != ["address", "certificates", "id", "securityLevel", "signature", "status", "version"] {
        return Err("the phone's attestation answer does not match the protocol".into());
    }
    if s("status") != Some("ok") { return Err("unexpected status".into()); }
    if s("version") != Some("1") { return Err("unsupported attestation version".into()); }
    let address = s("address").ok_or("address is not a string")?;
    if address.len() != 42 || !address.starts_with("0x") || !address[2..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
        return Err("the phone's address is not 0x + 40 lowercase hex".into());
    }
    let mut address_bytes = [0u8; 20];
    address_bytes.copy_from_slice(&hex::decode(&address[2..]).map_err(|e| e.to_string())?);
    let security_level = SecurityLevel::parse_name(s("securityLevel").ok_or("securityLevel is not a string")?)
        .filter(|l| *l != SecurityLevel::Software)
        .ok_or("unknown securityLevel")?;
    let list = s("certificates").ok_or("certificates is not a string")?;
    let parts: Vec<&str> = list.split(',').collect();
    if parts.len() < 2 || parts.len() > chain::MAX_CHAIN { return Err("the certificate list has the wrong length".into()); }
    let certificates = parts.iter().map(|p| base64::engine::general_purpose::STANDARD.decode(p).map_err(|_| "a certificate is not valid base64".to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    let sig_hex = s("signature").ok_or("signature is not a string")?.strip_prefix("0x").ok_or("signature must start with 0x")?;
    if sig_hex.bytes().any(|b| b.is_ascii_uppercase()) { return Err("signature must be lowercase hex".into()); }
    let signature = hex::decode(sig_hex).map_err(|_| "signature is not hex".to_string())?;
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES { return Err("signature has the wrong length".into()); }
    Ok(Answer::Attestation(PhoneAttestation { address: address.to_string(), address_bytes, security_level, certificates, signature }))
}

/// ECDSA P-256 / SHA-256 over the binding message, by the attested key.
pub fn verify_binding(point: &[u8], challenge: &[u8], address: &[u8; 20], signature: &[u8]) -> bool {
    ring::signature::UnparsedPublicKey::new(&ring::signature::ECDSA_P256_SHA256_ASN1, point)
        .verify(&binding_message(challenge, address), signature).is_ok()
}

/// What the UI shows and the gates check.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    #[serde(flatten)]
    pub assessment: Assessment,
    /// EIP-55 address the phone attested to, when it gave one.
    pub address: Option<String>,
    pub checked_at: u64,
    pub dev_mode: bool,
}

impl Report {
    pub fn verdict(&self) -> Verdict { self.assessment.verdict }
    fn summary(&self) -> String {
        match self.assessment.problems.first() { Some(p) => format!("{} — {p}", self.assessment.headline), None => self.assessment.headline.clone() }
    }
}

fn unix_now() -> u64 { std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0) }

/// Phone answers that mean "try again", not "not genuine".
fn transient(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("not ready") || m.contains("in progress")
}

/// Verify one exchange. `Err` only for a transient refusal (locked/not ready/busy); every other
/// problem is a FAIL report. `revocation` is called only once the chain itself verified.
#[allow(clippy::too_many_arguments)]
pub fn assess(
    policy: &Policy, roots: &[chain::TrustedRoot], now: i64, challenge: &[u8],
    request: &Value, response: &Value, revocation: impl FnOnce() -> revocation::Status, allow_dev: bool,
) -> Result<Report, String> {
    let report = |assessment: Assessment, address: Option<&str>| Report {
        assessment, address: address.map(verify::checksum), checked_at: now.max(0) as u64, dev_mode: allow_dev,
    };
    let phone = match parse_response(request, response) {
        Err(e) => return Ok(report(policy::fail(format!("The phone's answer is malformed: {e}.")), None)),
        Ok(Answer::Refused(msg)) if transient(&msg) => return Err(format!("phone: {msg}")),
        Ok(Answer::Refused(msg)) => return Ok(report(policy::fail(format!(
            "The phone did not attest ({msg}). A Phone Vault app without device attestation cannot prove it is genuine; update the app.")), None)),
        Ok(Answer::Attestation(a)) => a,
    };
    let chain = match chain::verify(&phone.certificates, roots, now) {
        Err(e) => return Ok(report(policy::fail(format!("The attestation certificate chain is not valid: {e}.")), Some(&phone.address))),
        Ok(c) => c,
    };
    let binding_ok = chain.leaf_p256_point.as_deref().map(|p| verify_binding(p, challenge, &phone.address_bytes, &phone.signature)).unwrap_or(false);
    let status = revocation();
    let ev = policy::Evidence { chain: &chain, phone_level: phone.security_level, challenge, binding_ok, revocation: &status };
    Ok(report(policy::evaluate(policy, &ev, allow_dev), Some(&phone.address)))
}

// ------------------------------------------------------------------ session cache + gates

struct Cached { report: Report, at: Instant, epoch: u64 }
struct State { cached: Option<Cached>, epoch: u64 }
static STATE: Mutex<State> = Mutex::new(State { cached: None, epoch: 0 });
static RUNNING: AtomicBool = AtomicBool::new(false);

struct RunGuard;
impl Drop for RunGuard { fn drop(&mut self) { RUNNING.store(false, Ordering::SeqCst); } }

/// Called with every USB presence poll: a phone that left the bus takes its verdict with it.
pub fn note_presence(p: aoa::Presence) {
    if p == aoa::Presence::None {
        if let Ok(mut s) = STATE.lock() { if s.cached.is_some() { s.cached = None; s.epoch += 1; } }
    }
}

fn cached() -> Option<Report> {
    let s = STATE.lock().ok()?;
    let c = s.cached.as_ref()?;
    (c.epoch == s.epoch && c.at.elapsed() < CACHE_TTL).then(|| c.report.clone())
}

/// Ask the phone on USB for a fresh attestation and verify it.
pub fn run() -> Result<Report, String> {
    let allow_dev = devmode::enabled();
    // Queue behind any other request on the phone (re-entrant when a send already holds the turn).
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    if RUNNING.swap(true, Ordering::SeqCst) { return Err("a device check is already running".into()); }
    let _guard = RunGuard;
    let epoch = STATE.lock().map_err(|_| "state poisoned")?.epoch;
    let mut challenge = [0u8; CHALLENGE_BYTES];
    ring::rand::SystemRandom::new().fill(&mut challenge).map_err(|_| "no randomness for the challenge")?;
    let req = request(&uuid::Uuid::new_v4().to_string(), &challenge);
    let response = crate::ask_phone(req.clone(), PHONE_TIMEOUT)?;
    let report = assess(&Policy::builtin(), &chain::google_roots(), unix_now() as i64, &challenge, &req, &response, revocation::current, allow_dev)?;
    if let Ok(mut s) = STATE.lock() {
        if s.epoch == epoch { s.cached = Some(Cached { report: report.clone(), at: Instant::now(), epoch }); }
    }
    Ok(report)
}

fn blocked(r: &Report) -> String { format!("attestation: {}", r.summary()) }

/// Gate for every signing path: the phone on USB must have passed (GENUINE or DEVELOPMENT) for
/// the pinned address in this connection; runs the check first if there is no current verdict.
pub fn require_ok(pinned: &str) -> Result<Report, String> {
    // Hold the phone while deciding, so a check another caller started finishes first and its
    // verdict is used here instead of a second check.
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    let report = match cached() {
        // The phone may have switched accounts since the cached check (same USB connection):
        // a cached verdict for another address is asked again, once, before refusing.
        Some(r) if r.verdict() != Verdict::Fail && !r.address.as_deref().is_some_and(|a| a.eq_ignore_ascii_case(pinned)) => run()?,
        Some(r) => r,
        None => run()?,
    };
    if report.verdict() == Verdict::Fail { return Err(blocked(&report)); }
    match &report.address {
        Some(a) if a.eq_ignore_ascii_case(pinned) => Ok(report),
        _ => Err("attestation: the phone on USB is using a different account or wallet than the one selected on this Mac. Switch accounts on the phone (☰ → Accounts) or on this Mac".into()),
    }
}

/// Gate for Bitcoin requests: the phone on USB must have passed the device check (GENUINE or
/// DEVELOPMENT) in this connection; runs it if there is no current verdict. The attested EVM
/// address is not compared here: Bitcoin requests are pinned by the account's xpub instead (the
/// returned address or signature must belong to it).
pub fn require_genuine() -> Result<Report, String> {
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    let report = match cached() { Some(r) => r, None => run()? };
    if report.verdict() == Verdict::Fail { return Err(blocked(&report)); }
    Ok(report)
}

/// Gate for pairing: the address being pinned must come from a phone that passed just now.
pub fn require_pairable(address: &str) -> Result<(), String> {
    let report = cached().ok_or("Check the phone first: its device check has not run for this connection.")?;
    if report.verdict() == Verdict::Fail { return Err(blocked(&report)); }
    match &report.address { Some(a) if a.eq_ignore_ascii_case(address) => Ok(()), _ => Err("This address is not the one the phone attested to.".into()) }
}

/// Forget the verdict for the phone on USB (Developer mode changed: it must be checked again).
fn invalidate() {
    if let Ok(mut s) = STATE.lock() { s.cached = None; s.epoch += 1; }
}

/// Fresh device check. Developer mode is read from this Mac's settings file, never from the webview.
#[tauri::command]
pub async fn attest_phone() -> CmdResult<Report> { blocking(run).await }

/// Whether Developer mode is on (Settings → Device).
#[tauri::command]
pub async fn developer_mode() -> CmdResult<bool> { Ok(devmode::enabled()) }

/// Turn Developer mode on (only with the exact typed confirmation) or off. Either way the current
/// verdict is dropped, so the next request runs a fresh check under the new setting.
#[tauri::command]
pub async fn set_developer_mode(on: bool, confirmation: Option<String>) -> CmdResult<bool> {
    blocking(move || {
        devmode::set(on, confirmation.as_deref())?;
        invalidate();
        Ok(devmode::enabled())
    }).await
}

/// The verdict for the phone on USB right now, if one was taken in this connection.
#[tauri::command]
pub async fn attestation_cached() -> CmdResult<Option<Report>> { Ok(cached()) }
