//! Android Open Accessory transport to the Phone Vault signer: switch a Pixel into accessory
//! mode, claim the vendor interface, exchange one newline-framed JSON request/response.
//!
//! Port of `tools/aoa_client.py`. Same identity strings (the phone's accessory filter matches
//! manufacturer + model), same framing, same 64 KiB response cap.

use rusb::{Context, Device, DeviceHandle, Direction, Recipient, RequestType, TransferType, UsbContext};
use serde_json::Value;
use std::time::{Duration, Instant};

pub const GOOGLE_VENDOR_ID: u16 = 0x18D1;
const ACCESSORY_PRODUCTS: [u16; 2] = [0x2D00, 0x2D01];
const AOA_GET_PROTOCOL: u8 = 51;
const AOA_SEND_IDENT: u8 = 52;
const AOA_START: u8 = 53;
const IDENTITY: [&str; 6] = [
    "PhoneVault",
    "EVM Signer",
    "User-confirmed offline EVM signing prototype",
    "1.0",
    "https://example.invalid/phone-vault",
    "prototype",
];
const MAX_RESPONSE_BYTES: usize = 65_536;
/// btcSignPsbt answers carry the whole signed PSBT (btc::tx::MAX_PSBT_BYTES plus signatures, base64).
pub const MAX_PSBT_RESPONSE_BYTES: usize = 272 * 1024;

/// The response cap for one request: larger only for btcSignPsbt.
fn response_cap(request: &Value) -> usize {
    if request.get("method").and_then(Value::as_str) == Some("btcSignPsbt") {
        MAX_PSBT_RESPONSE_BYTES
    } else {
        MAX_RESPONSE_BYTES
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AoaError {
    #[error("usb: {0}")]
    Usb(#[from] rusb::Error),
    #[error("{0}")]
    Protocol(String),
    #[error("{}", NO_DEVICE)]
    NoDevice,
    /// The accessory interface could not be claimed: another process (or session) holds it.
    #[error("{}", USB_BUSY)]
    Busy,
    #[error(
        "the phone did not answer within {0} s (locked, or its USB session ended). Unlock it, or unplug and reconnect the cable"
    )]
    Timeout(u64),
}

/// What `AoaError::Busy` says. Also matched in the text of errors that reach the send flows as
/// strings (the device check returns `String`).
pub const USB_BUSY: &str =
    "the USB interface is held by another program (usually the adb server: run `adb kill-server`)";
/// What `AoaError::NoDevice` says (matched the same way).
pub const NO_DEVICE: &str = "no Android device on USB";

fn proto(msg: impl Into<String>) -> AoaError {
    AoaError::Protocol(msg.into())
}

/// What the host can see on the bus right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    None,
    Android,
    Accessory,
}

pub fn presence() -> Result<Presence, AoaError> {
    let ctx = Context::new()?;
    let mut seen = Presence::None;
    for dev in ctx.devices()?.iter() {
        let d = dev.device_descriptor()?;
        if d.vendor_id() != GOOGLE_VENDOR_ID {
            continue;
        }
        if ACCESSORY_PRODUCTS.contains(&d.product_id()) {
            return Ok(Presence::Accessory);
        }
        seen = Presence::Android;
    }
    Ok(seen)
}

fn google_devices(ctx: &Context) -> Result<Vec<Device<Context>>, AoaError> {
    let mut out = Vec::new();
    for dev in ctx.devices()?.iter() {
        if dev.device_descriptor()?.vendor_id() == GOOGLE_VENDOR_ID {
            out.push(dev);
        }
    }
    Ok(out)
}

fn accessory_device(ctx: &Context) -> Result<Option<Device<Context>>, AoaError> {
    let mut found: Vec<Device<Context>> = google_devices(ctx)?
        .into_iter()
        .filter(|d| d.device_descriptor().is_ok_and(|x| ACCESSORY_PRODUCTS.contains(&x.product_id())))
        .collect();
    if found.len() > 1 {
        return Err(proto(format!("expected one Phone Vault accessory, found {}", found.len())));
    }
    Ok(found.pop())
}

/// Ask the phone to re-enumerate as our accessory. No-op if it already did.
fn switch_to_accessory(ctx: &Context) -> Result<Device<Context>, AoaError> {
    if let Some(acc) = accessory_device(ctx)? {
        return Ok(acc);
    }
    let mut devices = google_devices(ctx)?;
    let device = devices.pop().ok_or(AoaError::NoDevice)?;
    if devices.len() > 1 {
        return Err(proto("more than one Android device is attached; keep only the vault on USB"));
    }
    let handle = device.open()?;
    let t = Duration::from_secs(2);
    let mut version = [0u8; 2];
    let rt_in = rusb::request_type(Direction::In, RequestType::Vendor, Recipient::Device);
    let rt_out = rusb::request_type(Direction::Out, RequestType::Vendor, Recipient::Device);
    handle.read_control(rt_in, AOA_GET_PROTOCOL, 0, 0, &mut version, t)?;
    let v = u16::from_le_bytes(version);
    if v < 1 {
        return Err(proto(format!("unsupported Android Open Accessory protocol {v}")));
    }
    for (index, value) in IDENTITY.iter().enumerate() {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        handle.write_control(rt_out, AOA_SEND_IDENT, 0, index as u16, &bytes, t)?;
    }
    handle.write_control(rt_out, AOA_START, 0, 0, &[], t)?;
    drop(handle);
    let deadline = Instant::now() + Duration::from_secs(12);
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(400));
        if let Some(acc) = accessory_device(ctx)? {
            return Ok(acc);
        }
    }
    Err(proto("the phone did not re-enumerate in accessory mode"))
}

pub struct Session {
    handle: DeviceHandle<Context>,
    iface: u8,
    ep_in: u8,
    ep_out: u8,
}

impl Session {
    /// Switch (if needed), open and claim the accessory interface.
    pub fn connect() -> Result<Session, AoaError> {
        let ctx = Context::new()?;
        let device = switch_to_accessory(&ctx)?;
        let handle = device.open()?;
        // Only configure a device that has no active configuration: re-issuing SET_CONFIGURATION
        // to a configured Android gadget resets it out of accessory mode (observed on Linux).
        match handle.active_configuration() {
            Ok(0) | Err(_) => handle.set_active_configuration(1)?,
            Ok(_) => {}
        }
        let config = device.active_config_descriptor()?;
        let mut chosen = None;
        for interface in config.interfaces() {
            for desc in interface.descriptors() {
                if (desc.class_code(), desc.sub_class_code(), desc.protocol_code()) != (0xFF, 0xFF, 0x00) {
                    continue;
                }
                let eps: Vec<_> = desc.endpoint_descriptors().collect();
                if eps.len() != 2 || eps.iter().any(|e| e.transfer_type() != TransferType::Bulk) {
                    continue;
                }
                let ep_in = eps.iter().find(|e| e.direction() == Direction::In).map(rusb::EndpointDescriptor::address);
                let ep_out =
                    eps.iter().find(|e| e.direction() == Direction::Out).map(rusb::EndpointDescriptor::address);
                if let (Some(i), Some(o)) = (ep_in, ep_out) {
                    chosen = Some((desc.interface_number(), i, o));
                }
            }
        }
        let (iface, ep_in, ep_out) =
            chosen.ok_or_else(|| proto("accessory interface with two bulk endpoints not found"))?;
        handle.claim_interface(iface).map_err(|e| match e {
            rusb::Error::Busy | rusb::Error::Access => AoaError::Busy,
            other => AoaError::Usb(other),
        })?;
        Ok(Session { handle, iface, ep_in, ep_out })
    }

    /// One request, one newline-framed JSON response. `timeout` covers the wait for on-device approval.
    pub fn exchange(&mut self, request: &Value, timeout: Duration) -> Result<Value, AoaError> {
        self.exchange_observed(request, timeout, || {}, || false)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(self.iface);
    }
}

// ---------------------------------------------------------------- one conversation at a time
//
// The accessory interface can be claimed by one session at a time; a second `connect` while
// another request is on the phone fails with `AoaError::Busy` ("USB busy" if Send starts
// during an identify or a WalletConnect request). So every exchange takes a turn first. Holders
// are bounded by their own timeouts, so a turn always comes.

use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, TryLockError};

static PHONE: Mutex<()> = Mutex::new(());
thread_local!(static HELD: Cell<bool> = const { Cell::new(false) });

/// This thread's turn with the phone; released on drop. Re-entrant on the same thread (the send
/// path takes a turn, then the device check inside it asks the phone too).
pub struct PhoneTurn {
    guard: Option<MutexGuard<'static, ()>>,
}
impl Drop for PhoneTurn {
    fn drop(&mut self) {
        if self.guard.take().is_some() {
            HELD.with(|h| h.set(false));
        }
    }
}

/// Wait for the phone. `on_wait` runs once if someone else has it; `cancelled` is polled while waiting.
pub fn take_turn(on_wait: impl FnOnce(), cancelled: impl Fn() -> bool) -> Result<PhoneTurn, AoaError> {
    if HELD.with(Cell::get) {
        return Ok(PhoneTurn { guard: None });
    }
    let mut on_wait = Some(on_wait);
    loop {
        match PHONE.try_lock() {
            Ok(g) => {
                HELD.with(|h| h.set(true));
                return Ok(PhoneTurn { guard: Some(g) });
            }
            Err(TryLockError::Poisoned(p)) => {
                HELD.with(|h| h.set(true));
                return Ok(PhoneTurn { guard: Some(p.into_inner()) });
            }
            Err(TryLockError::WouldBlock) => {}
        }
        if let Some(f) = on_wait.take() {
            f();
        }
        if cancelled() {
            return Err(proto(CANCELLED));
        }
        std::thread::sleep(Duration::from_millis(150));
    }
}

// ---------------------------------------------------------------- observed exchange (UI progress)
//
// The one implementation of the exchange (`exchange` calls it with no-op hooks). The two hooks are
// what the send flows need so the UI can tell the truth: `on_delivered` fires once the request is
// actually in the phone's hands (the bulk write completed), and `cancelled` is polled about once a
// second so the user can stop waiting.
pub const CANCELLED: &str = "cancelled on this Mac";
impl Session {
    /// The phone only reads once its app has opened the session (it wakes the screen and does so
    /// on attach, but a sleeping phone needs a moment): the request is offered for up to 60 s
    /// instead of failing on the first 5-second write timeout.
    pub fn exchange_observed(
        &mut self,
        request: &Value,
        timeout: Duration,
        on_delivered: impl FnOnce(),
        cancelled: impl Fn() -> bool,
    ) -> Result<Value, AoaError> {
        let id =
            request.get("id").and_then(Value::as_str).ok_or_else(|| proto("request needs a string id"))?.to_string();
        let mut payload = serde_json::to_vec(request).map_err(|e| proto(e.to_string()))?;
        payload.push(b'\n');
        let write_deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if cancelled() {
                return Err(proto(CANCELLED));
            }
            match self.handle.write_bulk(self.ep_out, &payload, Duration::from_secs(5)) {
                Ok(_) => break,
                Err(rusb::Error::Timeout) if Instant::now() < write_deadline => continue,
                Err(rusb::Error::Timeout) => return Err(proto("the phone is not reading USB. Wake it, unlock it and try again; if it still fails, unplug and reconnect the cable")),
                Err(other) => return Err(AoaError::Usb(other)),
            }
        }
        on_delivered();
        let deadline = Instant::now() + timeout;
        let cap = response_cap(request);
        let mut received: Vec<u8> = Vec::new();
        let mut chunk = vec![0u8; 16_384];
        while Instant::now() < deadline {
            if cancelled() {
                return Err(proto(CANCELLED));
            }
            match self.handle.read_bulk(self.ep_in, &mut chunk, Duration::from_secs(1)) {
                Ok(n) => received.extend_from_slice(&chunk[..n]),
                Err(rusb::Error::Timeout) => continue,
                Err(e) => return Err(AoaError::Usb(e)),
            }
            if received.len() > cap {
                return Err(proto(format!("phone response exceeds {} KiB", cap / 1024)));
            }
            if let Some(pos) = received.iter().position(|&b| b == b'\n') {
                if received.len() > pos + 1 {
                    return Err(proto("phone returned more than one framed response"));
                }
                let line = std::str::from_utf8(&received[..pos]).map_err(|_| proto("phone response is not UTF-8"))?;
                let response: Value = serde_json::from_str(line).map_err(|_| proto("phone response is not JSON"))?;
                if !response.is_object() {
                    return Err(proto("phone response must be a JSON object"));
                }
                if response.get("id").and_then(Value::as_str) != Some(id.as_str()) {
                    return Err(proto("phone response id does not match the request"));
                }
                return Ok(response);
            }
        }
        Err(AoaError::Timeout(timeout.as_secs()))
    }
}

#[cfg(test)]
mod turn_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;

    #[test]
    fn turns_serialize_reenter_and_cancel() {
        let first = take_turn(|| panic!("free phone must not wait"), || false).unwrap();
        // re-entrant on the same thread
        let inner = take_turn(|| panic!("same thread must not wait"), || false).unwrap();
        drop(inner);
        // another thread waits, says so once, and can be cancelled
        let waited = Arc::new(AtomicUsize::new(0));
        let cancel = Arc::new(AtomicBool::new(false));
        let (w, c) = (waited.clone(), cancel.clone());
        let t = std::thread::spawn(move || {
            take_turn(
                || {
                    w.fetch_add(1, Ordering::SeqCst);
                },
                || c.load(Ordering::SeqCst),
            )
            .map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(400));
        cancel.store(true, Ordering::SeqCst);
        assert!(matches!(t.join().unwrap(), Err(AoaError::Protocol(ref m)) if m == CANCELLED));
        assert_eq!(waited.load(Ordering::SeqCst), 1);
        // and gets the phone once the holder lets go
        let w2 = waited.clone();
        let t2 = std::thread::spawn(move || {
            take_turn(
                || {
                    w2.fetch_add(1, Ordering::SeqCst);
                },
                || false,
            )
            .map(|_| ())
        });
        std::thread::sleep(Duration::from_millis(300));
        drop(first);
        assert!(t2.join().unwrap().is_ok());
        assert_eq!(waited.load(Ordering::SeqCst), 2);
        assert!(take_turn(|| panic!("released"), || false).is_ok());
    }
}
