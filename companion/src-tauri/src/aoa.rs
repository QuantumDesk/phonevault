//! Android Open Accessory transport to the Phone Vault signer: switch a Pixel into accessory
//! mode, claim the vendor interface, exchange one newline-framed JSON request/response.
//!
//! Port of `tools/aoa_client.py`. Same identity strings (the phone's accessory filter matches
//! manufacturer + model), same framing, same 64 KiB response cap, same connect/recovery steps.

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
    /// Nothing on the phone reads the accessory, even after it was attached afresh (`connect`).
    #[error("{}", NOT_READING)]
    NotReading,
    /// The phone dropped off the bus while a request waited for its answer (the answer can no
    /// longer arrive on this handle). Classified like `Usb` ("disconnected").
    #[error("the phone left USB while this request waited for its answer ({0}). Check the phone, then ask again; if it keeps failing, unplug and replug the cable")]
    Left(rusb::Error),
}

/// What `AoaError::Busy` says. Also matched in the text of errors that reach the send flows as
/// strings (the device check returns `String`).
pub const USB_BUSY: &str =
    "the USB interface is held by another program (usually the adb server: run `adb kill-server`)";
/// What `AoaError::NoDevice` says (matched the same way).
pub const NO_DEVICE: &str = "no Android device on USB";
/// What `AoaError::NotReading` says.
pub const NOT_READING: &str = "the phone is not reading USB, even after reconnecting to it. Make sure Phone Vault is open on the phone, then unplug and replug the cable and try again";

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

// ---------------------------------------------------------------- connect: probe, switch, recover
//
// Whether a phone that is already an accessory has a live session cannot be read from its
// descriptors: an idle beta2 phone (18d1:2d00 before any handshake: vault-os frameworks-base-a17
// 0006), a phone whose app closed its session (the vault locked on an app that does not reopen it,
// the app restarted) and a phone whose app reads right now all look the same. The kernel accessory
// function (f_accessory) tells them apart on the wire: its reader keeps one bulk OUT request
// queued while the app is in read(), and drops a zero-length packet it receives (acc_read requeues
// on a 0-byte completion). So a ZLP on the OUT endpoint completes at once when the phone reads and
// is NAKed until timeout when nothing does: a liveness probe that the phone's app never sees and
// that answers nothing (the vault still answers no bytes while locked).
//
// A phone already in accessory mode does not re-enumerate for a new handshake: UsbDeviceManager's
// START handler sets the accessory function, which is already current, and the gadget HAL is not
// called for an unchanged set (setEnabledFunctions), so no new USB_ACCESSORY_ATTACHED reaches the
// app. What does: the gadget reporting CONFIGURED while START is pending (updateCurrentAccessory
// attaches the accessory with the new strings when MSG_ACCESSORY_MODE_ENTER_TIMEOUT, 10 s, is
// queued). A USB port reset makes the host re-configure the device: configfs sends CONFIGURED on
// SET_CONFIGURATION (android_setup → android_work). Without a pending START the same uevent makes
// the framework leave accessory mode instead (notifyAccessoryModeExit): the phone re-enumerates
// in its idle composition and the next pass switches it as usual. Either way no function is added.

/// (bus, address) of a device on the bus.
type Location = (u8, u8);

/// A Google device on the bus, as `connect` sees it.
#[derive(Clone)]
struct Seen<D> {
    dev: D,
    accessory: bool,
    at: Location,
}

/// What `connect` needs from USB: libusb in the app (`LibUsb`), a scripted fake in the tests.
trait Bus {
    type Dev: Clone;
    type Open;
    /// Every Google (18d1) device on the bus now.
    fn scan(&self) -> Result<Vec<Seen<Self::Dev>>, AoaError>;
    /// The AOA handshake on EP0: protocol version, our identity strings, START.
    fn handshake(&self, dev: &Self::Dev) -> Result<(), AoaError>;
    /// A USB port reset (Linux USBDEVFS_RESET; macOS re-enumeration).
    fn reset(&self, dev: &Self::Dev) -> Result<(), AoaError>;
    /// Open and claim the accessory interface, then wait up to `wait` for the phone to read it
    /// (`Session::phone_reads`). `None`: nothing on the phone reads it.
    fn open_reading(&self, dev: &Self::Dev, wait: Duration) -> Result<Option<Self::Open>, AoaError>;
    fn pause(&self, d: Duration);
}

/// Poll interval while waiting for the bus to change.
const POLL: Duration = Duration::from_millis(400);
/// How long an accessory that predates this connect gets to show that the phone reads it. A live
/// session takes the probe at once (its reader has a request queued).
const LIVE_PROBE: Duration = Duration::from_millis(2500);
/// After an attach (handshake, re-enumeration or reset), how long the phone's app may take to
/// open its session: USB_ACCESSORY_ATTACHED starts or wakes it, and it reads at once, even
/// behind the PIN gate.
const FRESH_ATTACH: Duration = Duration::from_secs(20);
/// After START, how long a phone may take to re-enumerate by itself before its port is reset. An
/// idle beta2 phone changes functions (charging composition → accessory); a Pixel 6a whose
/// accessory session ended re-attaches by itself too, about 4.0 s after START: a 4 s window reset
/// its port just as it came back, so it dropped and re-attached a second time under the session
/// just opened (Errno 19, reconnecttest step 6, 3 of 3 runs). Still well inside the framework's
/// 10 s START timeout (MSG_ACCESSORY_MODE_ENTER_TIMEOUT), which the reset needs to be pending.
const SELF_REENUMERATION: Duration = Duration::from_secs(7);
/// After a re-enumeration or a port reset the phone may come and go once more: it is opened only
/// after it has stayed at one address for this long.
const SETTLE: Duration = Duration::from_millis(1200);
/// How long the phone may be off the bus (re-enumerating) before it counts as gone.
const BACK_ON_BUS: Duration = Duration::from_secs(12);

fn polls(d: Duration) -> u32 {
    (d.as_millis() / POLL.as_millis()).max(1) as u32
}

/// Poll the bus until `found` returns something, for at most `within`.
fn wait_for<B: Bus, T>(
    bus: &B,
    within: Duration,
    found: impl Fn(&[Seen<B::Dev>]) -> Option<T>,
) -> Result<Option<T>, AoaError> {
    for _ in 0..polls(within) {
        bus.pause(POLL);
        if let Some(t) = found(&bus.scan()?) {
            return Ok(Some(t));
        }
    }
    Ok(None)
}

/// The phone: its accessory if it is one, else the single Android device. Several accessories, or
/// several plain Android devices, are refused. `patient`: during recovery the phone may be off the
/// bus for a moment.
fn the_phone<B: Bus>(bus: &B, patient: bool) -> Result<Seen<B::Dev>, AoaError> {
    fn pick<D: Clone>(seen: &[Seen<D>]) -> Result<Option<Seen<D>>, AoaError> {
        let accessories: Vec<&Seen<D>> = seen.iter().filter(|d| d.accessory).collect();
        if accessories.len() > 1 {
            return Err(proto(format!("expected one Phone Vault accessory, found {}", accessories.len())));
        }
        if let Some(a) = accessories.first() {
            return Ok(Some((*a).clone()));
        }
        if seen.len() > 1 {
            return Err(proto("more than one Android device is attached; keep only the vault on USB"));
        }
        Ok(seen.first().cloned())
    }
    if let Some(d) = pick(&bus.scan()?)? {
        return Ok(d);
    }
    if patient {
        for _ in 0..polls(BACK_ON_BUS) {
            bus.pause(POLL);
            if let Some(d) = pick(&bus.scan()?)? {
                return Ok(d);
            }
        }
    }
    Err(AoaError::NoDevice)
}

/// A device error that means "it is re-enumerating", not "it refused".
fn transient(e: &AoaError) -> bool {
    matches!(e, AoaError::Usb(rusb::Error::NoDevice | rusb::Error::NotFound | rusb::Error::Io | rusb::Error::Pipe))
}

/// Find the phone, switch it to our accessory if needed, and return the claimed interface once
/// something on the phone reads it. An accessory whose session is live is used as it is (no
/// handshake, no wait). A stale one is attached afresh once (`reattach`); if nothing reads then,
/// the bus is scanned again once and the phone probed where it now is (the phone's app reopens
/// its accessory by itself after a session it lost to the reset, which can take a moment longer
/// than the attach); if nothing reads even then, `NotReading` says to replug: never a silent wait.
fn connect_with<B: Bus>(bus: &B) -> Result<B::Open, AoaError> {
    let mut fresh = false;
    let mut recovered = false;
    let mut rescanned = false;
    let mut vanished = false;
    loop {
        let found = the_phone(bus, recovered || vanished)?;
        let accessory = if found.accessory {
            found
        } else {
            bus.handshake(&found.dev)?;
            fresh = true;
            wait_for(bus, BACK_ON_BUS, |seen| seen.iter().find(|d| d.accessory).cloned())?
                .ok_or_else(|| proto("the phone did not re-enumerate in accessory mode"))?
        };
        match bus.open_reading(&accessory.dev, if fresh { FRESH_ATTACH } else { LIVE_PROBE }) {
            Ok(Some(open)) => return Ok(open),
            Ok(None) => {}
            Err(e) if transient(&e) => {
                if !vanished {
                    // It left the bus under us (still re-enumerating): once, let it settle and
                    // open it again where it now is, without another START or reset.
                    vanished = true;
                    settle(bus)?;
                    continue;
                }
            }
            Err(e) => return Err(e),
        }
        if recovered {
            if !rescanned {
                rescanned = true;
                eprintln!("aoa: still nothing reading after the re-attach; scanning for the phone again");
                settle(bus)?;
                continue;
            }
            return Err(AoaError::NotReading);
        }
        recovered = true;
        fresh = true;
        eprintln!("aoa: nothing on the phone reads its accessory; attaching it afresh (START, then a port reset)");
        reattach(bus, &accessory)?;
    }
}

/// Wait (up to `BACK_ON_BUS`) until one Google device has stayed at the same address, in the same
/// mode, for `SETTLE`: a phone still re-enumerating is not opened (its handle would die). Not
/// settled: `connect_with`'s patient scan reports whatever is (or is not) there.
fn settle<B: Bus>(bus: &B) -> Result<(), AoaError> {
    let mut last: Option<(Location, bool)> = None;
    let mut since = Duration::ZERO;
    for _ in 0..polls(BACK_ON_BUS) {
        bus.pause(POLL);
        let seen = bus.scan()?;
        let now = if seen.len() == 1 { Some((seen[0].at, seen[0].accessory)) } else { None };
        if now.is_none() || now != last {
            last = now;
            since = Duration::ZERO;
            continue;
        }
        since += POLL;
        if since >= SETTLE {
            return Ok(());
        }
    }
    Ok(())
}

/// Make the phone attach our accessory afresh (a new USB_ACCESSORY_ATTACHED: its app opens a new
/// session): our identity and START, then, if the phone did not re-enumerate by itself, a port
/// reset while START is pending (see the section comment). Returns once the phone has settled,
/// so the next scan finds it where it stays.
fn reattach<B: Bus>(bus: &B, stale: &Seen<B::Dev>) -> Result<(), AoaError> {
    // A phone that does not answer the AOA requests is reset all the same.
    let _ = bus.handshake(&stale.dev);
    // Moved: our accessory left its old address (the phone dropped off the bus or came back at a
    // new address). Only a phone that never moved is reset.
    let moved = wait_for(bus, SELF_REENUMERATION, |seen| {
        (!seen.iter().any(|d| d.accessory && d.at == stale.at)).then_some(())
    })?;
    if moved.is_none() {
        if let Err(e) = bus.reset(&stale.dev) {
            if !transient(&e) {
                return Err(e);
            }
        }
    }
    settle(bus)
}

/// The libusb `Bus`.
struct LibUsb {
    ctx: Context,
}

impl Bus for LibUsb {
    type Dev = Device<Context>;
    type Open = Session;

    fn scan(&self) -> Result<Vec<Seen<Self::Dev>>, AoaError> {
        let mut out = Vec::new();
        for dev in self.ctx.devices()?.iter() {
            let d = dev.device_descriptor()?;
            if d.vendor_id() == GOOGLE_VENDOR_ID {
                let accessory = ACCESSORY_PRODUCTS.contains(&d.product_id());
                out.push(Seen { at: (dev.bus_number(), dev.address()), dev, accessory });
            }
        }
        Ok(out)
    }

    fn handshake(&self, dev: &Self::Dev) -> Result<(), AoaError> {
        send_identity(dev)
    }

    fn reset(&self, dev: &Self::Dev) -> Result<(), AoaError> {
        dev.open()?.reset()?;
        Ok(())
    }

    fn open_reading(&self, dev: &Self::Dev, wait: Duration) -> Result<Option<Session>, AoaError> {
        let session = Session::open(dev)?;
        if !session.phone_reads(wait)? {
            return Ok(None);
        }
        session.drain_stale();
        Ok(Some(session))
    }

    fn pause(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The AOA handshake on EP0: protocol version, our identity strings, START.
fn send_identity(device: &Device<Context>) -> Result<(), AoaError> {
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
    Ok(())
}

pub struct Session {
    handle: DeviceHandle<Context>,
    iface: u8,
    ep_in: u8,
    ep_out: u8,
}

impl Session {
    /// Find the phone, switch it to our accessory (or recover a stale one) and claim the
    /// interface once the phone reads it. See `connect_with`.
    pub fn connect() -> Result<Session, AoaError> {
        connect_with(&LibUsb { ctx: Context::new()? })
    }

    /// Open and claim an accessory's vendor interface.
    fn open(device: &Device<Context>) -> Result<Session, AoaError> {
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

    /// Does anything on the phone read the accessory? A zero-length packet on the OUT endpoint
    /// completes as soon as the phone's reader has a request queued (it is dropped there unseen);
    /// with no reader it is NAKed until the timeout. A host stack that refuses a zero-length write
    /// outright gets the benefit of the doubt (the request write then waits, as before this probe).
    fn phone_reads(&self, within: Duration) -> Result<bool, AoaError> {
        let deadline = Instant::now() + within;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Ok(false);
            }
            match self.handle.write_bulk(self.ep_out, &[], left.min(Duration::from_millis(500))) {
                Ok(_) => return Ok(true),
                Err(rusb::Error::Timeout) => continue,
                Err(e) if transient(&AoaError::Usb(e)) => return Err(AoaError::Usb(e)),
                Err(_) => return Ok(true),
            }
        }
    }

    /// Throw away anything the phone sent to an earlier host process that never read it (a
    /// response to a request whose client went away): this exchange must only see its own answer.
    fn drain_stale(&self) {
        let mut sink = vec![0u8; 16_384];
        for _ in 0..64 {
            match self.handle.read_bulk(self.ep_in, &mut sink, Duration::from_millis(50)) {
                Ok(_) => continue,
                Err(_) => break,
            }
        }
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
                // Re-enumerated or reset under us: this handle will never see the answer.
                Err(e @ (rusb::Error::NoDevice | rusb::Error::NotFound | rusb::Error::Io | rusb::Error::Pipe)) => {
                    return Err(AoaError::Left(e))
                }
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

#[cfg(test)]
mod connect_tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Mode {
        /// adb only (18d1:4ee7): a dev phone outside accessory mode
        Adb,
        /// beta2 idle: the accessory composition before any handshake (no strings, no reader)
        Idle,
        /// our accessory; `reader`: the app has a session open
        Accessory {
            reader: bool,
        },
        Gone,
    }

    /// A phone as UsbDeviceManager + f_accessory behave (see the comment above `Location`).
    struct Phone {
        mode: Mode,
        address: u8,
        start_pending: bool,
        /// whether the app opens a session when the accessory is attached afresh
        app_reads: bool,
        /// a beta2 phone falls back to Idle (not Adb) when it leaves accessory mode
        idle_is_accessory: bool,
        handshakes: u32,
        resets: u32,
        /// Pixel 6a: a stale accessory re-attaches by itself this long after START (still listed
        /// until then, off the bus for 0.4 s, then back at a new address with a reader)
        self_reattach_after: Option<Duration>,
        reattach_at: Option<Duration>,
        /// the phone drops off the bus as the next N opens start (still re-enumerating)
        vanish_on_open: u32,
        /// the app opens its session late: the next N opens find nothing reading, whatever the mode
        late_reader_opens: u32,
        vanished_opens: u32,
        clock: Duration,
        /// the 6a race: a port reset while it was re-attaching by itself
        reset_while_moving: bool,
    }

    impl Phone {
        fn tick(&mut self) {
            if let Some(at) = self.reattach_at {
                if self.clock >= at + POLL {
                    self.reattach_at = None;
                    self.start_pending = false;
                    self.mode = Mode::Accessory { reader: self.app_reads };
                    self.address += 1;
                }
            }
        }
        fn moving(&self) -> bool {
            matches!(self.reattach_at, Some(at) if self.clock >= at)
        }
    }

    struct Fake(RefCell<Phone>);

    fn phone(mode: Mode, app_reads: bool) -> Fake {
        Fake(RefCell::new(Phone {
            mode,
            address: 10,
            start_pending: false,
            app_reads,
            idle_is_accessory: mode == Mode::Idle,
            handshakes: 0,
            resets: 0,
            self_reattach_after: None,
            reattach_at: None,
            vanish_on_open: 0,
            late_reader_opens: 0,
            vanished_opens: 0,
            clock: Duration::ZERO,
            reset_while_moving: false,
        }))
    }

    impl Bus for Fake {
        type Dev = u8;
        type Open = u8;
        fn scan(&self) -> Result<Vec<Seen<u8>>, AoaError> {
            let mut p = self.0.borrow_mut();
            p.tick();
            if p.moving() {
                return Ok(vec![]);
            }
            Ok(match p.mode {
                Mode::Gone => vec![],
                Mode::Adb => vec![Seen { dev: p.address, accessory: false, at: (1, p.address) }],
                _ => vec![Seen { dev: p.address, accessory: true, at: (1, p.address) }],
            })
        }
        fn handshake(&self, dev: &u8) -> Result<(), AoaError> {
            let mut p = self.0.borrow_mut();
            if *dev != p.address && p.vanished_opens > 0 {
                return Err(AoaError::Usb(rusb::Error::NoDevice)); // a handle from before it vanished
            }
            assert_eq!(*dev, p.address);
            p.handshakes += 1;
            match p.mode {
                // the function set changes: the gadget re-composes and the accessory is attached
                Mode::Adb | Mode::Idle => {
                    p.mode = Mode::Accessory { reader: p.app_reads };
                    p.address += 1;
                }
                // unchanged function set: nothing re-enumerates, START stays pending
                Mode::Accessory { .. } => {
                    p.start_pending = true;
                    if let Some(after) = p.self_reattach_after {
                        p.reattach_at = Some(p.clock + after);
                    }
                }
                Mode::Gone => return Err(AoaError::Usb(rusb::Error::NoDevice)),
            }
            Ok(())
        }
        fn reset(&self, dev: &u8) -> Result<(), AoaError> {
            let mut p = self.0.borrow_mut();
            assert_eq!(*dev, p.address);
            p.resets += 1;
            if p.reattach_at.is_some() {
                p.reset_while_moving = true;
            }
            if let Mode::Accessory { .. } = p.mode {
                if p.start_pending {
                    // CONFIGURED with START pending: attached afresh, the app opens a session
                    p.mode = Mode::Accessory { reader: p.app_reads };
                } else {
                    // CONFIGURED without START: the framework leaves accessory mode
                    p.mode = if p.idle_is_accessory { Mode::Idle } else { Mode::Adb };
                    p.address += 1;
                }
                p.start_pending = false;
            }
            Ok(())
        }
        fn open_reading(&self, dev: &u8, _wait: Duration) -> Result<Option<u8>, AoaError> {
            let mut p = self.0.borrow_mut();
            p.tick();
            if p.vanish_on_open > 0 {
                p.vanish_on_open -= 1;
                p.vanished_opens += 1;
                p.address += 1; // back a moment later, at a new address
                return Err(AoaError::Usb(rusb::Error::NoDevice));
            }
            if *dev != p.address || p.moving() {
                return Err(AoaError::Usb(rusb::Error::NoDevice));
            }
            if p.late_reader_opens > 0 {
                p.late_reader_opens -= 1;
                return Ok(None);
            }
            Ok(match p.mode {
                Mode::Accessory { reader: true } => Some(*dev),
                _ => None,
            })
        }
        fn pause(&self, d: Duration) {
            self.0.borrow_mut().clock += d;
        }
    }

    fn counts(f: &Fake) -> (u32, u32) {
        let p = f.0.borrow();
        (p.handshakes, p.resets)
    }

    #[test]
    fn a_live_session_is_used_as_it_is() {
        let f = phone(Mode::Accessory { reader: true }, true);
        assert!(connect_with(&f).is_ok());
        assert_eq!(counts(&f), (0, 0), "no handshake, no reset");
    }

    #[test]
    fn a_plain_android_phone_is_switched() {
        let f = phone(Mode::Adb, true);
        assert_eq!(connect_with(&f).unwrap(), 11);
        assert_eq!(counts(&f), (1, 0));
    }

    #[test]
    fn an_idle_beta2_accessory_gets_our_identity_and_re_enumerates() {
        let f = phone(Mode::Idle, true);
        assert_eq!(connect_with(&f).unwrap(), 11);
        assert_eq!(counts(&f), (1, 0), "START changes its functions: no reset needed");
    }

    #[test]
    fn a_stale_session_is_attached_afresh_by_start_and_a_port_reset() {
        // the vault locked (on an app that does not reopen), or the app restarted: no reader
        let f = phone(Mode::Accessory { reader: false }, true);
        assert_eq!(connect_with(&f).unwrap(), 10);
        assert_eq!(counts(&f), (1, 1));
    }

    #[test]
    fn nothing_reading_even_after_recovery_says_replug() {
        let f = phone(Mode::Accessory { reader: false }, false);
        let e = connect_with(&f).expect_err("must fail");
        assert!(matches!(e, AoaError::NotReading));
        assert!(e.to_string().contains("unplug and replug"));
        assert_eq!(counts(&f), (1, 1), "one recovery only");
    }

    #[test]
    fn after_the_reset_the_phone_is_scanned_again_once_before_replug() {
        // The phone's app lost its session to the reset and reopens the accessory a moment after
        // the first post-reset probe gave up: one more scan finds it, with no second START/reset.
        let f = phone(Mode::Accessory { reader: false }, true);
        f.0.borrow_mut().late_reader_opens = 2; // the stale probe, then the first post-reset probe
        assert_eq!(connect_with(&f).unwrap(), 10);
        assert_eq!(counts(&f), (1, 1), "one recovery, then a re-scan only");
        // Still nothing after the re-scan: replug, never a third probe or a second reset.
        let g = phone(Mode::Accessory { reader: false }, true);
        g.0.borrow_mut().late_reader_opens = 3;
        let e = connect_with(&g).expect_err("must fail");
        assert!(matches!(e, AoaError::NotReading));
        assert!(e.to_string().contains("unplug and replug"));
        assert_eq!(counts(&g), (1, 1));
    }

    #[test]
    fn a_phone_that_left_mid_wait_says_so() {
        let e = AoaError::Left(rusb::Error::NoDevice);
        assert!(e.to_string().contains("left USB"));
        assert!(e.to_string().contains("unplug and replug"));
    }

    #[test]
    fn a_fresh_switch_whose_app_never_reads_is_recovered_once_then_refused() {
        let f = phone(Mode::Adb, false);
        assert!(matches!(connect_with(&f), Err(AoaError::NotReading)));
        assert_eq!(counts(&f), (2, 1));
    }

    #[test]
    fn a_phone_that_reattaches_by_itself_after_4s_is_not_reset() {
        // Pixel 6a: START on a stale accessory re-attaches it ~4.0 s later. The client waits for
        // that (no port reset racing it) and opens it only once it has settled.
        let f = phone(Mode::Accessory { reader: false }, true);
        f.0.borrow_mut().self_reattach_after = Some(Duration::from_secs(4));
        assert_eq!(connect_with(&f).unwrap(), 11);
        assert_eq!(counts(&f), (1, 0));
        assert!(!f.0.borrow().reset_while_moving);
        assert!(SELF_REENUMERATION > Duration::from_secs(4) + POLL * 2);
        assert!(SELF_REENUMERATION < Duration::from_secs(10), "the reset must come while START is pending");
    }

    #[test]
    fn a_phone_that_vanishes_as_it_is_opened_is_opened_again_once() {
        let f = phone(Mode::Accessory { reader: true }, true);
        f.0.borrow_mut().vanish_on_open = 1;
        assert_eq!(connect_with(&f).unwrap(), 11);
        assert_eq!(counts(&f), (0, 0), "no START, no reset for a retry");
        // The retry is once only: a second vanish goes through the ordinary (single) recovery,
        // and a third through its one re-scan; a fourth is refused (replug).
        let thrice = phone(Mode::Accessory { reader: true }, true);
        thrice.0.borrow_mut().vanish_on_open = 3;
        assert!(connect_with(&thrice).is_ok(), "the re-scan after the recovery finds it");
        assert_eq!(thrice.0.borrow().resets, 0, "it moved: never reset");
        let four = phone(Mode::Accessory { reader: true }, true);
        four.0.borrow_mut().vanish_on_open = 4;
        assert!(matches!(connect_with(&four), Err(AoaError::NotReading)));
        assert_eq!(four.0.borrow().resets, 0, "it moved: never reset");
    }

    #[test]
    fn settle_waits_for_a_stable_address() {
        let f = phone(Mode::Accessory { reader: true }, true);
        settle(&f).unwrap();
        let took = f.0.borrow().clock;
        assert!(took >= SETTLE && took < SETTLE + POLL * 2, "{took:?}");
    }

    #[test]
    fn no_phone_and_two_phones_are_refused() {
        let f = phone(Mode::Gone, true);
        assert!(matches!(connect_with(&f), Err(AoaError::NoDevice)));
        struct Two;
        impl Bus for Two {
            type Dev = u8;
            type Open = u8;
            fn scan(&self) -> Result<Vec<Seen<u8>>, AoaError> {
                Ok(vec![Seen { dev: 1, accessory: true, at: (1, 1) }, Seen { dev: 2, accessory: true, at: (1, 2) }])
            }
            fn handshake(&self, _: &u8) -> Result<(), AoaError> {
                unreachable!()
            }
            fn reset(&self, _: &u8) -> Result<(), AoaError> {
                unreachable!()
            }
            fn open_reading(&self, _: &u8, _: Duration) -> Result<Option<u8>, AoaError> {
                unreachable!()
            }
            fn pause(&self, _: Duration) {}
        }
        assert!(matches!(connect_with(&Two), Err(AoaError::Protocol(ref m)) if m.contains("found 2")));
    }
}
