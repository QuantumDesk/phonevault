//! What the ETH (`send.rs`) and Bitcoin (`btc/mod.rs`) send flows share: the error the UI explains,
//! the `send-progress` events, the per-ticket cancel flag, the turn with the phone, and the one
//! request/answer exchange with its error mapping. Each flow keeps its own steps around these: which
//! device check gates it, what is checked before the phone sees the request, and how the answer is
//! verified.

use crate::aoa;
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tauri::{AppHandle, Emitter};

/// A failure the UI can explain: `kind` picks the plain-language text, `message` is the detail,
/// `delivered` says whether the request had reached the phone.
#[derive(Serialize, Debug)]
pub struct SendError {
    pub(crate) kind: &'static str,
    pub(crate) message: String,
    pub(crate) delivered: bool,
}

pub fn fail(kind: &'static str, message: impl Into<String>, delivered: bool) -> SendError {
    SendError { kind, message: message.into(), delivered }
}

#[derive(Serialize, Clone)]
struct Progress {
    ticket: String,
    stage: &'static str,
}

/// Requests in flight, by ticket: each can be cancelled on its own.
pub type Cancels = Arc<Mutex<HashMap<String, Arc<AtomicBool>>>>;

/// Forgets the ticket however the command ends.
pub struct TicketGuard(Cancels, String);
impl Drop for TicketGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = self.0.lock() {
            m.remove(&self.1);
        }
    }
}

/// One send in flight: emits its progress and answers whether it was cancelled.
pub struct Flow {
    app: AppHandle,
    ticket: String,
    cancel: Arc<AtomicBool>,
}

/// Register `ticket` (refused while a request with the same ticket runs).
pub fn start(cancels: &Cancels, app: AppHandle, ticket: String) -> Result<(Flow, TicketGuard), SendError> {
    let cancel = Arc::new(AtomicBool::new(false));
    {
        let mut m = cancels.lock().map_err(|_| fail("internal", "state poisoned", false))?;
        if m.contains_key(&ticket) {
            return Err(fail("busy", "this request is already running", false));
        }
        m.insert(ticket.clone(), cancel.clone());
    }
    let guard = TicketGuard(cancels.clone(), ticket.clone());
    Ok((Flow { app, ticket, cancel }, guard))
}

/// Stop waiting for the phone: one request by ticket, or every request in flight without one.
pub fn cancel(cancels: &Cancels, ticket: Option<&str>) {
    if let Ok(m) = cancels.lock() {
        for (t, c) in m.iter() {
            if ticket.is_none_or(|x| x == t) {
                c.store(true, Ordering::SeqCst);
            }
        }
    }
}

impl Flow {
    pub fn emit(&self, stage: &'static str) {
        let _ = self.app.emit("send-progress", Progress { ticket: self.ticket.clone(), stage });
    }

    pub fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::SeqCst)
    }

    /// Fails with "cancelled" (not delivered) if the user cancelled.
    pub fn check_cancelled(&self) -> Result<(), SendError> {
        if self.cancelled() {
            return Err(fail("cancelled", aoa::CANCELLED, false));
        }
        Ok(())
    }

    /// Wait our turn with the phone (an identify, a device check or a dApp request may be on it):
    /// the UI shows "waiting for the phone" instead of failing with "USB busy".
    pub fn take_turn(&self) -> Result<aoa::PhoneTurn, SendError> {
        let mut waited = false;
        let turn = aoa::take_turn(
            || {
                waited = true;
                self.emit("waiting");
            },
            || self.cancelled(),
        )
        .map_err(|_| fail("cancelled", aoa::CANCELLED, false))?;
        if waited {
            self.emit("connecting");
        }
        Ok(turn)
    }

    /// Connect, hand the request to the phone and wait for its answer (progress: connecting →
    /// delivered → verifying). The answer is not checked here; each flow verifies its own.
    pub fn exchange(&self, request: &Value, timeout: Duration) -> Result<Value, SendError> {
        phone_exchange(request, timeout, |stage| self.emit(stage), || self.cancelled())
    }
}

/// A device-check failure (the gate returns `String`) as the UI's kinds. The Bitcoin flow uses this
/// as is; the ETH flow additionally maps "a genuine check is already running" to `busy`.
pub fn gate_failure(m: String) -> SendError {
    if m.starts_with("attestation:") {
        fail("attestation", m.trim_start_matches("attestation:").trim().to_string(), false)
    } else if m.contains(aoa::NO_DEVICE) {
        fail("no_phone", m, false)
    } else if m.contains(aoa::USB_BUSY) {
        fail("usb_busy", m, false)
    } else {
        fail("connect", m, false)
    }
}

/// One request/answer with the phone for a send, with the error mapping the UI relies on:
/// `delivered` is true once the bulk write completed (the phone has the request).
pub fn phone_exchange(
    request: &Value,
    timeout: Duration,
    emit: impl Fn(&'static str),
    cancelled: impl Fn() -> bool,
) -> Result<Value, SendError> {
    emit("connecting");
    let mut session = aoa::Session::connect().map_err(|e| match e {
        aoa::AoaError::NoDevice => fail("no_phone", e.to_string(), false),
        aoa::AoaError::Busy => fail("usb_busy", e.to_string(), false),
        other => fail("connect", other.to_string(), false),
    })?;
    if cancelled() {
        return Err(fail("cancelled", aoa::CANCELLED, false));
    }
    let delivered = AtomicBool::new(false);
    let response = session
        .exchange_observed(
            request,
            timeout,
            || {
                delivered.store(true, Ordering::SeqCst);
                emit("delivered");
            },
            &cancelled,
        )
        .map_err(|e| {
            let d = delivered.load(Ordering::SeqCst);
            match e {
                aoa::AoaError::Protocol(ref m) if m == aoa::CANCELLED => fail("cancelled", m.clone(), d),
                aoa::AoaError::Timeout(_) => fail("timeout", e.to_string(), d),
                aoa::AoaError::Usb(_) => fail("disconnected", e.to_string(), d),
                other if !d => fail("not_delivered", other.to_string(), d),
                other => fail("protocol", other.to_string(), d),
            }
        })?;
    drop(session);
    emit("verifying");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gate_failures_keep_their_kinds() {
        let kind = |m: &str| gate_failure(m.to_string()).kind;
        assert_eq!(kind("attestation: the phone failed"), "attestation");
        assert_eq!(gate_failure("attestation:  x ".into()).message, "x");
        assert_eq!(kind(aoa::NO_DEVICE), "no_phone");
        assert_eq!(kind(aoa::USB_BUSY), "usb_busy");
        assert_eq!(kind(&aoa::AoaError::Busy.to_string()), "usb_busy");
        assert_eq!(kind("a genuine check is already running"), "connect");
    }

    #[test]
    fn cancel_by_ticket_or_all() {
        let cancels = Cancels::default();
        let (a, b) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicBool::new(false)));
        cancels.lock().unwrap().insert("a".into(), a.clone());
        cancels.lock().unwrap().insert("b".into(), b.clone());
        cancel(&cancels, Some("a"));
        assert!(a.load(Ordering::SeqCst) && !b.load(Ordering::SeqCst));
        cancel(&cancels, None);
        assert!(b.load(Ordering::SeqCst));
        drop(TicketGuard(cancels.clone(), "a".into()));
        assert!(!cancels.lock().unwrap().contains_key("a"));
    }
}
