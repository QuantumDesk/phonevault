//! Pending-request queue entries, the connection backoff and app alerts.

use super::{CONNECT_BACKOFF_MAX, CONNECT_BACKOFF_START, CONNECT_WITHDRAWN_BACKOFF_START};
use serde::Serialize;
use serde_json::Value;
use std::time::{Duration, Instant};

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingKind {
    Connect,
    Request,
}

#[derive(Clone, Debug)]
pub(super) struct Pending {
    pub(super) id: u64,
    pub(super) conn: u64,
    pub(super) ext_id: u64,
    pub(super) origin: String,
    pub(super) method: String,
    pub(super) params: Value,
    pub(super) chain: u64,
    pub(super) kind: PendingKind,
    pub(super) created: u64,
}

/// A waiting request, as the webview sees it.
#[derive(Serialize, Clone, Debug)]
pub struct PendingOut {
    pub id: u64,
    pub kind: PendingKind,
    pub origin: String,
    pub host: String,
    pub local: bool,
    pub method: String,
    pub params: Value,
    pub chain_id: u64,
    pub created: u64,
}

/// What the app shows for something the user should know about but need not answer.
#[derive(Clone, Debug, PartialEq)]
pub enum Alert {
    /// A request now waits for the user: bring the window forward and notify.
    Queued { origin: String, connect: bool, method: String },
    /// A request was refused before it reached the user (sign-in for another site).
    Blocked { origin: String, message: String },
    /// The extension popup asked to bring the window forward.
    ShowWindow,
}

#[derive(Serialize, Clone, Debug)]
pub struct SiteOut {
    pub origin: String,
    pub host: String,
    pub local: bool,
    pub chains: Vec<u64>,
    pub active: u64,
    pub connected_at: u64,
    pub address: String,
    pub current_pairing: bool,
}

/// Connection backoff for one registrable domain after the user rejected a connection (or the
/// site withdrew one before the user answered).
#[derive(Clone, Copy, Debug)]
pub struct Backoff {
    pub until: Instant,
    pub next: Duration,
    pub withdrawn: bool,
}

impl Backoff {
    /// The user rejected a connection: blocked for the current penalty, doubled for next time.
    pub fn after_rejection(previous: Option<Backoff>, now: Instant) -> Backoff {
        let penalty = previous.map(|b| b.next).unwrap_or(CONNECT_BACKOFF_START).max(CONNECT_BACKOFF_START);
        Backoff { until: now + penalty, next: (penalty * 2).min(CONNECT_BACKOFF_MAX), withdrawn: false }
    }
    /// The site withdrew its own waiting connection request: the same doubling, from a shorter start.
    pub fn after_withdrawal(previous: Option<Backoff>, now: Instant) -> Backoff {
        let penalty = previous.map(|b| b.next).unwrap_or(CONNECT_WITHDRAWN_BACKOFF_START);
        Backoff { until: now + penalty, next: (penalty * 2).min(CONNECT_BACKOFF_MAX), withdrawn: true }
    }
    /// Time left, if still blocked.
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        (self.until > now).then(|| self.until - now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_backoff_doubles_to_ten_minutes() {
        let t0 = Instant::now();
        let b = Backoff::after_rejection(None, t0);
        assert_eq!(b.remaining(t0), Some(Duration::from_secs(30)));
        assert!(b.remaining(t0 + Duration::from_secs(30)).is_none());
        let mut b = Some(b);
        let mut seen = vec![];
        for _ in 0..7 {
            let n = Backoff::after_rejection(b, t0);
            seen.push(n.until - t0);
            b = Some(n);
        }
        assert_eq!(seen.iter().map(Duration::as_secs).collect::<Vec<_>>(), [60, 120, 240, 480, 600, 600, 600]);
    }
}
