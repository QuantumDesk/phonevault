//! Security-audit regressions (2026-10-13), against the real bridge over its socket.
//!
//! 1. An UNCONNECTED site could bring the companion window to the front (set_focus) and post a
//!    desktop notification as often as it liked: the connection backoff started only when the user
//!    REJECTED a card, a page that withdrew its own request first (the extension sends
//!    {"type":"cancel"} when the tab navigates or reloads) was never backed off, and
//!    `Alert::Queued` (→ lib on_queued → tray::show_main + notification) was not throttled. Now a
//!    withdrawn connect counts towards the backoff (from 10 s) and Alert::Queued is rate-limited
//!    per registrable domain.
//! 2. A failed node request was answered to the SITE with reqwest's error text, which includes the
//!    full node URL (and so the user's provider API key). Now a fixed message.

use companion_lib::bridge::{self, Alert, Bridge, CHROME_EXTENSION_ID, MAX_IN_FRAME};
use serde_json::{json, Value};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";

fn wait_for(mut f: impl FnMut() -> bool) { for _ in 0..300 { if f() { return; } std::thread::sleep(Duration::from_millis(10)); } panic!("timed out"); }

#[test]
fn unconnected_site_reload_loop_cannot_pop_the_window_repeatedly() {
    let d = std::env::temp_dir().join(format!("pva{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("a.sock");
    let log: Arc<Mutex<Vec<Alert>>> = Arc::new(Mutex::new(vec![]));
    let l = log.clone();
    let b = Bridge::with_alerts(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}), Box::new(move |a| l.lock().unwrap().push(a)));
    b.serve(&sock).unwrap();
    let mut s = UnixStream::connect(&sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    let send = |s: &mut UnixStream, v: Value| bridge::write_frame(s, v.to_string().as_bytes(), MAX_IN_FRAME).unwrap();
    let recv = |s: &mut UnixStream| -> Value { serde_json::from_slice(&bridge::read_frame(s, bridge::MAX_OUT_FRAME).unwrap().unwrap()).unwrap() };
    send(&mut s, json!({"type": "relay_hello", "caller": format!("chrome-extension://{CHROME_EXTENSION_ID}/")}));

    let origin = "https://wallet-security-alert.example";
    let rounds = 25u64;
    let (mut queued_rounds, mut refused) = (0, 0);
    for i in 0..rounds {
        // the page asks to connect (from a rotating subdomain of the same site, to be thorough)
        let o = if i % 2 == 0 { origin.to_string() } else { format!("https://s{i}.wallet-security-alert.example") };
        send(&mut s, json!({"type": "request", "id": i, "origin": o, "method": "eth_requestAccounts", "params": []}));
        let v = loop { let v = recv(&mut s); if v["id"] == i && (v["type"] == "queued" || v["type"] == "response") { break v; } };
        if v["type"] == "queued" {
            queued_rounds += 1;
            wait_for(|| b.pending().len() == 1);
            // the page reloads before the user can answer: the extension withdraws the request
            send(&mut s, json!({"type": "cancel", "id": i}));
            wait_for(|| b.pending().is_empty());
        } else {
            assert_eq!(v["error"]["code"], 4001, "{v}");
            assert!(v["error"]["message"].as_str().unwrap().contains("withdrawn"), "{v}");
            refused += 1;
        }
    }
    let queued = log.lock().unwrap().iter().filter(|a| matches!(a, Alert::Queued { connect: true, .. })).count();
    assert_eq!(queued, 1, "only the first round brought the window forward and notified");
    assert_eq!((queued_rounds, refused), (1, rounds - 1), "after a withdrawal the site family is backed off");
    let _ = std::fs::remove_dir_all(d);
}

#[test]
fn node_url_with_api_key_does_not_leak_to_the_site() {
    let d = std::env::temp_dir().join(format!("pvn{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    let sock = d.join("n.sock");
    let b = Bridge::new(None, Box::new(|| Some(ME.to_string())), Box::new(|| {}));
    b.serve(&sock).unwrap();
    // a node URL with a secret in it that refuses connections (stands in for any failure)
    let secret = "v3/SECRET-API-KEY-1234";
    b.set_nodes([(8453u64, format!("https://127.0.0.1:9/{secret}"))].into_iter().collect()).unwrap();
    let mut s = UnixStream::connect(&sock).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
    let send = |s: &mut UnixStream, v: Value| bridge::write_frame(s, v.to_string().as_bytes(), MAX_IN_FRAME).unwrap();
    let recv = |s: &mut UnixStream| -> Value { serde_json::from_slice(&bridge::read_frame(s, bridge::MAX_OUT_FRAME).unwrap().unwrap()).unwrap() };
    send(&mut s, json!({"type": "relay_hello", "caller": format!("chrome-extension://{CHROME_EXTENSION_ID}/")}));
    let origin = "https://some-dapp.example";
    send(&mut s, json!({"type": "request", "id": 1, "origin": origin, "method": "eth_requestAccounts", "params": []}));
    wait_for(|| b.pending().len() == 1);
    b.approve_connect(b.pending()[0].id, &[8453]).unwrap();
    send(&mut s, json!({"type": "request", "id": 2, "origin": origin, "method": "eth_blockNumber", "params": []}));
    let answer = loop { let v = recv(&mut s); if v["type"] == "response" && v["id"] == 2 { break v; } };
    let msg = answer["error"]["message"].as_str().unwrap_or_default().to_string();
    assert!(msg.starts_with("node unreachable"), "the site is told the node failed: {msg}");
    assert!(!msg.contains("SECRET") && !msg.contains("127.0.0.1") && !msg.contains("https://"), "no part of the node URL reaches the site: {msg}");
    let _ = std::fs::remove_dir_all(d);
}
