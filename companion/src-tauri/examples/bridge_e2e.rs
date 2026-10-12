//! Test harness for extension/test/e2e.mjs: the REAL bridge (src/bridge.rs) on a temporary socket,
//! with a scripted stand-in for the person at the Mac. It never signs anything and never talks to
//! a phone: connection requests are approved (Base + Ethereum) with a fixed test address, every
//! signing request is REJECTED (4001), and a switch to a new network is approved.
//!
//! The same binary is also the native messaging host (Chrome starts it with the extension origin as
//! the first argument), so the bridge's socket peer check (same executable) holds in the test too.
//!
//!   cargo build --example bridge_e2e
//!   PHONEVAULT_BRIDGE_SOCKET=/tmp/x.sock target/debug/examples/bridge_e2e serve
//!
//! One JSON line per decision on stdout, for the test to assert on.

use companion_lib::bridge::{self, Bridge, PendingKind};
use serde_json::json;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const TEST_ADDRESS: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if let Some(caller) = bridge::native_host_caller(&args) {
        std::process::exit(bridge::native_host_main(caller));
    }
    let socket = bridge::socket_path().expect("PHONEVAULT_BRIDGE_SOCKET");
    let wake = Arc::new((Mutex::new(false), Condvar::new()));
    let w = wake.clone();
    let b: Arc<Bridge> = Bridge::new(None, Box::new(|| Some(TEST_ADDRESS.to_string())), Box::new(move || {
        let (m, c) = &*w;
        *m.lock().unwrap() = true;
        c.notify_all();
    }));
    b.serve(&socket).expect("serve");
    println!("{}", json!({"ready": socket.display().to_string()}));
    loop {
        {
            let (m, c) = &*wake;
            let mut flag = m.lock().unwrap();
            if !*flag { flag = c.wait_timeout(flag, Duration::from_millis(200)).unwrap().0; }
            *flag = false;
        }
        for p in b.pending() {
            let line = json!({"pending": {"kind": p.kind, "origin": p.origin, "method": p.method, "chain": p.chain_id}});
            println!("{line}");
            match (p.kind, p.method.as_str()) {
                (PendingKind::Connect, _) => b.approve_connect(p.id, &[8453, 1]).expect("approve"),
                (_, "wallet_switchEthereumChain") => {
                    let target = p.params[0]["chainId"].as_str().and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok()).unwrap_or(0);
                    let mut chains = b.sites().into_iter().find(|s| s.origin == p.origin).map(|s| s.chains).unwrap_or_default();
                    chains.push(target);
                    b.update_site(&p.origin, Some(chains), Some(target)).expect("switch");
                    b.respond(p.id, None, None).expect("answer");
                }
                _ => b.reject(p.id, 4001, "Rejected by the test harness.").expect("reject"),
            }
        }
    }
}
