//! Offline verifier for one captured attestation exchange (tools/dev-device/attesttest.sh).
//! Same code as the companion app: chain to a pinned Google root, KeyDescription, binding
//! signature, revocation list, verdict policy.
//!
//!   cargo run --manifest-path companion/src-tauri/Cargo.toml --example attest_verify -- \
//!       REQUEST.json RESPONSE.json [--dev-mode]
//!
//! Prints the report as JSON. Exit 0 = GENUINE, 10 = DEVELOPMENT, 20 = FAIL, 2 = usage/transient.

use companion_lib::attest::{
    self, chain,
    policy::{Policy, Verdict},
    revocation,
};
use serde_json::Value;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let dev = args.iter().any(|a| a == "--dev-mode");
    let files: Vec<&String> = args.iter().filter(|a| !a.starts_with("--")).collect();
    if files.len() != 2 {
        eprintln!("usage: attest_verify REQUEST.json RESPONSE.json [--dev-mode]");
        std::process::exit(2);
    }
    let read = |p: &str| -> Value {
        serde_json::from_str(&std::fs::read_to_string(p).expect("readable file")).expect("JSON file")
    };
    let request = read(files[0]);
    let response = read(files[1]);
    let challenge =
        hex::decode(request["challenge"].as_str().expect("request has a challenge")).expect("hex challenge");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    match attest::assess(
        &Policy::builtin(),
        &chain::google_roots(),
        now,
        &challenge,
        &request,
        &response,
        revocation::current,
        dev,
    ) {
        Err(e) => {
            eprintln!("transient: {e}");
            std::process::exit(2);
        }
        Ok(report) => {
            println!("{}", serde_json::to_string_pretty(&report).unwrap());
            std::process::exit(match report.verdict() {
                Verdict::Genuine => 0,
                Verdict::Development => 10,
                Verdict::Fail => 20,
            });
        }
    }
}
