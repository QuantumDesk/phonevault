//! Security-audit proof tests (2026-10-13). Each test DEMONSTRATES an issue: it passes while the
//! issue exists. Release builds use `panic = "abort"` (Cargo.toml), so any panic shown here kills
//! the whole companion in production; in a test build the panic is caught and asserted instead.

use serde_json::json;
use std::panic::{catch_unwind, AssertUnwindSafe};

const ME: &str = "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3";
const TRANSFER: &str = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

fn topic(addr: &str) -> String { format!("0x{:0>64}", addr.trim_start_matches("0x")) }

fn panics(f: impl FnOnce()) -> bool {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let r = catch_unwind(AssertUnwindSafe(f)).is_err();
    std::panic::set_hook(prev);
    r
}

/// A malicious RPC node answers `eth_simulateV1` (sim.rs) with a Transfer log whose emitting
/// `address` is not a 20-byte address. `apply_log` never validates it; `describe` → `short` →
/// `verify::checksum` then slices `&c[..6]` (too short) or indexes the 64-char keccak hex past its
/// end (too long). Both panic → with panic=abort the app dies whenever the user reviews a send.
#[test]
fn proof_malicious_node_simulation_log_panics_the_companion() {
    let other = "0x1111111111111111111111111111111111111111";
    for bad_asset in ["0x1", &format!("0x{}", "a".repeat(80))] {
        let log = json!({"address": bad_asset, "topics": [TRANSFER, topic(ME), topic(other)], "data": format!("0x{:064x}", 5u8)});
        assert!(panics(|| { let _ = crate::sim::changes_from_logs(&[log.clone()], ME, 1, 0); }), "asset {bad_asset} should panic");
    }
    // The same path through the public interpreter of a full eth_simulateV1 answer:
    let resp = json!({"result": [{"calls": [{"status": "0x1", "gasUsed": "0x5208",
        "logs": [{"address": "0x1", "topics": [TRANSFER, topic(ME), topic(other)], "data": format!("0x{:064x}", 5u8)}]}]}]});
    let tx = crate::sim::Tx { from: ME.into(), to: other.into(), value: 0, data: "0x".into(), gas: 21_000, chain: 1, max_fee: 1, priority: 1 };
    assert!(panics(|| { let _ = crate::sim::interpret_simulate_v1(&resp, &tx, 1, "node", None); }));
}

/// RLP (verify.rs:41-61): an 8-byte list length is added to the cursor unchecked. In a test/debug
/// build that is an overflow panic; in release (no overflow checks) `start + len` wraps, so a
/// nested list can point its end BACK to the start of its parent and the parent's decode loop
/// never ends, pushing items until memory runs out. Input: the phone's `signedTransaction`.
#[test]
fn proof_rlp_length_overflow() {
    // 0x02 ‖ F8 38 (list of 56 bytes) ‖ FF (list, 8-byte length) ‖ len = 2^64 - 9 ‖ padding
    let mut raw = vec![0x02u8, 0xf8, 56, 0xff];
    raw.extend_from_slice(&(u64::MAX - 8).to_be_bytes());
    raw.resize(3 + 56, 0);
    let hex_tx = format!("0x{}", hex::encode(&raw));
    assert!(panics(|| { let _ = crate::verify::decode_signed_eip1559(&hex_tx); }), "debug build: overflow panic");
    // Release semantics: the inner list (cursor 3, length bytes 4..12, body at 12) "ends" at 3,
    // the outer list's first item, so the outer loop re-reads the same item forever.
    assert_eq!(12usize.wrapping_add((u64::MAX - 8) as usize), 3);
}

/// nft.rs `decode_string` (used for name()/symbol() of every NFT contract found by `nft_scan`, and
/// tokenURI()) reads an ABI offset from the contract's return data and computes `off + 32`
/// unchecked. ANY third party can make this run: emit an ERC-721 Transfer log to the user from a
/// contract whose name() returns this. Debug: overflow panic. Release: `off + 32` wraps to 16,
/// passes the bound check, and `ret[off..off + 16]` panics (start > end) → abort.
#[test]
fn proof_hostile_nft_contract_name_panics_the_companion() {
    let mut ret = vec![0u8; 64];
    ret[16..32].copy_from_slice(&((u64::MAX - 15) as u128).to_be_bytes());
    assert!(panics(|| { let _ = crate::nft::decode_string(&ret); }));
    // release arithmetic: the bound check passes
    let off = (u64::MAX - 15) as usize;
    assert!(off.wrapping_add(32) <= ret.len());
}
