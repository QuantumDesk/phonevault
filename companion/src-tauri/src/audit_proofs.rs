//! Security-audit regression tests (2026-10-13). Each test first demonstrated an issue (it passed
//! while the issue existed); they now assert the fix. Release builds use `panic = "abort"`
//! (Cargo.toml), so any panic on untrusted input kills the whole companion in production; in a
//! test build a panic is caught, and these tests assert there is none.

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
/// `address` is not a 20-byte address. It used to reach `describe` → `short` → `verify::checksum`,
/// which sliced past the end of the text and panicked (panic=abort: the app died whenever the user
/// reviewed a send). Such logs are now ignored, and `checksum`/`short_address` never panic.
#[test]
fn malicious_node_simulation_log_is_ignored() {
    let other = "0x1111111111111111111111111111111111111111";
    let long = format!("0x{}", "a".repeat(80));
    for bad_asset in ["0x1", long.as_str(), "0xzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "0xéééééééééééééééééééé"] {
        let log = json!({"address": bad_asset, "topics": [TRANSFER, topic(ME), topic(other)], "data": format!("0x{:064x}", 5u8)});
        let r = catch_unwind(AssertUnwindSafe(|| crate::sim::changes_from_logs(&[log.clone()], ME, 1, 0)));
        assert_eq!(r.ok().and_then(Result::ok), Some(vec![]), "asset {bad_asset} must be ignored, not panic");
    }
    // a well-formed unknown token log still counts
    let good = json!({"address": "0x2222222222222222222222222222222222222222", "topics": [TRANSFER, topic(ME), topic(other)], "data": format!("0x{:064x}", 5u8)});
    let c = crate::sim::changes_from_logs(&[good], ME, 1, 0).unwrap();
    assert_eq!(c.len(), 1);
    assert_eq!(c[0].delta, "-5");
    // malformed topics (short, non-hex, non-ASCII) are ignored too
    for t in ["0x1234", "0xéééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"] {
        let log = json!({"address": "0x2222222222222222222222222222222222222222", "topics": [TRANSFER, t, topic(other)], "data": format!("0x{:064x}", 5u8)});
        assert!(!panics(|| { let _ = crate::sim::changes_from_logs(&[log.clone()], ME, 1, 0); }), "topic {t}");
    }
    // The same path through the public interpreter of a full eth_simulateV1 answer:
    let resp = json!({"result": [{"calls": [{"status": "0x1", "gasUsed": "0x5208",
        "logs": [{"address": "0x1", "topics": [TRANSFER, topic(ME), topic(other)], "data": format!("0x{:064x}", 5u8)}]}]}]});
    let tx = crate::sim::Tx { from: ME.into(), to: other.into(), value: 0, data: "0x".into(), gas: 21_000, chain: 1, max_fee: 1, priority: 1 };
    let s = crate::sim::interpret_simulate_v1(&resp, &tx, 1, "node", None).unwrap();
    assert_eq!(s.status, "ok");
    assert_eq!(s.changes.len(), 1, "only the fee: {:?}", s.changes);
    assert_eq!(s.changes[0].asset, "native");
    // checksum of anything that is not an address: returned as given, no panic
    for x in ["0x1", long.as_str(), "", "é", "0x", "0xéééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééééé"] {
        assert!(!panics(|| { let _ = crate::verify::checksum(x); let _ = crate::verify::short_address(x); }), "{x:?}");
        assert!(crate::verify::try_checksum(x).is_none());
    }
    assert_eq!(crate::verify::checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
}

/// RLP (verify.rs): an 8-byte list length used to be added to the cursor unchecked (overflow panic
/// in debug; in release `start + len` wrapped, so a nested list could point its end back to its
/// parent's start and the parent's loop never ended). Now every addition is checked and an item
/// that does not move forward inside its list is refused.
#[test]
fn rlp_length_overflow_is_refused() {
    // 0x02 ‖ F8 38 (list of 56 bytes) ‖ FF (list, 8-byte length) ‖ len = 2^64 - 9 ‖ padding
    let mut raw = vec![0x02u8, 0xf8, 56, 0xff];
    raw.extend_from_slice(&(u64::MAX - 8).to_be_bytes());
    raw.resize(3 + 56, 0);
    let hex_tx = format!("0x{}", hex::encode(&raw));
    let r = catch_unwind(|| crate::verify::decode_signed_eip1559(&hex_tx).map(|_| ()).map_err(|e| e.0));
    assert!(matches!(r, Ok(Err(_))), "refused with an error, no panic, no hang");
    // the same with a string (0xBF: 8-byte string length) and with deep nesting
    let mut s = vec![0x02u8, 0xf8, 56, 0xbf];
    s.extend_from_slice(&u64::MAX.to_be_bytes());
    s.resize(3 + 56, 0);
    assert!(crate::verify::decode_signed_eip1559(&format!("0x{}", hex::encode(&s))).is_err());
    // lists nested 2000 deep: refused at a fixed depth instead of recursing as deep as the input
    let mut nested = vec![0xc0u8];
    for _ in 0..2_000 {
        let n = nested.len();
        let mut head = if n < 56 { vec![0xc0 + n as u8] } else {
            let be: Vec<u8> = n.to_be_bytes().iter().copied().skip_while(|b| *b == 0).collect();
            let mut h = vec![0xf7 + be.len() as u8]; h.extend(be); h
        };
        head.extend(nested);
        nested = head;
    }
    let mut tx = vec![0x02u8]; tx.extend(nested);
    let r = catch_unwind(|| crate::verify::decode_signed_eip1559(&format!("0x{}", hex::encode(&tx))).map(|_| ()).map_err(|e| e.0));
    assert_eq!(r.ok(), Some(Err("RLP nested too deeply".to_string())));
}

/// nft.rs `decode_string` (name()/symbol() of every NFT contract found by `nft_scan`, and
/// tokenURI()) used to compute `off + 32` from the contract's return data unchecked. ANY third
/// party could trigger it by sending the user an ERC-721 from such a contract. Now refused.
#[test]
fn hostile_nft_contract_name_is_refused() {
    let mut ret = vec![0u8; 64];
    ret[16..32].copy_from_slice(&((u64::MAX - 15) as u128).to_be_bytes());
    assert_eq!(catch_unwind(|| crate::nft::decode_string(&ret)).ok(), Some(None));
    // the length word overflowing the end, and the largest offsets
    for (off, len) in [(32u128, u64::MAX as u128), (u128::MAX, 1), (usize::MAX as u128 - 31, 0), (usize::MAX as u128, 0)] {
        let mut r = vec![0u8; 96];
        r[16..32].copy_from_slice(&off.to_be_bytes());
        r[48..64].copy_from_slice(&len.to_be_bytes());
        assert_eq!(catch_unwind(|| crate::nft::decode_string(&r)).ok(), Some(None), "off {off} len {len}");
    }
}
