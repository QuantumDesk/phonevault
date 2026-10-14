//! Revert reasons in words, and how a node's error is classified.

use super::{strip, word, word_usize, U256};
use serde_json::Value;

pub(super) fn printable(s: &str, max: usize) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect::<String>().trim().to_string();
    if t.chars().count() > max {
        format!("{}…", t.chars().take(max).collect::<String>())
    } else {
        t
    }
}

/// The revert reason in words, from the node's error message and the revert data.
#[deny(clippy::indexing_slicing)]
pub fn revert_reason(message: Option<&str>, data: Option<&str>) -> String {
    let bytes = data.and_then(|d| hex::decode(strip(d)).ok()).unwrap_or_default();
    if bytes.len() >= 4 {
        let (sel, body) = bytes.split_at(4);
        if sel == [0x08, 0xc3, 0x79, 0xa0] {
            // Error(string)
            if let Some(off) = word_usize(body, 0) {
                let start = off.checked_add(32);
                if let Some(len) = start
                    .and_then(|s| body.get(off..s))
                    .and_then(U256::from_be)
                    .and_then(U256::to_u128)
                    .and_then(|l| usize::try_from(l).ok())
                {
                    let text = start
                        .and_then(|s| Some((s, s.checked_add(len)?)))
                        .and_then(|(s, e)| body.get(s..e))
                        .and_then(|b| std::str::from_utf8(b).ok());
                    if let Some(text) = text {
                        let t = printable(text, 160);
                        return if t.is_empty() { "reverted with an empty reason".into() } else { t };
                    }
                }
            }
        } else if sel == [0x4e, 0x48, 0x7b, 0x71] {
            // Panic(uint256)
            let code = word(body, 0).and_then(U256::to_u128).unwrap_or(u128::MAX);
            let what = match code {
                0x01 => "assertion failed",
                0x11 => "arithmetic overflow or underflow",
                0x12 => "division by zero",
                0x21 => "invalid enum value",
                0x31 => "pop from an empty array",
                0x32 => "array index out of bounds",
                0x41 => "out of memory",
                0x51 => "call to an uninitialised function",
                _ => "panic",
            };
            return format!("{what} (panic 0x{code:x})");
        } else {
            return format!("custom error 0x{}", hex::encode(sel));
        }
    }
    let m = message.unwrap_or("").trim();
    let m = m
        .strip_prefix("execution reverted:")
        .or_else(|| m.strip_prefix("execution reverted"))
        .map(str::trim)
        .unwrap_or(m);
    if m.is_empty() {
        "reverted without a reason".into()
    } else {
        printable(m, 160)
    }
}

pub(super) fn is_revert(error: &Value) -> bool {
    let code = error.get("code").and_then(Value::as_i64);
    let msg = error.get("message").and_then(Value::as_str).unwrap_or("").to_ascii_lowercase();
    code == Some(3)
        || code == Some(-32015)
        || msg.contains("revert")
        || msg.contains("out of gas")
        || msg.contains("invalid opcode")
}

pub(super) fn is_insufficient_funds(error: &Value) -> bool {
    error.get("message").and_then(Value::as_str).is_some_and(|m| m.to_ascii_lowercase().contains("insufficient funds"))
        || error.get("code").and_then(Value::as_i64) == Some(-38014)
}

pub(super) fn error_text(error: &Value) -> String {
    printable(error.get("message").and_then(Value::as_str).unwrap_or("unknown error"), 160)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revert_reasons_are_decoded() {
        assert_eq!(revert_reason(Some("execution reverted: Too little received"), None), "Too little received");
        assert_eq!(revert_reason(Some("execution reverted"), None), "reverted without a reason");
        assert_eq!(
            revert_reason(None, Some("0x4e487b710000000000000000000000000000000000000000000000000000000000000011")),
            "arithmetic overflow or underflow (panic 0x11)"
        );
        assert_eq!(revert_reason(Some("execution reverted"), Some("0x5bf6f916")), "custom error 0x5bf6f916"); // TransactionDeadlinePassed()
                                                                                                              // control characters and length are tamed
        let long = format!("execution reverted: {}\u{7}", "x".repeat(300));
        let r = revert_reason(Some(&long), None);
        assert!(r.chars().count() <= 161 && !r.contains('\u{7}'));
    }
}
