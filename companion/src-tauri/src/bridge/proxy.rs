//! Read-only node calls forwarded to the user's node for the site's network.

use super::{LIMITED, MAX_OUT_FRAME};
use crate::{eth, wc};
use serde_json::{json, Value};
use std::io::Read;
use std::time::Duration;

/// Forward one read-only call to the user's node. The node must answer for the site's network
/// (checked once per URL). Returns (result, chain the node was verified for) or a JSON-RPC error
/// object (with the node's revert `data` when small, so dApps can decode it).
pub(super) fn proxy_call(
    url: &str,
    chain: u64,
    known_chain: Option<u64>,
    method: &str,
    params: &Value,
) -> Result<(Value, Option<u64>), Value> {
    let fail = |m: String| json!({"code": wc::INTERNAL, "message": m});
    let client = crate::http::client(Duration::from_secs(20), crate::http::Policy::none()).map_err(fail)?;
    let post = |method: &str, params: &Value| -> Result<Value, Value> {
        let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params});
        // never the reqwest error text: it contains the node URL, often with the user's API key
        let resp = client.post(url).json(&body).send().map_err(|e| fail(eth::transport_error(&e)))?;
        let mut bytes = vec![];
        resp.take(MAX_OUT_FRAME as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| fail(format!("the node's answer could not be read ({:?})", e.kind())))?;
        if bytes.len() > MAX_OUT_FRAME - 1024 {
            return Err(json!({"code": LIMITED, "message": "The node's answer is too large to pass to the browser."}));
        }
        let v: Value = serde_json::from_slice(&bytes).map_err(|_| fail("node returned non-JSON".into()))?;
        sanitize_node_reply(&v)
    };
    let verified = match known_chain {
        Some(c) => c,
        None => {
            let c = post("eth_chainId", &json!([]))?;
            let id = c
                .as_str()
                .and_then(|s| s.strip_prefix("0x"))
                .and_then(|h| u64::from_str_radix(h, 16).ok())
                .ok_or_else(|| fail("node gave a bad chain id".into()))?;
            id
        }
    };
    if verified != chain {
        return Err(fail(format!(
            "the node set for {} answers for chain {verified}; check it in Phone Vault Settings",
            wc::chain_name(chain)
        )));
    }
    Ok((post(method, params)?, Some(verified)))
}

/// Keep only `result`, or `error.{code,message,data}` with bounded sizes.
pub fn sanitize_node_reply(v: &Value) -> Result<Value, Value> {
    if let Some(e) = v.get("error") {
        let code =
            e.get("code").and_then(Value::as_i64).filter(|c| (-32768..=4999).contains(c)).unwrap_or(wc::INTERNAL);
        let message: String =
            e.get("message").and_then(Value::as_str).unwrap_or("node error").chars().take(500).collect();
        let mut out = json!({"code": code, "message": message});
        if let Some(d) = e.get("data").and_then(Value::as_str).filter(|d| d.len() <= 16 * 1024) {
            out["data"] = json!(d);
        }
        return Err(out);
    }
    v.get("result").cloned().ok_or_else(|| json!({"code": wc::INTERNAL, "message": "node returned no result"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_replies_are_trimmed() {
        assert_eq!(
            sanitize_node_reply(&json!({"jsonrpc": "2.0", "id": 1, "result": "0x10", "extra": 1})).unwrap(),
            json!("0x10")
        );
        let e =
            sanitize_node_reply(&json!({"error": {"code": 3, "message": "execution reverted", "data": "0x08c379a0"}}))
                .unwrap_err();
        assert_eq!(e, json!({"code": 3, "message": "execution reverted", "data": "0x08c379a0"}));
        let e =
            sanitize_node_reply(&json!({"error": {"code": 99999, "message": "x".repeat(2000), "data": {"obj": 1}}}))
                .unwrap_err();
        assert_eq!(e["code"], wc::INTERNAL);
        assert_eq!(e["message"].as_str().unwrap().len(), 500);
        assert!(e.get("data").is_none());
        assert!(sanitize_node_reply(&json!({})).is_err());
    }
}
