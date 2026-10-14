//! Method policy: what to do with one request, and which results the webview may return.

use super::{rpc, Site, BUCKET_CAPACITY, BUCKET_REFILL_PER_SEC, DEFAULT_CHAIN, PROMPT_METHODS, READ_ONLY_METHODS};
use crate::{verify, wc};
use serde_json::{json, Value};
use std::time::Instant;

/// What to do with one request. Pure: decided from the method, params, the site's permission and
/// the paired address. `wc.rs` supplies the method allow-list and parameter rules.
#[derive(Debug, PartialEq)]
pub enum Decision {
    Answer(Value),
    Error(wc::RpcError),
    /// Forward to the user's node for this network.
    Proxy {
        chain: u64,
    },
    /// Show "<site> wants to connect".
    Connect,
    /// Show a request card (sign, send, switch to a network the site doesn't have yet).
    Prompt {
        chain: u64,
    },
    /// Switch to a network the user already approved for this site; no card needed.
    SwitchNow {
        chain: u64,
    },
    /// The site disconnects itself (wallet_revokePermissions).
    Revoke,
}

/// The site's permission, if it is connected under the current pairing.
pub fn connected<'a>(site: Option<&'a Site>, paired: Option<&str>) -> Option<&'a Site> {
    match (site, paired) {
        (Some(s), Some(p)) if s.address.eq_ignore_ascii_case(p) => Some(s),
        _ => None,
    }
}

pub fn decide(method: &str, params: &Value, site: Option<&Site>, paired: Option<&str>) -> Decision {
    let conn = connected(site, paired);
    let chain = conn.map(|s| s.active).unwrap_or(DEFAULT_CHAIN);
    let unauthorized = || {
        Decision::Error(rpc(
            wc::UNAUTHORIZED,
            "Not connected: ask for the account first (eth_requestAccounts) and approve it in Phone Vault.",
        ))
    };
    if !params.is_array() {
        return Decision::Error(rpc(wc::INVALID_PARAMS, "params must be an array"));
    }
    match method {
        "eth_chainId" => Decision::Answer(json!(verify::to_quantity(chain as u128))),
        "net_version" => Decision::Answer(json!(chain.to_string())),
        "eth_accounts" => Decision::Answer(match (conn, paired) {
            (Some(_), Some(p)) => json!([verify::checksum(p)]),
            _ => json!([]),
        }),
        "eth_requestAccounts" => match (conn, paired) {
            (_, None) => Decision::Error(rpc(
                wc::UNAUTHORIZED,
                "Phone Vault is not paired with a phone yet. Pair it in the Phone Vault Companion app first.",
            )),
            (Some(_), Some(p)) => Decision::Answer(json!([verify::checksum(p)])),
            (None, Some(_)) => Decision::Connect,
        },
        "wallet_getPermissions" => Decision::Answer(if conn.is_some() {
            json!([{"parentCapability": "eth_accounts", "caveats": []}])
        } else {
            json!([])
        }),
        "wallet_revokePermissions" => {
            if site.is_some() {
                Decision::Revoke
            } else {
                Decision::Answer(Value::Null)
            }
        }
        m if READ_ONLY_METHODS.contains(&m) => {
            if conn.is_some() {
                Decision::Proxy { chain }
            } else {
                unauthorized()
            }
        }
        m if PROMPT_METHODS.contains(&m) => {
            let (Some(s), Some(p)) = (conn, paired) else { return unauthorized() };
            if m == "eth_sendTransaction" {
                return match wc::normalize_tx(params, p, chain) {
                    Ok(_) => Decision::Prompt { chain },
                    Err(e) => Decision::Error(e),
                };
            }
            match wc::route(m, params, chain, &s.chains, p) {
                Ok(wc::Prepared::SwitchChain { chain_id, in_session, .. }) => {
                    if chain_id == s.active {
                        Decision::Answer(Value::Null)
                    } else if in_session {
                        Decision::SwitchNow { chain: chain_id }
                    } else {
                        Decision::Prompt { chain }
                    }
                }
                Ok(_) => Decision::Prompt { chain },
                Err(e) => Decision::Error(e),
            }
        }
        // eth_sign, eth_signTransaction, wallet_addEthereumChain and everything unknown: wc.rs's refusals.
        m => match wc::route(m, params, chain, &[], "0x0000000000000000000000000000000000000000") {
            Err(e) => Decision::Error(e),
            Ok(_) => Decision::Error(rpc(wc::UNSUPPORTED_METHOD, format!("{m} is not supported by Phone Vault"))),
        },
    }
}

/// Token bucket. Returns false when the site is over its rate.
pub(super) fn take_token(bucket: &mut (f64, Instant), now: Instant) -> bool {
    let elapsed = now.saturating_duration_since(bucket.1).as_secs_f64();
    bucket.0 = (bucket.0 + elapsed * BUCKET_REFILL_PER_SEC).min(BUCKET_CAPACITY);
    bucket.1 = now;
    if bucket.0 >= 1.0 {
        bucket.0 -= 1.0;
        true
    } else {
        false
    }
}

/// What the webview may send back for a request: only result shapes the verified pipeline
/// produces (a 32-byte transaction hash, a 65-byte signature, null for a network switch).
pub fn check_result(method: &str, result: &Value) -> Result<(), String> {
    let hex_of = |v: &Value, bytes: usize| {
        v.as_str().is_some_and(|s| {
            s.len() == 2 + 2 * bytes && s.starts_with("0x") && s[2..].bytes().all(|b| b.is_ascii_hexdigit())
        })
    };
    let ok = match method {
        "eth_sendTransaction" => hex_of(result, 32),
        "personal_sign" | "eth_signTypedData_v4" => hex_of(result, 65),
        "wallet_switchEthereumChain" => result.is_null(),
        _ => false,
    };
    if ok {
        Ok(())
    } else {
        Err(format!("refusing to send an unexpected result for {method}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bridge::tests::{site, ME, OTHER};
    use std::time::Duration;

    #[test]
    fn unconnected_sites_learn_nothing_and_can_only_ask_to_connect() {
        let p = Some(ME);
        assert_eq!(decide("eth_chainId", &json!([]), None, p), Decision::Answer(json!("0x2105")));
        assert_eq!(decide("net_version", &json!([]), None, p), Decision::Answer(json!("8453")));
        assert_eq!(decide("eth_accounts", &json!([]), None, p), Decision::Answer(json!([])));
        assert_eq!(decide("wallet_getPermissions", &json!([]), None, p), Decision::Answer(json!([])));
        assert_eq!(decide("eth_requestAccounts", &json!([]), None, p), Decision::Connect);
        for m in [
            "eth_sendTransaction",
            "personal_sign",
            "eth_signTypedData_v4",
            "wallet_switchEthereumChain",
            "eth_call",
            "eth_getBalance",
            "eth_blockNumber",
        ] {
            assert!(matches!(decide(m, &json!([]), None, p), Decision::Error(e) if e.code == wc::UNAUTHORIZED), "{m}");
        }
        // not paired at all
        assert!(
            matches!(decide("eth_requestAccounts", &json!([]), None, None), Decision::Error(e) if e.code == wc::UNAUTHORIZED)
        );
        // a site connected under another pairing is not connected
        let s = site(&[8453], 8453);
        assert_eq!(decide("eth_accounts", &json!([]), Some(&s), Some(OTHER)), Decision::Answer(json!([])));
        assert_eq!(decide("eth_requestAccounts", &json!([]), Some(&s), Some(OTHER)), Decision::Connect);
        assert!(
            matches!(decide("personal_sign", &json!(["hi", OTHER]), Some(&s), Some(OTHER)), Decision::Error(e) if e.code == wc::UNAUTHORIZED)
        );
    }

    #[test]
    fn connected_sites_follow_the_walletconnect_rules() {
        let s = site(&[8453, 1], 1);
        let p = Some(ME);
        let d = |m: &str, params: Value| decide(m, &params, Some(&s), p);
        assert_eq!(d("eth_chainId", json!([])), Decision::Answer(json!("0x1")));
        assert_eq!(d("eth_accounts", json!([])), Decision::Answer(json!([verify::checksum(ME)])));
        assert_eq!(d("eth_requestAccounts", json!([])), Decision::Answer(json!([verify::checksum(ME)])));
        assert_eq!(d("eth_getBalance", json!([ME, "latest"])), Decision::Proxy { chain: 1 });
        assert_eq!(d("eth_call", json!([{"to": OTHER, "data": "0x"}, "latest"])), Decision::Proxy { chain: 1 });
        assert_eq!(d("personal_sign", json!(["0x48656c6c6f", ME])), Decision::Prompt { chain: 1 });
        assert_eq!(
            d("eth_sendTransaction", json!([{"from": ME, "to": OTHER, "value": "0x1"}])),
            Decision::Prompt { chain: 1 }
        );
        // parameter checks happen before anything is queued
        assert!(
            matches!(d("eth_sendTransaction", json!([{"from": OTHER, "to": OTHER}])), Decision::Error(e) if e.code == wc::UNAUTHORIZED)
        );
        assert!(
            matches!(d("eth_sendTransaction", json!([{"to": OTHER, "chainId": "0x2105"}])), Decision::Error(e) if e.code == wc::INVALID_PARAMS)
        );
        assert!(matches!(d("personal_sign", json!(["hi", OTHER])), Decision::Error(e) if e.code == wc::UNAUTHORIZED));
        assert!(matches!(d("eth_signTypedData_v4", json!([ME, "{\"types\":{}}"])), Decision::Error(_)));
        // refused outright, as for WalletConnect
        for m in [
            "eth_sign",
            "eth_signTransaction",
            "wallet_addEthereumChain",
            "eth_getEncryptionPublicKey",
            "wallet_sendCalls",
            "wallet_requestPermissions",
            "eth_subscribe",
            "debug_traceTransaction",
        ] {
            assert!(matches!(d(m, json!([])), Decision::Error(e) if e.code == wc::UNSUPPORTED_METHOD), "{m}");
        }
        // network switching: same → no-op, approved → immediate, new allowed → card, unknown → 4902
        assert_eq!(d("wallet_switchEthereumChain", json!([{"chainId": "0x1"}])), Decision::Answer(Value::Null));
        assert_eq!(
            d("wallet_switchEthereumChain", json!([{"chainId": "0x2105"}])),
            Decision::SwitchNow { chain: 8453 }
        );
        assert_eq!(d("wallet_switchEthereumChain", json!([{"chainId": "0xa"}])), Decision::Prompt { chain: 1 });
        assert!(
            matches!(d("wallet_switchEthereumChain", json!([{"chainId": "0x38"}])), Decision::Error(e) if e.code == wc::UNRECOGNIZED_CHAIN)
        );
        assert_eq!(d("wallet_revokePermissions", json!([{"eth_accounts": {}}])), Decision::Revoke);
        // params must be an array
        assert!(matches!(d("eth_chainId", json!({})), Decision::Error(e) if e.code == wc::INVALID_PARAMS));
    }

    #[test]
    fn rate_limit_bucket() {
        let t0 = Instant::now();
        let mut b = (BUCKET_CAPACITY, t0);
        let allowed = (0..100).filter(|_| take_token(&mut b, t0)).count();
        assert_eq!(allowed, BUCKET_CAPACITY as usize);
        assert!(!take_token(&mut b, t0));
        assert!(take_token(&mut b, t0 + Duration::from_millis(100)), "refills at 20/s");
    }

    #[test]
    fn results_the_webview_may_return() {
        assert!(check_result("eth_sendTransaction", &json!(format!("0x{}", "ab".repeat(32)))).is_ok());
        assert!(check_result("eth_sendTransaction", &json!(format!("0x{}", "ab".repeat(65)))).is_err());
        assert!(check_result("personal_sign", &json!(format!("0x{}", "0f".repeat(65)))).is_ok());
        assert!(check_result("personal_sign", &json!("0xdeadbeef")).is_err());
        assert!(check_result("eth_signTypedData_v4", &json!(null)).is_err());
        assert!(check_result("wallet_switchEthereumChain", &json!(null)).is_ok());
        assert!(check_result("eth_accounts", &json!([ME])).is_err(), "accounts never come from the webview");
    }
}
