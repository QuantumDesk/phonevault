//! Message signing commands: `personal_sign` and `eth_signTypedData_v4`. The phone reviews and
//! approves; this side pre-checks the request with the same strict rules as the phone, then
//! recomputes the digest from the original request and only hands back a signature that recovers
//! to the pinned signer over that digest (verify::validate_message_signature).
//!
//! USB contract for the site that asked (`origin`): the `personal_sign` and `eth_signTypedData_v4`
//! requests (only these; `signEip1559` refuses the field) carry an OPTIONAL string field `"origin"`
//! when a dApp asked for the signature, in bridge::normalize_origin's form, which is what the phone
//! accepts: `https://<lowercase ASCII labels>[:port]` (internationalized names in punycode) or
//! `http://localhost|127.0.0.1|[::1][:port]`, port 1-65535 without leading zeros, no path, trailing
//! slash, userinfo or query, at most 255 characters. An origin that cannot be written so is left
//! out (the phone would refuse the whole request). It is the browser-reported origin (extension)
//! or WalletConnect Verify's origin when Verify said VALID; it is absent for an unverified
//! WalletConnect request and for anything the user started on this Mac. It is not signed; the
//! phone shows it and compares it with a sign-in message's domain.

use crate::{ask_phone, blocking, message, pairing, verify, CmdResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Serialize)]
pub struct SignedMessage {
    signature: String,
    digest: String,
    signer: String,
}

fn chain_quantity(chain_id: u64) -> CmdResult<String> {
    if !matches!(chain_id, 1 | 11155111 | 8453 | 10 | 42161 | 137) {
        return Err(format!("the phone has no reviewed profile for chain {chain_id}"));
    }
    Ok(verify::to_quantity(chain_id as u128))
}

fn request_signature(request: Value) -> CmdResult<SignedMessage> {
    let pinned = pairing::load()?.ok_or("not paired yet")?;
    // Hold the phone from the device check through the signature (queued behind any other request).
    let _turn = crate::aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    crate::attest::require_ok(&pinned)?;
    // Refuse locally what the phone would refuse, before bothering the user on the phone.
    verify::expected_message_digest(&request)?;
    // Pinned to the account active NOW: the phone refuses it if another account is active there.
    let request = crate::pinned_request(request, &pinned);
    let response = ask_phone(request.clone(), Duration::from_secs(300))?;
    let v = verify::validate_message_signature(&request, &response, &pinned)?;
    Ok(SignedMessage { signature: v.signature, digest: v.digest, signer: verify::checksum(&v.signer) })
}

/// The request field for the site that asked, if any: normalized, or refused when malformed.
/// The phone accepts exactly `https://<lowercase labels>[:port]` or `http://localhost|127.0.0.1|[::1]
/// [:port]`, port 1-65535, at most 255 characters, and refuses the whole request otherwise; an
/// origin that cannot be written that way is left out (the request then has no site, as for one
/// started on this Mac).
pub(crate) const MAX_ORIGIN_CHARS: usize = 255;

fn origin_field(origin: Option<&str>) -> Option<String> {
    origin
        .filter(|o| !o.is_empty())
        .and_then(|o| crate::bridge::normalize_origin(o).ok())
        .filter(|o| o.len() <= MAX_ORIGIN_CHARS)
}

/// Add `"origin"` to a USB message request when there is a site origin.
pub(crate) fn with_origin(mut request: Value, origin: Option<&str>) -> Value {
    if let (Some(o), Some(obj)) = (origin, request.as_object_mut()) {
        obj.insert("origin".into(), Value::from(o));
    }
    request
}

/// The personal_sign USB request; refuses a sign-in (EIP-4361) message for another site than
/// `origin` (the same rule wc_prepare applies, checked again here before the phone sees it).
pub(crate) fn personal_sign_request(id: &str, bytes: &[u8], chain_id: u64, origin: Option<&str>) -> CmdResult<Value> {
    let origin = origin_field(origin);
    if let (Ok(text), Some(o)) = (std::str::from_utf8(bytes), origin.as_deref()) {
        if let crate::siwe::Check::Mismatch { domain, site } = crate::siwe::check(text, Some(o)) {
            return Err(crate::siwe::blocked_message(&site, &domain));
        }
    }
    Ok(with_origin(
        json!({
            "id": id, "method": "personal_sign",
            "chainId": chain_quantity(chain_id)?, "message": format!("0x{}", hex::encode(bytes)),
        }),
        origin.as_deref(),
    ))
}

pub(crate) fn typed_data_request(id: &str, typed_data: &str, chain_id: u64, origin: Option<&str>) -> CmdResult<Value> {
    let origin = origin_field(origin);
    Ok(with_origin(
        json!({
            "id": id, "method": "eth_signTypedData_v4",
            "chainId": chain_quantity(chain_id)?, "typedData": typed_data,
        }),
        origin.as_deref(),
    ))
}

/// `message` is UTF-8 text, or 0x-prefixed hex bytes when `is_hex` is set. `origin`: the site that
/// asked, when known (see the module comment); None for a message the user started here.
#[tauri::command]
pub async fn sign_message(
    message: String,
    is_hex: bool,
    chain_id: u64,
    origin: Option<String>,
) -> CmdResult<SignedMessage> {
    blocking(move || {
        let bytes = if is_hex {
            let body = message.trim().strip_prefix("0x").ok_or("hex message must start with 0x")?.to_string();
            hex::decode(&body).map_err(|_| "hex message must be an even number of hex digits".to_string())?
        } else {
            message.into_bytes()
        };
        if bytes.is_empty() {
            return Err("the message is empty".into());
        }
        if bytes.len() > message::MAX_MESSAGE_BYTES {
            return Err(format!("the message exceeds {} bytes", message::MAX_MESSAGE_BYTES));
        }
        request_signature(personal_sign_request(
            &uuid::Uuid::new_v4().to_string(),
            &bytes,
            chain_id,
            origin.as_deref(),
        )?)
    })
    .await
}

/// `typed_data` is the eth_signTypedData_v4 JSON text, sent to the phone exactly as given.
#[tauri::command]
pub async fn sign_typed_data(typed_data: String, chain_id: u64, origin: Option<String>) -> CmdResult<SignedMessage> {
    blocking(move || {
        request_signature(typed_data_request(
            &uuid::Uuid::new_v4().to_string(),
            &typed_data,
            chain_id,
            origin.as_deref(),
        )?)
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIWE: &str = "app.uniswap.org wants you to sign in with your Ethereum account:\n0x7a3B9c1D2E4F5061728394a5B6c7D8e9F0A1B2c3\n\nURI: https://app.uniswap.org\nVersion: 1\nChain ID: 1\nNonce: 32891756\nIssued At: 2021-09-30T16:25:24Z";

    #[test]
    fn requests_carry_the_normalized_origin_only_when_there_is_one() {
        let r = personal_sign_request("m-1", b"hello", 1, Some("HTTPS://App.Uniswap.org")).unwrap();
        assert_eq!(
            r,
            json!({"id": "m-1", "method": "personal_sign", "chainId": "0x1", "message": "0x68656c6c6f", "origin": "https://app.uniswap.org"})
        );
        let r = personal_sign_request("m-1", b"hello", 1, None).unwrap();
        assert!(r.get("origin").is_none());
        assert_eq!(r.as_object().unwrap().len(), 4, "unchanged wire format without a site");
        assert!(personal_sign_request("m-1", b"hello", 1, Some("")).unwrap().get("origin").is_none());
        let r = typed_data_request("t-1", "{}", 8453, Some("http://localhost:5173")).unwrap();
        assert_eq!(
            r,
            json!({"id": "t-1", "method": "eth_signTypedData_v4", "chainId": "0x2105", "typedData": "{}", "origin": "http://localhost:5173"})
        );
        assert!(typed_data_request("t-1", "{}", 8453, None).unwrap().get("origin").is_none());
        // anything the phone's grammar would refuse is left out, never sent
        let long = format!("https://{}.example.org:65535", ["a", "b", "c", "d"].map(|c| c.repeat(58)).join("."));
        assert!(crate::bridge::normalize_origin(&long).is_ok() && long.len() > MAX_ORIGIN_CHARS);
        for bad in [
            "https://app.uniswap.org/path",
            "https://app.uniswap.org/",
            "http://evil.org",
            "javascript:alert(1)",
            "https://ápp.org",
            "https://user@app.uniswap.org",
            "https://a.org:0",
            "https://a.org:65536",
            "https://a.org?x",
            &long,
        ] {
            assert!(personal_sign_request("m-1", b"hello", 1, Some(bad)).unwrap().get("origin").is_none(), "{bad}");
            assert!(typed_data_request("t-1", "{}", 1, Some(bad)).unwrap().get("origin").is_none(), "{bad}");
        }
        // what is sent always matches the phone's pattern
        let phone_ok = |o: &str| {
            let (scheme, rest) = o.split_once("://").unwrap();
            let (host, port) = match rest.rfind(':').filter(|_| !rest.ends_with(']')) {
                Some(i) if !rest.starts_with('[') || rest[..i].ends_with(']') => (&rest[..i], Some(&rest[i + 1..])),
                _ => (rest, None),
            };
            let port_ok = port.is_none_or(|p| {
                !p.is_empty()
                    && p.len() <= 5
                    && !p.starts_with('0')
                    && p.bytes().all(|b| b.is_ascii_digit())
                    && p.parse::<u32>().unwrap() <= 65535
            });
            let host_ok = match scheme {
                "https" => host.split('.').all(|l| {
                    !l.is_empty() && l.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                }),
                "http" => matches!(host, "localhost" | "127.0.0.1" | "[::1]"),
                _ => false,
            };
            o.len() <= 255 && port_ok && host_ok
        };
        for o in [
            "HTTPS://App.Uniswap.org",
            "https://xn--uniswp-9za.org:8443",
            "http://[::1]:3000",
            "http://127.0.0.1",
            "http://localhost:5173",
        ] {
            let r = personal_sign_request("m-1", b"hello", 1, Some(o)).unwrap();
            let sent = r["origin"].as_str().unwrap();
            assert!(phone_ok(sent), "{sent}");
        }
        // the pinned account is added after this, as for every request
        let pinned = crate::pinned_request(
            personal_sign_request("m-1", b"hi", 1, Some("https://a.org")).unwrap(),
            "0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3",
        );
        assert_eq!(pinned.as_object().unwrap().len(), 6);
    }

    #[test]
    fn a_sign_in_for_another_site_never_reaches_the_phone() {
        assert!(personal_sign_request("m", SIWE.as_bytes(), 1, Some("https://app.uniswap.org")).is_ok());
        let e = personal_sign_request("m", SIWE.as_bytes(), 1, Some("https://evil.example")).unwrap_err();
        assert!(e.starts_with("Blocked: evil.example asked you to sign in to app.uniswap.org"), "{e}");
        // no site (started on this Mac, or unverified WalletConnect): the phone's review warns instead
        assert!(personal_sign_request("m", SIWE.as_bytes(), 1, None).is_ok());
    }
}
