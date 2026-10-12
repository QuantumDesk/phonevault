//! Message signing commands: `personal_sign` and `eth_signTypedData_v4`. The phone reviews and
//! approves; this side pre-checks the request with the same strict rules as the phone, then
//! recomputes the digest from the original request and only hands back a signature that recovers
//! to the pinned signer over that digest (verify::validate_message_signature).

use crate::{ask_phone, blocking, message, pairing, verify, CmdResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Serialize)]
pub struct SignedMessage { signature: String, digest: String, signer: String }

fn chain_quantity(chain_id: u64) -> CmdResult<String> {
    if !matches!(chain_id, 1 | 11155111 | 8453 | 10 | 42161 | 137) {
        return Err(format!("the phone has no reviewed profile for chain {chain_id}"));
    }
    Ok(verify::to_quantity(chain_id as u128))
}

fn request_signature(request: Value) -> CmdResult<SignedMessage> {
    let pinned = pairing::load().map_err(|e| e.0)?.ok_or("not paired yet")?;
    // Hold the phone from the device check through the signature (queued behind any other request).
    let _turn = crate::aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    crate::attest::require_ok(&pinned)?;
    // Refuse locally what the phone would refuse, before bothering the user on the phone.
    verify::expected_message_digest(&request).map_err(|e| e.0)?;
    let response = ask_phone(request.clone(), Duration::from_secs(300))?;
    let v = verify::validate_message_signature(&request, &response, &pinned).map_err(|e| e.0)?;
    Ok(SignedMessage { signature: v.signature, digest: v.digest, signer: verify::checksum(&v.signer) })
}

/// `message` is UTF-8 text, or 0x-prefixed hex bytes when `is_hex` is set.
#[tauri::command]
pub async fn sign_message(message: String, is_hex: bool, chain_id: u64) -> CmdResult<SignedMessage> {
    blocking(move || {
        let bytes = if is_hex {
            let body = message.trim().strip_prefix("0x").ok_or("hex message must start with 0x")?.to_string();
            hex::decode(&body).map_err(|_| "hex message must be an even number of hex digits".to_string())?
        } else {
            message.into_bytes()
        };
        if bytes.is_empty() { return Err("the message is empty".into()); }
        if bytes.len() > message::MAX_MESSAGE_BYTES { return Err(format!("the message exceeds {} bytes", message::MAX_MESSAGE_BYTES)); }
        request_signature(json!({
            "id": uuid::Uuid::new_v4().to_string(), "method": "personal_sign",
            "chainId": chain_quantity(chain_id)?, "message": format!("0x{}", hex::encode(&bytes)),
        }))
    }).await
}

/// `typed_data` is the eth_signTypedData_v4 JSON text, sent to the phone exactly as given.
#[tauri::command]
pub async fn sign_typed_data(typed_data: String, chain_id: u64) -> CmdResult<SignedMessage> {
    blocking(move || {
        request_signature(json!({
            "id": uuid::Uuid::new_v4().to_string(), "method": "eth_signTypedData_v4",
            "chainId": chain_quantity(chain_id)?, "typedData": typed_data,
        }))
    }).await
}
