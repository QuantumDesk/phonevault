//! Independent verification of what the phone returned. Nothing the phone claims is trusted:
//! the signed transaction is decoded field by field and compared with the request, the hash is
//! recomputed from the signed bytes, and the signer is recovered from the signature and compared
//! with the address pinned at pairing time. Port of `tools/evm_verify.py` + `validate_response`.

use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use serde_json::Value;
use sha3::{Digest, Keccak256};

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct VerifyError(pub String);
fn err(m: impl Into<String>) -> VerifyError { VerifyError(m.into()) }

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Keccak256::digest(data));
    out
}

/// Canonical 0x quantity → u128 ("0x0" or no leading zeros), the only form the phone accepts.
pub fn quantity(value: &str) -> Result<u128, VerifyError> {
    let hex = value.strip_prefix("0x").ok_or_else(|| err(format!("quantity without 0x: {value}")))?;
    if hex.is_empty() || hex.len() > 32 || (hex.len() > 1 && hex.starts_with('0')) || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(err(format!("non-canonical hex quantity: {value}")));
    }
    u128::from_str_radix(hex, 16).map_err(|_| err(format!("bad quantity: {value}")))
}

pub fn to_quantity(v: u128) -> String { if v == 0 { "0x0".into() } else { format!("0x{v:x}") } }

// ---------------------------------------------------------------- minimal RLP decoder

#[derive(Debug, Clone, PartialEq, Eq)]
enum Rlp { Bytes(Vec<u8>), List(Vec<Rlp>) }

fn rlp_len(data: &[u8], at: usize, prefix: u8, short_base: u8, long_base: u8) -> Result<(usize, usize), VerifyError> {
    if prefix < long_base {
        return Ok(((prefix - short_base) as usize, at + 1));
    }
    let n = (prefix - long_base + 1) as usize;
    let end = at + 1 + n;
    let bytes = data.get(at + 1..end).ok_or_else(|| err("RLP length truncated"))?;
    if bytes[0] == 0 { return Err(err("RLP length has leading zero")); }
    let mut len = 0usize;
    for &b in bytes { len = len.checked_mul(256).and_then(|l| l.checked_add(b as usize)).ok_or_else(|| err("RLP length overflow"))?; }
    if len < 56 { return Err(err("RLP long form used for short payload")); }
    Ok((len, end))
}

fn rlp_decode(data: &[u8], at: usize) -> Result<(Rlp, usize), VerifyError> {
    let prefix = *data.get(at).ok_or_else(|| err("RLP truncated"))?;
    if prefix < 0x80 { return Ok((Rlp::Bytes(vec![prefix]), at + 1)); }
    if prefix < 0xC0 {
        let (len, start) = rlp_len(data, at, prefix, 0x80, 0xB8)?;
        let bytes = data.get(start..start + len).ok_or_else(|| err("RLP string truncated"))?.to_vec();
        if len == 1 && bytes[0] < 0x80 { return Err(err("RLP single byte should be encoded directly")); }
        return Ok((Rlp::Bytes(bytes), start + len));
    }
    let (len, start) = rlp_len(data, at, prefix, 0xC0, 0xF8)?;
    let end = start + len;
    if end > data.len() { return Err(err("RLP list truncated")); }
    let mut items = Vec::new();
    let mut cursor = start;
    while cursor < end {
        let (item, next) = rlp_decode(data, cursor)?;
        items.push(item);
        cursor = next;
    }
    Ok((Rlp::List(items), end))
}

fn rlp_int(item: &Rlp, label: &str) -> Result<u128, VerifyError> {
    match item {
        Rlp::Bytes(b) => {
            if b.first() == Some(&0) && b.len() > 1 || b.len() > 16 { return Err(err(format!("{label}: non-canonical integer"))); }
            let mut v: u128 = 0;
            for &x in b { v = (v << 8) | x as u128; }
            Ok(v)
        }
        _ => Err(err(format!("{label}: expected bytes"))),
    }
}
fn rlp_bytes<'a>(item: &'a Rlp, label: &str) -> Result<&'a [u8], VerifyError> {
    match item { Rlp::Bytes(b) => Ok(b), _ => Err(err(format!("{label}: expected bytes"))) }
}

pub struct Signed {
    pub chain_id: u128, pub nonce: u128, pub max_priority_fee_per_gas: u128, pub max_fee_per_gas: u128,
    pub gas_limit: u128, pub to: String, pub value: u128, pub data: String,
    pub y_parity: u8, pub r: [u8; 32], pub s: [u8; 32], pub raw: Vec<u8>,
}

/// Decode `0x02 ‖ rlp([chainId, nonce, maxPrio, maxFee, gas, to, value, data, accessList, yParity, r, s])`.
pub fn decode_signed_eip1559(hex_tx: &str) -> Result<Signed, VerifyError> {
    let raw = hex::decode(hex_tx.strip_prefix("0x").ok_or_else(|| err("signedTransaction without 0x"))?).map_err(|_| err("signedTransaction is not hex"))?;
    if raw.first() != Some(&0x02) { return Err(err("not an EIP-1559 typed transaction")); }
    let (decoded, end) = rlp_decode(&raw, 1)?;
    if end != raw.len() { return Err(err("trailing bytes after the transaction")); }
    let items = match decoded { Rlp::List(v) => v, _ => return Err(err("transaction body is not a list")) };
    if items.len() != 12 { return Err(err(format!("expected 12 fields, got {}", items.len()))); }
    let to_bytes = rlp_bytes(&items[5], "to")?;
    if to_bytes.len() != 20 { return Err(err("to is not 20 bytes")); }
    match &items[8] { Rlp::List(l) if l.is_empty() => {}, _ => return Err(err("access list must be empty")) }
    let y = rlp_int(&items[9], "yParity")?;
    if y > 1 { return Err(err("yParity must be 0 or 1")); }
    let mut r = [0u8; 32]; let mut s = [0u8; 32];
    let rb = rlp_bytes(&items[10], "r")?; let sb = rlp_bytes(&items[11], "s")?;
    if rb.is_empty() || rb.len() > 32 || sb.is_empty() || sb.len() > 32 || (rb.len() > 1 && rb[0] == 0) || (sb.len() > 1 && sb[0] == 0) {
        return Err(err("signature components out of range"));
    }
    r[32 - rb.len()..].copy_from_slice(rb); s[32 - sb.len()..].copy_from_slice(sb);
    Ok(Signed {
        chain_id: rlp_int(&items[0], "chainId")?, nonce: rlp_int(&items[1], "nonce")?,
        max_priority_fee_per_gas: rlp_int(&items[2], "maxPriorityFeePerGas")?, max_fee_per_gas: rlp_int(&items[3], "maxFeePerGas")?,
        gas_limit: rlp_int(&items[4], "gasLimit")?, to: format!("0x{}", hex::encode(to_bytes)), value: rlp_int(&items[6], "value")?,
        data: format!("0x{}", hex::encode(rlp_bytes(&items[7], "data")?)), y_parity: y as u8, r, s, raw,
    })
}

/// The exact bytes the phone signed: the typed payload without the signature.
fn signing_payload(signed: &Signed) -> Result<Vec<u8>, VerifyError> {
    // Re-encode from the decoded fields: 0x02 ‖ rlp(first nine items). Re-encoding the parsed
    // list is simplest and exact because RLP is canonical.
    let (decoded, _) = rlp_decode(&signed.raw, 1)?;
    let items = match decoded { Rlp::List(v) => v, _ => unreachable!() };
    let unsigned = Rlp::List(items[..9].to_vec());
    let mut out = vec![0x02];
    out.extend(rlp_encode(&unsigned));
    Ok(out)
}

fn rlp_encode(item: &Rlp) -> Vec<u8> {
    fn prefix(len: usize, short: u8, long: u8) -> Vec<u8> {
        if len < 56 { return vec![short + len as u8]; }
        let mut be = len.to_be_bytes().to_vec();
        while be.first() == Some(&0) { be.remove(0); }
        // long form: 0xB7 / 0xF7 + length-of-length (was off by one, which broke signer
        // recovery for any transaction whose payload or calldata is 56 bytes or longer)
        let mut out = vec![long + be.len() as u8];
        out.extend(be);
        out
    }
    match item {
        Rlp::Bytes(b) if b.len() == 1 && b[0] < 0x80 => b.clone(),
        Rlp::Bytes(b) => { let mut out = prefix(b.len(), 0x80, 0xB7); out.extend(b); out }
        Rlp::List(items) => {
            let body: Vec<u8> = items.iter().flat_map(rlp_encode).collect();
            let mut out = prefix(body.len(), 0xC0, 0xF7); out.extend(body); out
        }
    }
}

pub fn recover_signer(signed: &Signed) -> Result<String, VerifyError> {
    let hash = keccak256(&signing_payload(signed)?);
    let sig = Signature::from_scalars(signed.r, signed.s).map_err(|_| err("signature scalars out of range"))?;
    if sig.normalize_s().is_some() { return Err(err("signature s is not low-s (EIP-2)")); }
    let rid = RecoveryId::try_from(signed.y_parity).map_err(|_| err("bad recovery id"))?;
    let key = VerifyingKey::recover_from_prehash(&hash, &sig, rid).map_err(|_| err("signature does not recover to a key"))?;
    let point = key.to_encoded_point(false);
    let addr = keccak256(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&addr[12..])))
}

/// EIP-55 checksum casing, for display only.
pub fn checksum(address: &str) -> String {
    let lower = address.trim_start_matches("0x").to_ascii_lowercase();
    let hash = hex::encode(keccak256(lower.as_bytes()));
    let mut out = String::from("0x");
    for (i, c) in lower.chars().enumerate() {
        let h = u8::from_str_radix(&hash[i..i + 1], 16).unwrap_or(0);
        out.push(if c.is_ascii_alphabetic() && h >= 8 { c.to_ascii_uppercase() } else { c });
    }
    out
}

/// A signature that passed `validate_signature`, with the destination, value and calldata as
/// DECODED FROM THE SIGNED BYTES (not copied from the request), for intent checks such as
/// `check_erc20_transfer`.
#[derive(Debug)]
pub struct Verified { pub raw_hex: String, pub tx_hash: String, pub signer: String, pub to: String, pub value: u128, pub data: String }

/// Validate a `signEip1559` response against the request and the pinned signer.
pub fn validate_signature(request: &Value, response: &Value, pinned_signer: &str) -> Result<Verified, VerifyError> {
    let obj = response.as_object().ok_or_else(|| err("response is not an object"))?;
    if obj.get("id") != request.get("id") { return Err(err("phone response does not correlate to the request")); }
    match obj.get("status").and_then(Value::as_str) {
        Some("rejected") => return Err(err("rejected on the phone")),
        Some("error") => return Err(err(format!("phone error: {}", obj.get("error").and_then(Value::as_str).unwrap_or("unknown")))),
        Some("approved") => {}
        _ => return Err(err("malformed response status")),
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
    if keys != ["address", "id", "signedTransaction", "status", "transactionHash"] { return Err(err("approved response has unexpected fields")); }
    let claimed_hash = obj["transactionHash"].as_str().ok_or_else(|| err("transactionHash missing"))?;
    let signed = decode_signed_eip1559(obj["signedTransaction"].as_str().ok_or_else(|| err("signedTransaction missing"))?)?;
    let q = |k: &str| -> Result<u128, VerifyError> { quantity(request.get(k).and_then(Value::as_str).ok_or_else(|| err(format!("request lacks {k}")))?) };
    let checks: [(&str, bool); 8] = [
        ("chainId", signed.chain_id == q("chainId")?),
        ("nonce", signed.nonce == q("nonce")?),
        ("maxPriorityFeePerGas", signed.max_priority_fee_per_gas == q("maxPriorityFeePerGas")?),
        ("maxFeePerGas", signed.max_fee_per_gas == q("maxFeePerGas")?),
        ("gasLimit", signed.gas_limit == q("gasLimit")?),
        ("to", signed.to == request["to"].as_str().unwrap_or("").to_ascii_lowercase()),
        ("value", signed.value == q("value")?),
        ("data", signed.data == request["data"].as_str().unwrap_or("").to_ascii_lowercase()),
    ];
    if let Some((field, _)) = checks.iter().find(|(_, ok)| !ok) {
        return Err(err(format!("signed {field} differs from the request — refusing to broadcast")));
    }
    let recomputed = format!("0x{}", hex::encode(keccak256(&signed.raw)));
    if recomputed != claimed_hash.to_ascii_lowercase() { return Err(err("transaction hash does not match the signed bytes")); }
    let signer = recover_signer(&signed)?;
    if signer != pinned_signer.to_ascii_lowercase() { return Err(err(format!("recovered signer {} is not the paired phone {}", checksum(&signer), checksum(pinned_signer)))); }
    if obj["address"].as_str().map(str::to_ascii_lowercase) != Some(signer.clone()) { return Err(err("phone's claimed address differs from the recovered signer")); }
    Ok(Verified { raw_hex: format!("0x{}", hex::encode(&signed.raw)), tx_hash: recomputed, signer, to: signed.to, value: signed.value, data: signed.data })
}

// ---------------------------------------------------------------- ERC-20 intent

/// Strictly decode `transfer(address,uint256)` calldata: exactly 68 bytes, selector a9059cbb,
/// zero-padded non-zero address, amount that fits u128. Returns (recipient lower-case, amount).
pub fn decode_erc20_transfer(data: &str) -> Result<(String, u128), VerifyError> {
    let body = data.strip_prefix("0x").ok_or_else(|| err("calldata without 0x"))?.to_ascii_lowercase();
    if body.len() != 136 || !body.bytes().all(|b| b.is_ascii_hexdigit()) { return Err(err("calldata is not exactly transfer(address,uint256): wrong length")); }
    if &body[..8] != "a9059cbb" { return Err(err("calldata is not transfer(address,uint256)")); }
    if !body[8..32].bytes().all(|b| b == b'0') { return Err(err("transfer recipient has non-zero ABI padding")); }
    let recipient = format!("0x{}", &body[32..72]);
    if body[32..72].bytes().all(|b| b == b'0') { return Err(err("transfer to the zero address")); }
    if !body[72..104].bytes().all(|b| b == b'0') { return Err(err("transfer amount does not fit this app's range")); }
    let amount = u128::from_str_radix(&body[104..136], 16).map_err(|_| err("bad transfer amount"))?;
    Ok((recipient, amount))
}

/// The UI's token-send intent against what the phone SIGNED (decoded from the signed bytes):
/// the transaction goes to the token contract, carries no ETH, and its calldata decodes to
/// exactly transfer(recipient, amount). Runs after `validate_signature`, never instead of it.
pub fn check_erc20_transfer(v: &Verified, contract: &str, recipient: &str, amount: u128) -> Result<(), VerifyError> {
    if v.to != contract.to_ascii_lowercase() { return Err(err("signed transaction is not addressed to the token contract — refusing to broadcast")); }
    if v.value != 0 { return Err(err("signed token transfer also sends ETH — refusing to broadcast")); }
    let (to, amt) = decode_erc20_transfer(&v.data)?;
    if to != recipient.to_ascii_lowercase() { return Err(err("signed token recipient differs from what you entered — refusing to broadcast")); }
    if amt != amount { return Err(err("signed token amount differs from what you entered — refusing to broadcast")); }
    Ok(())
}

// ---------------------------------------------------------------- personal_sign / EIP-712

/// The digest the phone must have signed, recomputed here from the ORIGINAL request only.
pub fn expected_message_digest(request: &Value) -> Result<[u8; 32], VerifyError> {
    let field = |k: &str| request.get(k).and_then(Value::as_str).ok_or_else(|| err(format!("request lacks {k}")));
    match field("method")? {
        "personal_sign" => {
            let hex_msg = field("message")?;
            let body = hex_msg.strip_prefix("0x").ok_or_else(|| err("message without 0x"))?;
            let bytes = hex::decode(body).map_err(|_| err("message is not even-length hex"))?;
            if bytes.is_empty() || bytes.len() > crate::message::MAX_MESSAGE_BYTES { return Err(err("message length out of range")); }
            Ok(crate::message::personal_digest(&bytes))
        }
        "eth_signTypedData_v4" => Ok(crate::message::typed_data_digest(field("typedData")?).map_err(|e| err(e.0))?.digest),
        other => Err(err(format!("not a message-signing method: {other}"))),
    }
}

/// Recover the signer of a 32-byte digest from a 65-byte r ‖ s ‖ v signature (v = 27 or 28, low s).
pub fn recover_digest_signer(digest: &[u8; 32], signature_hex: &str) -> Result<String, VerifyError> {
    let body = signature_hex.strip_prefix("0x").ok_or_else(|| err("signature without 0x"))?;
    if body.len() != 130 { return Err(err("signature must be 65 bytes")); }
    let sig = hex::decode(body).map_err(|_| err("signature is not hex"))?;
    let v = sig[64];
    if v != 27 && v != 28 { return Err(err("signature v must be 27 or 28")); }
    let mut r = [0u8; 32]; let mut s = [0u8; 32];
    r.copy_from_slice(&sig[..32]); s.copy_from_slice(&sig[32..64]);
    let sig = Signature::from_scalars(r, s).map_err(|_| err("signature scalars out of range"))?;
    if sig.normalize_s().is_some() { return Err(err("signature s is not low-s (EIP-2)")); }
    let rid = RecoveryId::try_from(v - 27).map_err(|_| err("bad recovery id"))?;
    let key = VerifyingKey::recover_from_prehash(digest, &sig, rid).map_err(|_| err("signature does not recover to a key"))?;
    let point = key.to_encoded_point(false);
    let addr = keccak256(&point.as_bytes()[1..]);
    Ok(format!("0x{}", hex::encode(&addr[12..])))
}

#[derive(Debug)]
pub struct VerifiedMessage { pub signature: String, pub digest: String, pub signer: String }

/// Validate a `personal_sign` / `eth_signTypedData_v4` response. The digest is recomputed from the
/// request (never taken from the phone), the phone's claimed digest must equal it, and the signature
/// must recover to the pinned signer over OUR digest. Anything else: refuse, return nothing.
pub fn validate_message_signature(request: &Value, response: &Value, pinned_signer: &str) -> Result<VerifiedMessage, VerifyError> {
    let expected = expected_message_digest(request)?;
    let obj = response.as_object().ok_or_else(|| err("response is not an object"))?;
    if obj.get("id") != request.get("id") { return Err(err("phone response does not correlate to the request")); }
    match obj.get("status").and_then(Value::as_str) {
        Some("rejected") => return Err(err("rejected on the phone")),
        Some("error") => return Err(err(format!("phone error: {}", obj.get("error").and_then(Value::as_str).unwrap_or("unknown")))),
        Some("approved") => {}
        _ => return Err(err("malformed response status")),
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect(); keys.sort();
    if keys != ["address", "digest", "id", "signature", "status"] { return Err(err("approved response has unexpected fields")); }
    let expected_hex = format!("0x{}", hex::encode(expected));
    let claimed = obj["digest"].as_str().ok_or_else(|| err("digest missing"))?;
    if claimed.to_ascii_lowercase() != expected_hex {
        return Err(err(format!("the phone signed digest {claimed}, but this request hashes to {expected_hex}; refusing the signature")));
    }
    let signature = obj["signature"].as_str().ok_or_else(|| err("signature missing"))?.to_ascii_lowercase();
    let signer = recover_digest_signer(&expected, &signature)?;
    if signer != pinned_signer.to_ascii_lowercase() { return Err(err(format!("recovered signer {} is not the paired phone {}", checksum(&signer), checksum(pinned_signer)))); }
    if obj["address"].as_str().map(str::to_ascii_lowercase) != Some(signer.clone()) { return Err(err("phone's claimed address differs from the recovered signer")); }
    Ok(VerifiedMessage { signature, digest: expected_hex, signer })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn checksum_matches_eip55_vector() {
        assert_eq!(checksum("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed"), "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed");
    }
    #[test]
    fn quantities_are_canonical() {
        assert_eq!(quantity("0x0").unwrap(), 0);
        assert_eq!(quantity("0x1a").unwrap(), 26);
        assert!(quantity("0x01").is_err());
        assert!(quantity("0x").is_err());
        assert_eq!(to_quantity(0), "0x0");
        assert_eq!(to_quantity(26), "0x1a");
    }
    // A REAL signature produced by the Pixel (tools/test_aoa_client.py fixture): Sepolia, nonce 0,
    // 1 gwei priority, 2 gwei max, 21000 gas, to 0x1111…, value 0. Signer 0x5d57…400f.
    const SIGNED: &str = "0x02f86d83aa36a780843b9aca008477359400825208\
9411111111111111111111111111111111111111118080c080\
a08fea69f8d5274d05db3283e8859f852c5c49600b0fd43eeb936e52797ff6a1eb\
a0552f96d381d40f3683e144a7fb52bc9eb92019f4fd5f1835bdbf72b5a6a6a1a9";
    const SIGNER: &str = "0x5d57809c668b6fa32396f3176df830ba3b49400f";
    fn fixture_request() -> Value {
        serde_json::json!({"id": "request-1", "method": "signEip1559", "chainId": "0xaa36a7", "nonce": "0x0",
            "maxPriorityFeePerGas": "0x3b9aca00", "maxFeePerGas": "0x77359400", "gasLimit": "0x5208",
            "to": "0x1111111111111111111111111111111111111111", "value": "0x0", "data": "0x"})
    }
    fn fixture_response() -> Value {
        serde_json::json!({"id": "request-1", "status": "approved", "address": SIGNER, "signedTransaction": SIGNED,
            "transactionHash": "0x8e4958ec81904b4397d3d095d316fbac072551ccc74b93b67acaa811d03e67b8"})
    }
    #[test]
    fn decodes_the_real_phone_signature_and_recovers_the_signer() {
        let signed = decode_signed_eip1559(SIGNED).unwrap();
        assert_eq!(signed.chain_id, 0xaa36a7);
        assert_eq!(signed.gas_limit, 21000);
        assert_eq!(recover_signer(&signed).unwrap(), SIGNER);
        assert_eq!(format!("0x{}", hex::encode(keccak256(&signed.raw))), "0x8e4958ec81904b4397d3d095d316fbac072551ccc74b93b67acaa811d03e67b8");
    }
    #[test]
    fn validates_a_matching_response_and_refuses_tampering() {
        assert!(validate_signature(&fixture_request(), &fixture_response(), SIGNER).is_ok());
        // wrong pinned signer → refused even though the response is self-consistent
        assert!(validate_signature(&fixture_request(), &fixture_response(), "0x1111111111111111111111111111111111111111").is_err());
        // request says a different recipient than what was signed → refused
        let mut req = fixture_request(); req["to"] = Value::from("0x2222222222222222222222222222222222222222");
        assert!(validate_signature(&req, &fixture_response(), SIGNER).unwrap_err().0.contains("to"));
        // a flipped byte in the signed bytes → hash mismatch or recovery failure, never a pass
        let mut resp = fixture_response();
        let mut raw = hex::decode(&SIGNED[2..]).unwrap(); raw[20] ^= 0x01;
        resp["signedTransaction"] = Value::from(format!("0x{}", hex::encode(raw)));
        assert!(validate_signature(&fixture_request(), &resp, SIGNER).is_err());
        // rejected → error surfaced, never a signature
        let rej = serde_json::json!({"id": "request-1", "status": "rejected"});
        assert!(validate_signature(&fixture_request(), &rej, SIGNER).unwrap_err().0.contains("rejected"));
    }

    // ------------------------------------------------ shared vectors with the phone's JVM tests
    const VECTORS: &str = include_str!("../../../app/src/test/resources/message-signing-vectors.json");
    fn vectors() -> Value { serde_json::from_str(VECTORS).unwrap() }
    fn vector(name: &str) -> Value {
        vectors()["vectors"].as_array().unwrap().iter().find(|v| v["name"] == name).cloned().unwrap()
    }
    fn message_request(v: &Value) -> Value {
        if v["kind"] == "typed" {
            serde_json::json!({"id": "m-1", "method": "eth_signTypedData_v4", "chainId": "0x1", "typedData": v["typedData"]})
        } else {
            serde_json::json!({"id": "m-1", "method": "personal_sign", "chainId": "0x1", "message": v["message"]})
        }
    }
    fn approved(v: &Value, signer: &str) -> Value {
        serde_json::json!({"id": "m-1", "status": "approved", "address": signer, "signature": v["signature"], "digest": v["digest"]})
    }

    #[test]
    fn every_shared_vector_matches_byte_for_byte() {
        let all = vectors();
        let signer = all["signer"].as_str().unwrap();
        let list = all["vectors"].as_array().unwrap();
        assert!(list.len() >= 11);
        for v in list {
            let name = v["name"].as_str().unwrap();
            if v["kind"] == "typed" {
                let t = crate::message::typed_data_digest(v["typedData"].as_str().unwrap()).unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(format!("0x{}", hex::encode(t.domain_separator)), v["domainSeparator"], "{name} domain separator");
                assert_eq!(format!("0x{}", hex::encode(t.message_hash)), v["messageHash"], "{name} message hash");
            }
            let req = message_request(v);
            let digest = expected_message_digest(&req).unwrap();
            assert_eq!(format!("0x{}", hex::encode(digest)), v["digest"], "{name} digest");
            assert_eq!(recover_digest_signer(&digest, v["signature"].as_str().unwrap()).unwrap(), signer, "{name} signer");
            let ok = validate_message_signature(&req, &approved(v, signer), signer).unwrap();
            assert_eq!(ok.digest, v["digest"].as_str().unwrap());
        }
    }

    #[test]
    fn every_shared_rejection_is_refused() {
        let all = vectors();
        let list = all["rejections"].as_array().unwrap();
        assert!(list.len() >= 50);
        for r in list {
            assert!(crate::message::typed_data_digest(r["typedData"].as_str().unwrap()).is_err(), "accepted {}", r["name"]);
        }
    }

    #[test]
    fn mail_matches_the_eip_published_values() {
        let v = vector("eip712-mail");
        let text = v["typedData"].as_str().unwrap();
        assert_eq!(crate::message::encode_type(text, "Mail"), "Mail(Person from,Person to,string contents)Person(string name,address wallet)");
        let t = crate::message::typed_data_digest(text).unwrap();
        assert_eq!(hex::encode(t.domain_separator), "f2cee375fa42b42143804025fc449deafd50cc031ca257e0b194a650a912090f");
        assert_eq!(hex::encode(t.message_hash), "c52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e");
        assert_eq!(hex::encode(t.digest), "be609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2");
        let nested = vector("sig-util-v4-nested-arrays");
        assert_eq!(crate::message::encode_type(nested["typedData"].as_str().unwrap(), "Mail"),
            "Mail(Person from,Person[] to,string contents)Person(string name,address[] wallets)");
    }

    #[test]
    fn message_responses_are_refused_unless_everything_matches() {
        let all = vectors();
        let signer = all["signer"].as_str().unwrap();
        let v = vector("permit2-single");
        let req = message_request(&v);
        assert!(validate_message_signature(&req, &approved(&v, signer), signer).is_ok());
        // wrong pinned signer
        assert!(validate_message_signature(&req, &approved(&v, signer), "0x1111111111111111111111111111111111111111").is_err());
        // the phone claims a different digest (it displayed/signed something else): refused
        let mut other = approved(&v, signer);
        other["digest"] = vector("permit2-batch")["digest"].clone();
        assert!(validate_message_signature(&req, &other, signer).unwrap_err().0.contains("refusing"));
        // a signature over another message with the right claimed digest: does not recover to the pinned key
        let mut swapped = approved(&v, signer);
        swapped["signature"] = vector("permit2-batch")["signature"].clone();
        assert!(validate_message_signature(&req, &swapped, signer).is_err());
        // the request was altered (one character of the typed data): refused
        let mut altered = req.clone();
        altered["typedData"] = Value::from(v["typedData"].as_str().unwrap().replace("1767225600", "1767225601"));
        assert!(validate_message_signature(&altered, &approved(&v, signer), signer).is_err());
        // the high-s twin of a valid signature is refused (EIP-2)
        let sig = hex::decode(&v["signature"].as_str().unwrap()[2..]).unwrap();
        let n = hex::decode("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141").unwrap();
        let mut high = vec![0u8; 32]; let mut borrow = 0i16;
        for i in (0..32).rev() { let d = n[i] as i16 - sig[32 + i] as i16 - borrow; high[i] = d.rem_euclid(256) as u8; borrow = (d < 0) as i16; }
        let mut twin = sig.clone(); twin[32..64].copy_from_slice(&high); twin[64] = if sig[64] == 27 { 28 } else { 27 };
        let mut resp = approved(&v, signer); resp["signature"] = Value::from(format!("0x{}", hex::encode(twin)));
        assert!(validate_message_signature(&req, &resp, signer).unwrap_err().0.contains("low-s"));
        // extra response field, rejection and error are never a signature
        let mut extra = approved(&v, signer); extra["note"] = Value::from("x");
        assert!(validate_message_signature(&req, &extra, signer).is_err());
        assert!(validate_message_signature(&req, &serde_json::json!({"id": "m-1", "status": "rejected"}), signer).unwrap_err().0.contains("rejected"));
        // claimed address differs from the recovered signer
        let mut liar = approved(&v, signer); liar["address"] = Value::from("0x1111111111111111111111111111111111111111");
        assert!(validate_message_signature(&req, &liar, signer).is_err());
    }

    // ------------------------------------------------ ERC-20 transfers: sign here, verify like the phone's answers

    /// Throwaway test key (the well-known web3 docs example key, also used by the JVM tests).
    const TEST_KEY: &str = "04c0883a69102937d6231471b5dbb6204fe51296170827966f278a5e6f4f4f5f";
    fn int_bytes(v: u128) -> Rlp { let b = v.to_be_bytes(); let i = b.iter().position(|&x| x != 0).unwrap_or(16); Rlp::Bytes(b[i..].to_vec()) }
    fn hex_bytes(h: &str) -> Vec<u8> { hex::decode(h.trim_start_matches("0x")).unwrap() }
    /// Sign a request the way the phone does (EIP-1559, empty access list) and answer in its format.
    fn sign_like_the_phone(req: &Value) -> Value {
        use k256::ecdsa::SigningKey;
        let q = |k: &str| quantity(req[k].as_str().unwrap()).unwrap();
        let fields = vec![int_bytes(q("chainId")), int_bytes(q("nonce")), int_bytes(q("maxPriorityFeePerGas")), int_bytes(q("maxFeePerGas")),
            int_bytes(q("gasLimit")), Rlp::Bytes(hex_bytes(req["to"].as_str().unwrap())), int_bytes(q("value")),
            Rlp::Bytes(hex_bytes(req["data"].as_str().unwrap())), Rlp::List(vec![])];
        let mut payload = vec![0x02]; payload.extend(rlp_encode(&Rlp::List(fields.clone())));
        let key = SigningKey::from_slice(&hex::decode(TEST_KEY).unwrap()).unwrap();
        let (sig, rid) = key.sign_prehash_recoverable(&keccak256(&payload)).unwrap();
        let (sig, rid) = match sig.normalize_s() { Some(n) => (n, RecoveryId::from_byte(rid.to_byte() ^ 1).unwrap()), None => (sig, rid) };
        let bytes = sig.to_bytes();
        let strip = |b: &[u8]| { let i = b.iter().position(|&x| x != 0).unwrap_or(b.len() - 1); Rlp::Bytes(b[i..].to_vec()) };
        let mut all = fields; all.push(int_bytes(rid.to_byte() as u128)); all.push(strip(&bytes[..32])); all.push(strip(&bytes[32..]));
        let mut raw = vec![0x02]; raw.extend(rlp_encode(&Rlp::List(all)));
        let point = key.verifying_key().to_encoded_point(false);
        let addr = format!("0x{}", hex::encode(&keccak256(&point.as_bytes()[1..])[12..]));
        serde_json::json!({"id": req["id"], "status": "approved", "address": addr, "signedTransaction": format!("0x{}", hex::encode(&raw)),
            "transactionHash": format!("0x{}", hex::encode(keccak256(&raw)))})
    }
    const USDC: &str = "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48";
    const RECIPIENT: &str = "0x7f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b93";
    fn token_request(data: &str) -> Value {
        serde_json::json!({"id": "tok-1", "method": "signEip1559", "chainId": "0x1", "nonce": "0x5",
            "maxPriorityFeePerGas": "0x3b9aca00", "maxFeePerGas": "0x77359400", "gasLimit": "0xfde8",
            "to": USDC, "value": "0x0", "data": data})
    }

    #[test]
    fn a_signed_token_transfer_is_re_decoded_and_matched_to_the_intent() {
        let data = crate::tokens::transfer_calldata(RECIPIENT, 50_000_000).unwrap();
        let req = token_request(&data);
        let resp = sign_like_the_phone(&req);
        let signer = resp["address"].as_str().unwrap().to_string();
        let v = validate_signature(&req, &resp, &signer).unwrap();
        assert_eq!((v.to.as_str(), v.value, v.data.as_str()), (USDC, 0, data.as_str()));
        check_erc20_transfer(&v, USDC, RECIPIENT, 50_000_000).unwrap();
        // the intent the UI showed must be exactly what was signed
        assert!(check_erc20_transfer(&v, USDC, RECIPIENT, 50_000_001).unwrap_err().0.contains("amount"));
        assert!(check_erc20_transfer(&v, USDC, "0x1111111111111111111111111111111111111111", 50_000_000).unwrap_err().0.contains("recipient"));
        assert!(check_erc20_transfer(&v, "0xdac17f958d2ee523a2206206994597c13d831ec7", RECIPIENT, 50_000_000).unwrap_err().0.contains("token contract"));
    }

    /// The Mac's simulation claim (`hostSimulation`, sim.rs) rides along in the request but is never
    /// signed and never read here: a lying claim changes nothing, and a matching claim rescues nothing.
    #[test]
    fn the_host_simulation_field_never_affects_verification() {
        let data = crate::tokens::transfer_calldata(RECIPIENT, 50_000_000).unwrap();
        let plain = token_request(&data);
        let resp = sign_like_the_phone(&plain);
        let signer = resp["address"].as_str().unwrap().to_string();
        let mut with_claim = plain.clone();
        with_claim["hostSimulation"] = serde_json::json!({"changes": [{"asset": USDC, "delta": "50000000", "symbol": "USDC", "decimals": 6},
            {"asset": "native", "delta": "1000000000000000000"}], "node": "evil.example", "block": "0x1"});
        let a = validate_signature(&plain, &resp, &signer).unwrap();
        let b = validate_signature(&with_claim, &resp, &signer).unwrap();
        assert_eq!((a.raw_hex, a.tx_hash), (b.raw_hex.clone(), b.tx_hash.clone()));
        check_erc20_transfer(&b, USDC, RECIPIENT, 50_000_000).unwrap();
        // the phone signs the transaction fields only, with or without the claim
        assert_eq!(sign_like_the_phone(&with_claim)["signedTransaction"], resp["signedTransaction"]);
        // a phone that signed something else is refused whatever the claim says
        let mut other = plain.clone(); other["data"] = Value::from(crate::tokens::transfer_calldata(RECIPIENT, 5_000_000_000).unwrap());
        let bad = sign_like_the_phone(&other);
        let mut claim_matching_bad = with_claim.clone();
        claim_matching_bad["hostSimulation"]["changes"][0]["delta"] = Value::from("-5000000000");
        assert!(validate_signature(&claim_matching_bad, &bad, &signer).unwrap_err().0.contains("data"));
    }

    #[test]
    fn a_phone_that_signs_different_calldata_is_refused() {
        let asked = token_request(&crate::tokens::transfer_calldata(RECIPIENT, 50_000_000).unwrap());
        // the phone (or the cable) swaps the amount: the response is internally consistent but differs from the request
        let mut other = asked.clone(); other["data"] = Value::from(crate::tokens::transfer_calldata(RECIPIENT, 5_000_000_000).unwrap());
        let resp = sign_like_the_phone(&other);
        let signer = resp["address"].as_str().unwrap().to_string();
        assert!(validate_signature(&asked, &resp, &signer).unwrap_err().0.contains("data"));
        // the swapped recipient likewise
        let mut other = asked.clone(); other["data"] = Value::from(crate::tokens::transfer_calldata("0x1111111111111111111111111111111111111111", 50_000_000).unwrap());
        assert!(validate_signature(&asked, &sign_like_the_phone(&other), &signer).is_err());
        // native value added to a token call
        let mut other = asked.clone(); other["value"] = Value::from("0x1");
        assert!(validate_signature(&asked, &sign_like_the_phone(&other), &signer).unwrap_err().0.contains("value"));
    }

    /// An independently produced token transfer (Foundry `cast mktx`, same throwaway key, RFC 6979):
    /// transfer 50 USDC to 0x7F3A…4B93, mainnet, nonce 5, gas 65000, 1 / 2 gwei.
    const CAST_USDC_TRANSFER: &str = "0x02f8af0105843b9aca00847735940082fde894a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4880b844a9059cbb\
0000000000000000000000007f3a9c04e2b16d58a41c0f9e6b2d7a8c5e1f4b930000000000000000000000000000000000000000000000000000000002faf080\
c001a01236613fa9151ad57d53751c56c08bcd7a5cfca21f201befba28f93b34f1b635a03daf980137a81f40dd69d93df5d7170757c8128f7982a02d83e7adda7b00541f";

    #[test]
    fn an_independently_signed_token_transfer_verifies_and_matches_our_encoder() {
        let data = crate::tokens::transfer_calldata(RECIPIENT, 50_000_000).unwrap();
        let req = token_request(&data);
        let resp = serde_json::json!({"id": "tok-1", "status": "approved", "address": SIGNER, "signedTransaction": CAST_USDC_TRANSFER,
            "transactionHash": format!("0x{}", hex::encode(keccak256(&hex::decode(&CAST_USDC_TRANSFER[2..]).unwrap())))});
        let v = validate_signature(&req, &resp, SIGNER).unwrap();
        check_erc20_transfer(&v, USDC, RECIPIENT, 50_000_000).unwrap();
        // our test signer (and so our RLP encoder) produces the very same bytes
        assert_eq!(sign_like_the_phone(&req)["signedTransaction"], CAST_USDC_TRANSFER);
    }

    #[test]
    fn rlp_long_forms_round_trip() {
        // 56+ byte strings and lists use the long form (0xB8.. / 0xF8..); token calldata is 68 bytes.
        for len in [55usize, 56, 68, 255, 256, 1024] {
            let item = Rlp::Bytes(vec![0xab; len]);
            let enc = rlp_encode(&item);
            if len >= 56 { assert_eq!(enc[0], 0xB7 + if len < 256 { 1 } else { 2 }); }
            assert_eq!(rlp_decode(&enc, 0).unwrap(), (item.clone(), enc.len()));
            let list = Rlp::List(vec![item.clone(), Rlp::Bytes(vec![1])]);
            let enc = rlp_encode(&list);
            assert_eq!(rlp_decode(&enc, 0).unwrap(), (list, enc.len()));
        }
    }

    #[test]
    fn erc20_decoding_is_strict() {
        let good = crate::tokens::transfer_calldata(RECIPIENT, 7).unwrap();
        assert_eq!(decode_erc20_transfer(&good).unwrap(), (RECIPIENT.to_string(), 7));
        assert!(decode_erc20_transfer(&format!("{good}00")).is_err(), "trailing byte");
        assert!(decode_erc20_transfer(&good[..good.len() - 2]).is_err(), "truncated");
        assert!(decode_erc20_transfer(&good.replacen("a9059cbb", "095ea7b3", 1)).is_err(), "approve is not a transfer");
        assert!(decode_erc20_transfer(&good.replacen("0xa9059cbb00", "0xa9059cbb01", 1)).is_err(), "dirty padding");
        assert!(decode_erc20_transfer(&crate::tokens::transfer_calldata("0x0000000000000000000000000000000000000000", 1).unwrap()).is_err());
        let huge = format!("0xa9059cbb{:0>64}{}", &RECIPIENT[2..], "f".repeat(64));
        assert!(decode_erc20_transfer(&huge).is_err(), "amount beyond u128");
        assert!(decode_erc20_transfer("0x").is_err());
    }

    #[test]
    fn personal_digest_matches_eip191() {
        // keccak256("\x19Ethereum Signed Message:\n5hello")
        assert_eq!(hex::encode(crate::message::personal_digest(b"hello")), "50b2c43fd39106bafbba0da34fc430e1f91e3c96ea2acee2bc34119f92b37750");
    }
}
