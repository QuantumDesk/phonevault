//! Tauri commands, and the sign-in (EIP-4361) gate applied to prepared requests.

use super::node::{paired_or_err, prepare_tx};
use super::request::note;
use super::session::{add_chain, build_namespaces, plan_session, session_matches, SessionPlan};
use super::*;
use crate::pairing;
use serde_json::Value;

#[tauri::command]
pub fn wc_plan_session(required: Value, optional: Value) -> SessionPlan {
    plan_session(&required, &optional)
}

#[tauri::command]
pub fn wc_session_namespaces(required: Value, optional: Value, selected: Vec<u64>) -> Result<Value, String> {
    let paired = pairing::load()?.ok_or("not paired yet")?;
    build_namespaces(&required, &optional, &selected, &paired)
}

#[tauri::command]
pub fn wc_add_chain(namespaces: Value, chain_id: u64) -> Result<Value, String> {
    let paired = pairing::load()?.ok_or("not paired yet")?;
    add_chain(&namespaces, chain_id, &paired)
}

#[tauri::command]
pub fn wc_session_matches(namespaces: Value) -> bool {
    matches!(pairing::load(), Ok(Some(p)) if session_matches(&namespaces, &p))
}

/// Validate and map one dApp request. `chain` is the request's CAIP-2 chain; `session_chains` the
/// chains the session was approved for; `rpc_url` the user's node for that chain.
///
/// `origin`: the site that asked, only when it is trusted: the browser-reported origin (extension)
/// or WalletConnect Verify's origin when it says VALID. It is what a sign-in (EIP-4361) message is
/// checked against; without one a sign-in is only warned about.
#[tauri::command]
pub async fn wc_prepare(
    rpc_url: Option<String>,
    chain: String,
    session_chains: Vec<String>,
    method: String,
    params: Value,
    origin: Option<String>,
) -> Result<Prepared, RpcError> {
    tauri::async_runtime::spawn_blocking(move || {
        let paired = paired_or_err()?;
        let origin = trusted_origin(origin.as_deref());
        let id =
            parse_caip2(&chain).ok_or_else(|| rpc_err(CHAIN_DISCONNECTED, format!("{chain} is not an EVM chain")))?;
        let session: Vec<u64> = session_chains.iter().filter_map(|c| parse_caip2(c)).collect();
        if !session.contains(&id) {
            return Err(rpc_err(CHAIN_DISCONNECTED, format!("{} is not part of this session", chain_name(id))));
        }
        if !chain_allowed(id) {
            return Err(rpc_err(CHAIN_DISCONNECTED, format!("your phone has no reviewed profile for chain {id}")));
        }
        if method == "eth_sendTransaction" {
            let url = rpc_url.ok_or_else(|| rpc_err(INTERNAL, "no node configured for this chain"))?;
            return prepare_tx(&url, id, &params, &paired);
        }
        let mut prep = route(&method, &params, id, &session, &paired)?;
        sign_in_gate(&mut prep, origin.as_deref())?;
        Ok(prep)
    })
    .await
    .map_err(|e| rpc_err(INTERNAL, e.to_string()))?
}

/// A site origin the webview passed, in the bridge's normal form; anything malformed is dropped
/// (and then treated as unverified).
pub fn trusted_origin(origin: Option<&str>) -> Option<String> {
    origin.filter(|o| !o.is_empty()).and_then(|o| crate::bridge::normalize_origin(o).ok())
}

/// Sign-In with Ethereum: refuse a sign-in message for another site than the one asking; warn
/// when it is not known which site is asking.
pub fn sign_in_gate(prep: &mut Prepared, origin: Option<&str>) -> Result<(), RpcError> {
    let Prepared::PersonalSign { text: Some(text), notes, .. } = prep else { return Ok(()) };
    match crate::siwe::check(text, origin) {
        crate::siwe::Check::NotSignIn => {}
        crate::siwe::Check::Mismatch { domain, site } => return Err(rpc_err(UNAUTHORIZED, crate::siwe::blocked_message(&site, &domain))),
        crate::siwe::Check::Unverified { domain } => notes.insert(0, note("danger", format!(
            "This signs you in to {domain}, but which site is asking could not be verified. Sign only if you opened {domain} yourself."))),
        crate::siwe::Check::Matches { domain } => notes.push(note("info", format!("Signs you in to {domain}, the site that is asking."))),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wc::tests::ME;
    use serde_json::json;

    #[test]
    fn sign_in_messages_are_checked_against_the_asking_site() {
        let siwe = |domain: &str| {
            format!("0x{}", hex::encode(format!("{domain} wants you to sign in with your Ethereum account:\n{ME}\n\nURI: https://{domain}\nVersion: 1\nChain ID: 1\nNonce: 1\nIssued At: 2021-09-30T16:25:24Z")))
        };
        let prep = |domain: &str, origin: Option<&str>| -> Result<Prepared, RpcError> {
            let mut p = route("personal_sign", &json!([siwe(domain), ME]), 1, &[1], ME)?;
            sign_in_gate(&mut p, trusted_origin(origin).as_deref())?;
            Ok(p)
        };
        let notes = |p: Prepared| match p {
            Prepared::PersonalSign { notes, .. } => notes,
            _ => panic!(),
        };
        // matching site: an info note
        let n = notes(prep("app.uniswap.org", Some("https://app.uniswap.org")).unwrap());
        assert!(n.iter().any(|n| n.level == "info" && n.text.contains("app.uniswap.org")), "{n:?}");
        // another site: refused with a message naming both
        let e = prep("opensea.io", Some("https://evil.example")).unwrap_err();
        assert_eq!(e.code, UNAUTHORIZED);
        assert!(e.message.starts_with("Blocked: evil.example asked you to sign in to opensea.io"), "{}", e.message);
        // no trusted origin (WalletConnect Verify not VALID), or a malformed one: a danger note first
        for o in [None, Some("not an origin"), Some("http://evil.example")] {
            let n = notes(prep("opensea.io", o).unwrap());
            assert_eq!(n[0].level, "danger", "{o:?}");
            assert!(n[0].text.contains("could not be verified"));
        }
        // ordinary messages are untouched
        let mut p = route("personal_sign", &json!(["0x68656c6c6f", ME]), 1, &[1], ME).unwrap();
        sign_in_gate(&mut p, Some("https://evil.example")).unwrap();
        assert!(notes(p).is_empty());
    }
}
