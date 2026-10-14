//! The session plan: which requested networks the phone can sign for, and the namespaces to approve.

use super::*;
use crate::verify;
use serde_json::{json, Value};

#[derive(Serialize, Debug, Clone, PartialEq)]
pub struct ChainOffer {
    pub caip: String,
    pub id: u64,
    pub name: String,
    pub supported: bool,
    pub required: bool,
}

#[derive(Serialize, Debug, Default)]
pub struct SessionPlan {
    /// Every eip155 chain the dApp named, required ones first.
    pub chains: Vec<ChainOffer>,
    /// Every method the dApp named (required and optional).
    pub methods: Vec<String>,
    /// Methods the dApp named that this wallet always refuses.
    pub refused_methods: Vec<String>,
    /// Required methods among `refused_methods`: approved so the session can exist, refused per call.
    pub required_refused_methods: Vec<String>,
    /// Non-EVM namespaces the dApp asked for.
    pub other_namespaces: Vec<String>,
    /// Why this proposal cannot be approved, if it cannot.
    pub blocker: Option<String>,
}

struct Requested {
    chains: Vec<(String, bool)>,
    methods: Vec<(String, bool)>,
    events: Vec<(String, bool)>,
    other: Vec<(String, bool)>,
}

/// Flatten requiredNamespaces/optionalNamespaces. Keys are "eip155" (with a `chains` list) or a
/// chain-specific key like "eip155:1" (no list).
fn requested(required: &Value, optional: &Value) -> Requested {
    let mut r = Requested { chains: vec![], methods: vec![], events: vec![], other: vec![] };
    fn push(list: &mut Vec<(String, bool)>, item: &str, req: bool) {
        if let Some(e) = list.iter_mut().find(|(s, _)| s == item) {
            e.1 |= req;
        } else {
            list.push((item.to_string(), req));
        }
    }
    for (ns, req) in [(required, true), (optional, false)] {
        let Some(map) = ns.as_object() else { continue };
        for (key, body) in map {
            let (space, key_chain) = match key.split_once(':') {
                Some((s, _)) => (s, Some(key.as_str())),
                None => (key.as_str(), None),
            };
            if space != "eip155" {
                push(&mut r.other, key, req);
                continue;
            }
            if let Some(c) = key_chain {
                push(&mut r.chains, c, req);
            }
            for c in body.get("chains").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                if c.starts_with("eip155:") {
                    push(&mut r.chains, c, req);
                } else {
                    push(&mut r.other, c, req);
                }
            }
            for m in body.get("methods").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                push(&mut r.methods, m, req);
            }
            for e in body.get("events").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str) {
                push(&mut r.events, e, req);
            }
        }
    }
    r.chains.sort_by_key(|(_, req)| !*req); // stable: required first, dApp order kept
    r
}

pub fn plan_session(required: &Value, optional: &Value) -> SessionPlan {
    let r = requested(required, optional);
    let mut plan = SessionPlan::default();
    for (caip, req) in &r.chains {
        let id = parse_caip2(caip);
        plan.chains.push(ChainOffer {
            caip: caip.clone(),
            id: id.unwrap_or(0),
            name: id.map(chain_name).unwrap_or_else(|| caip.clone()),
            supported: id.is_some_and(chain_allowed),
            required: *req,
        });
    }
    for (m, req) in &r.methods {
        plan.methods.push(m.clone());
        if !SUPPORTED_METHODS.contains(&m.as_str()) {
            plan.refused_methods.push(m.clone());
            if *req {
                plan.required_refused_methods.push(m.clone());
            }
        }
    }
    plan.other_namespaces = r.other.iter().map(|(s, _)| s.clone()).collect();
    let required_other: Vec<&str> = r.other.iter().filter(|(_, req)| *req).map(|(s, _)| s.as_str()).collect();
    let required_unsupported: Vec<&str> =
        plan.chains.iter().filter(|c| c.required && !c.supported).map(|c| c.name.as_str()).collect();
    plan.blocker = if !required_other.is_empty() {
        Some(format!(
            "It requires {}, which this wallet does not support (Ethereum-compatible networks only).",
            required_other.join(", ")
        ))
    } else if !required_unsupported.is_empty() {
        Some(format!("It requires {}, which your phone has no reviewed profile for.", required_unsupported.join(", ")))
    } else if !plan.chains.iter().any(|c| c.supported) {
        Some("It didn't ask for any network your phone can sign for.".into())
    } else {
        None
    };
    plan
}

/// The namespaces to approve: the selected chains (each requested by the dApp, each on the
/// allow-list, every required chain included), the supported methods plus any required ones
/// (refused per call), and accounts built from the PAIRED address.
pub fn build_namespaces(required: &Value, optional: &Value, selected: &[u64], paired: &str) -> Result<Value, String> {
    let plan = plan_session(required, optional);
    if let Some(b) = plan.blocker {
        return Err(b);
    }
    if selected.is_empty() {
        return Err("choose at least one network".into());
    }
    let mut chains: Vec<u64> = vec![];
    for &id in selected {
        if !chain_allowed(id) {
            return Err(format!("your phone has no reviewed profile for chain {id}"));
        }
        if !plan.chains.iter().any(|c| c.id == id) {
            return Err(format!("the dApp did not ask for chain {id}"));
        }
        if !chains.contains(&id) {
            chains.push(id);
        }
    }
    if let Some(missing) = plan.chains.iter().find(|c| c.required && !chains.contains(&c.id)) {
        return Err(format!("the dApp requires {}; it must be included", missing.name));
    }
    let r = requested(required, optional);
    let mut methods: Vec<String> = SUPPORTED_METHODS.iter().map(ToString::to_string).collect();
    for (m, req) in &r.methods {
        if *req && !methods.contains(m) {
            methods.push(m.clone());
        }
    }
    let mut events: Vec<String> = EVENTS.iter().map(ToString::to_string).collect();
    for (e, req) in &r.events {
        if *req && !events.contains(e) {
            events.push(e.clone());
        }
    }
    let address = verify::checksum(paired);
    Ok(json!({"eip155": {
        "chains": chains.iter().map(|c| format!("eip155:{c}")).collect::<Vec<_>>(),
        "methods": methods,
        "events": events,
        "accounts": chains.iter().map(|c| format!("eip155:{c}:{address}")).collect::<Vec<_>>(),
    }}))
}

/// Add one allow-listed chain (and the paired account on it) to approved namespaces.
pub fn add_chain(namespaces: &Value, chain: u64, paired: &str) -> Result<Value, String> {
    if !chain_allowed(chain) {
        return Err(format!("your phone has no reviewed profile for chain {chain}"));
    }
    let mut ns = namespaces.clone();
    let eip = ns.get_mut("eip155").and_then(Value::as_object_mut).ok_or("the session has no eip155 namespace")?;
    let caip = format!("eip155:{chain}");
    let account = format!("{caip}:{}", verify::checksum(paired));
    for (key, item) in [("chains", caip), ("accounts", account)] {
        let list = eip.entry(key).or_insert_with(|| json!([])).as_array_mut().ok_or("malformed namespace")?;
        if !list.iter().any(|v| v.as_str() == Some(item.as_str())) {
            list.push(Value::String(item));
        }
    }
    Ok(ns)
}

/// True when every account in the session's namespaces is the paired address.
pub fn session_matches(namespaces: &Value, paired: &str) -> bool {
    let mut any = false;
    for body in namespaces.as_object().into_iter().flat_map(|m| m.values()) {
        for acc in body.get("accounts").and_then(Value::as_array).into_iter().flatten() {
            let Some(a) = acc.as_str() else { return false };
            match a.rsplit_once(':') {
                Some((_, addr)) if addr.eq_ignore_ascii_case(paired) => any = true,
                _ => return false,
            }
        }
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wc::tests::{ME, TO};

    #[test]
    fn session_planning() {
        let req = json!({"eip155": {"chains": ["eip155:8453"], "methods": ["eth_sendTransaction", "eth_sign"], "events": ["chainChanged"]}});
        let opt = json!({"eip155": {"chains": ["eip155:1", "eip155:56"], "methods": ["personal_sign", "wallet_getCapabilities"], "events": []}});
        let p = plan_session(&req, &opt);
        assert!(p.blocker.is_none());
        assert_eq!(
            p.chains.iter().map(|c| (c.id, c.supported, c.required)).collect::<Vec<_>>(),
            vec![(8453, true, true), (1, true, false), (56, false, false)]
        );
        assert_eq!(p.required_refused_methods, vec!["eth_sign"]);
        assert!(p.refused_methods.contains(&"wallet_getCapabilities".to_string()));

        let ns = build_namespaces(&req, &opt, &[8453, 1], ME).unwrap();
        let eip = &ns["eip155"];
        assert_eq!(eip["chains"], json!(["eip155:8453", "eip155:1"]));
        assert_eq!(
            eip["accounts"],
            json!([format!("eip155:8453:{}", verify::checksum(ME)), format!("eip155:1:{}", verify::checksum(ME))])
        );
        let methods: Vec<&str> = eip["methods"].as_array().unwrap().iter().map(|m| m.as_str().unwrap()).collect();
        assert!(methods.contains(&"eth_sign"), "required method approved so the session can exist (refused per call)");
        assert!(!methods.contains(&"wallet_getCapabilities"), "optional unsupported methods are not approved");
        assert!(build_namespaces(&req, &opt, &[1], ME).unwrap_err().contains("requires"), "required chain missing");
        assert!(build_namespaces(&req, &opt, &[8453, 56], ME).is_err(), "not on the allow-list");
        assert!(build_namespaces(&req, &opt, &[8453, 10], ME).is_err(), "not requested");
        assert!(build_namespaces(&req, &opt, &[], ME).is_err());

        // chain-specific namespace key
        let p2 = plan_session(&json!({"eip155:10": {"methods": ["personal_sign"], "events": []}}), &json!({}));
        assert_eq!(p2.chains[0].id, 10);
        // required unsupported chain / non-EVM namespace block approval
        assert!(plan_session(&json!({"eip155": {"chains": ["eip155:56"], "methods": [], "events": []}}), &json!({}))
            .blocker
            .is_some());
        assert!(plan_session(
            &json!({"solana": {"chains": ["solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp"], "methods": [], "events": []}}),
            &opt
        )
        .blocker
        .is_some());
        assert!(plan_session(&json!({}), &json!({"solana": {"chains": ["solana:x"], "methods": [], "events": []}}))
            .blocker
            .is_some());
    }

    #[test]
    fn adding_a_chain_and_matching_sessions() {
        let ns = build_namespaces(
            &json!({}),
            &json!({"eip155": {"chains": ["eip155:8453"], "methods": [], "events": []}}),
            &[8453],
            ME,
        )
        .unwrap();
        let more = add_chain(&ns, 10, ME).unwrap();
        assert_eq!(more["eip155"]["chains"], json!(["eip155:8453", "eip155:10"]));
        assert_eq!(add_chain(&more, 10, ME).unwrap(), more, "idempotent");
        assert!(add_chain(&ns, 56, ME).is_err());
        assert!(session_matches(&more, ME));
        assert!(!session_matches(&more, TO));
        assert!(!session_matches(&json!({}), ME));
    }
}
