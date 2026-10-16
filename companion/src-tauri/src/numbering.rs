//! "Find accounts from another wallet": which account numbering holds the user's funds.
//!
//! Two wallets can read the same recovery phrase yet number accounts differently: Standard
//! (MetaMask, Trezor, Phone Vault's default) is m/44'/60'/0'/0/i, Ledger Live is m/44'/60'/i'/0/0.
//! Account 1 is the same under both. After pairing, the Mac asks the phone for the first
//! `SCAN_COUNT` public addresses under each numbering (USB `listAddresses`; the user approves each
//! on the phone), checks them strictly, reads balances from the user's own nodes (native coin and
//! the built-in token list on every supported chain; no other endpoint), and recommends switching
//! the phone's numbering when the funds are only under the other one.
//!
//! The phone decides: the Mac never changes the numbering and never assumes it changed. The
//! numbering in use is whatever the phone's getAddress reports (`scheme`, absent = Standard).
//! Everything the phone returns is untrusted until checked: exact fields, exactly the requested
//! number of distinct EIP-55 addresses, the requested numbering, and Account 1 (shared by both
//! numberings) equal to an address paired on this Mac.

use crate::{aoa, blocking, chains, eth, pairing, tokens, verify, CmdResult};
use serde::Serialize;
use serde_json::{json, Value};
use std::time::Duration;

/// Accounts read per numbering.
pub const SCAN_COUNT: usize = 5;
/// The phone waits for the user to approve sharing.
const PHONE_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Scheme {
    Standard,
    LedgerLive,
}

impl Scheme {
    pub fn wire(self) -> &'static str {
        match self {
            Scheme::Standard => "standard",
            Scheme::LedgerLive => "ledger-live",
        }
    }
    /// getAddress's optional `scheme`: absent is Standard, only "ledger-live" may be present.
    pub fn from_get_address(field: Option<&Value>) -> Result<Scheme, String> {
        match field {
            None => Ok(Scheme::Standard),
            Some(v) if v.as_str() == Some("ledger-live") => Ok(Scheme::LedgerLive),
            Some(_) => Err("malformed account numbering".into()),
        }
    }
}

/// `{"id","method":"listAddresses","scheme","count"}`, every value a string.
pub fn list_request(id: &str, scheme: Scheme, count: usize) -> Value {
    json!({"id": id, "method": "listAddresses", "scheme": scheme.wire(), "count": count.to_string()})
}

/// Strict parse of a listAddresses answer. `Ok(None)`: the user declined on the phone. `Ok(Some)`:
/// exactly the requested number of distinct addresses (lowercase), Account 1 first.
pub fn parse_list_response(request: &Value, response: &Value) -> Result<Option<Vec<String>>, String> {
    let obj = response.as_object().ok_or("malformed response")?;
    if obj.get("id") != request.get("id") {
        return Err("the phone's answer is for a different request".into());
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    match obj.get("status").and_then(Value::as_str) {
        Some("error") if keys == ["error", "id", "status"] => {
            return Err(format!("phone: {}", obj["error"].as_str().unwrap_or("error")));
        }
        Some("rejected") if keys == ["id", "status"] => return Ok(None),
        Some("ok") if keys == ["addresses", "id", "scheme", "status"] => {}
        _ => return Err("malformed address list from the phone".into()),
    }
    if obj["scheme"] != request["scheme"] {
        return Err("the phone listed addresses under another account numbering".into());
    }
    let wanted: usize = request["count"].as_str().and_then(|c| c.parse().ok()).ok_or("bad request count")?;
    let list = obj["addresses"].as_str().ok_or("malformed address list from the phone")?;
    let mut out = Vec::with_capacity(wanted);
    for a in list.split(',') {
        // The phone sends EIP-55 casing: anything else is not what it sends, so it is refused.
        let a = verify::parse_address(a, verify::Case::Checksummed)
            .map_err(|_| "the phone sent an address that is not a valid checksummed address".to_string())?;
        if out.contains(&a) {
            return Err("the phone sent the same address twice".into());
        }
        out.push(a);
    }
    if out.len() != wanted {
        return Err(format!("the phone sent {} addresses; {wanted} were asked for", out.len()));
    }
    Ok(Some(out))
}

/// Account 1 is the same address under both numberings, and it must be an address paired on this
/// Mac (the pairing pin): otherwise the lists belong to another wallet and nothing is said about them.
pub fn check_pin(standard: &[String], ledger: &[String], paired: &pairing::Pairings) -> Result<(), String> {
    let (Some(s0), Some(l0)) = (standard.first(), ledger.first()) else {
        return Err("the phone sent no addresses".into());
    };
    if s0 != l0 {
        return Err("the phone's Account 1 differs between the two numberings; it must be the same address".into());
    }
    match paired.find(s0) {
        Some(p) if p.wallet.as_deref() != Some("passphrase") => Ok(()),
        _ => Err(format!(
            "Account 1 on the phone ({}) is not paired with this Mac, so these addresses may belong to another wallet. Pair Account 1 first, then try again.",
            verify::checksum(s0)
        )),
    }
}

/// What the scan concludes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Advice {
    /// Funds only on Ledger Live accounts 2+, phone on Standard.
    SwitchToLedgerLive,
    /// Funds only on Standard accounts 2+, phone on Ledger Live.
    SwitchToStandard,
    /// Funds only on Ledger Live accounts 2+, phone already on Ledger Live.
    AlreadyLedgerLive,
    /// Funds only on Standard accounts 2+, phone already on Standard.
    AlreadyStandard,
    /// Funds on accounts 2+ under both numberings.
    Both,
    /// Only Account 1 (shared by both) holds funds.
    OnlyAccount1,
    /// Nothing found.
    NoFunds,
}

/// Account 1 (index 0) is shared, so only accounts 2+ tell the numberings apart.
pub fn advise(current: Scheme, standard_funded: &[bool], ledger_funded: &[bool]) -> Advice {
    let extra = |f: &[bool]| f.iter().skip(1).any(|x| *x);
    match (extra(standard_funded), extra(ledger_funded)) {
        (false, true) if current == Scheme::LedgerLive => Advice::AlreadyLedgerLive,
        (false, true) => Advice::SwitchToLedgerLive,
        (true, false) if current == Scheme::Standard => Advice::AlreadyStandard,
        (true, false) => Advice::SwitchToStandard,
        (true, true) => Advice::Both,
        (false, false) if standard_funded.first() == Some(&true) || ledger_funded.first() == Some(&true) => {
            Advice::OnlyAccount1
        }
        (false, false) => Advice::NoFunds,
    }
}

/// The sentence the Mac shows. `complete` false adds that some balances could not be read.
pub fn message(advice: Advice, complete: bool) -> String {
    let m = match advice {
        Advice::SwitchToLedgerLive => "Your funds are on Ledger Live accounts. Switch account numbering on your phone: Settings → Accounts → Account numbering.",
        Advice::SwitchToStandard => "Your funds are on Standard accounts. Switch account numbering on your phone back to Standard: Settings → Accounts → Account numbering.",
        Advice::AlreadyLedgerLive => "Your funds are on Ledger Live accounts, and your phone already uses Ledger Live account numbering. Nothing to change.",
        Advice::AlreadyStandard => "Your funds are on Standard accounts, which your phone already uses. Nothing to change.",
        Advice::Both => "There are funds under both numberings. Your phone shows one numbering at a time: switch it to reach the other accounts (Settings → Accounts → Account numbering).",
        Advice::OnlyAccount1 => "Only Account 1 holds funds, and it is the same under both numberings. Nothing to change.",
        Advice::NoFunds => "No funds found on the first 5 accounts under either numbering.",
    };
    if complete {
        m.to_string()
    } else {
        format!("{m} Some balances could not be read from your nodes, so this may be incomplete.")
    }
}

// ---------------------------------------------------------------- balances (the user's own nodes)

#[derive(Serialize, Clone, Debug, PartialEq)]
pub struct Holding {
    chain_id: u64,
    network: &'static str,
    symbol: String,
    amount: String,
}

#[derive(Serialize, Clone, Debug)]
pub struct AccountFunds {
    /// 1-based, as the phone names it.
    account: usize,
    path: String,
    address: String,
    holdings: Vec<Holding>,
}

#[derive(Serialize, Debug)]
pub struct ScanReport {
    /// The numbering the phone reported in getAddress just now.
    current: Scheme,
    standard: Vec<AccountFunds>,
    ledger_live: Vec<AccountFunds>,
    advice: Advice,
    message: String,
    complete: bool,
    /// Networks whose node could not be read (display).
    errors: Vec<String>,
}

pub fn path(scheme: Scheme, index: usize) -> String {
    match scheme {
        Scheme::Standard => format!("m/44'/60'/0'/0/{index}"),
        Scheme::LedgerLive => format!("m/44'/60'/{index}'/0/0"),
    }
}

/// Per address (in order), its non-zero balances on one chain; or why the node could not be read.
type ChainResult = Result<Vec<Vec<Holding>>, String>;

/// Every non-zero balance of `addresses` on one chain, or why the node could not be read.
fn chain_holdings(chain: &chains::Chain, addresses: &[String]) -> ChainResult {
    let url = crate::watcher::rpc_for(chain.id).ok_or("no node")?;
    let rpc = eth::Rpc::new(&url)?;
    let node_chain = rpc.chain_id()?;
    if node_chain != u128::from(chain.id) {
        return Err(format!("the node for {} is on chain {node_chain}", chain.watch_name));
    }
    let listed: Vec<&tokens::Token> = tokens::list()?.iter().filter(|t| t.chain_id == chain.id).collect();
    let mut out = Vec::with_capacity(addresses.len());
    for a in addresses {
        let mut h = Vec::new();
        let native = rpc.balance(a)?;
        if native > 0 {
            h.push(Holding {
                chain_id: chain.id,
                network: chain.watch_name,
                symbol: chain.symbol.into(),
                amount: eth::format_eth(native),
            });
        }
        let data = tokens::balance_of_calldata(a)?;
        for t in &listed {
            let raw = tokens::parse_balance_word(&rpc.eth_call(&t.address, &data)?)?;
            if raw > 0 {
                h.push(Holding {
                    chain_id: chain.id,
                    network: chain.watch_name,
                    symbol: t.symbol.clone(),
                    amount: tokens::format_units(raw, t.decimals),
                });
            }
        }
        out.push(h);
    }
    Ok(out)
}

/// One getAddress + two listAddresses on the phone (one turn, behind the genuine check).
fn ask_phone_for_lists() -> Result<(Scheme, Vec<String>, Vec<String>), String> {
    let _turn = aoa::take_turn(|| {}, || false).map_err(|e| e.to_string())?;
    crate::attest::require_genuine().map_err(|m| m.trim_start_matches("attestation:").trim().to_string())?;
    let mut session = aoa::Session::connect().map_err(|e| e.to_string())?;
    let get = json!({"id": uuid::Uuid::new_v4().to_string(), "method": "getAddress"});
    let answer = session.exchange(&get, Duration::from_secs(30)).map_err(|e| e.to_string())?;
    let phone = crate::parse_address_response(&get, &answer)?;
    if phone.wallet.as_deref() == Some("passphrase") {
        return Err(
            "A passphrase wallet is open on the phone. Close it (☰ → Passphrase wallet), then try again.".into()
        );
    }
    let mut lists = Vec::with_capacity(2);
    for scheme in [Scheme::Standard, Scheme::LedgerLive] {
        let request = list_request(&uuid::Uuid::new_v4().to_string(), scheme, SCAN_COUNT);
        let response = session.exchange(&request, PHONE_TIMEOUT).map_err(|e| e.to_string())?;
        match parse_list_response(&request, &response)? {
            Some(list) => lists.push(list),
            None => return Err("You chose not to share the addresses on the phone. Nothing was checked.".into()),
        }
    }
    let ledger = lists.pop().unwrap_or_default();
    let standard = lists.pop().unwrap_or_default();
    Ok((phone.scheme, standard, ledger))
}

/// Settings → Phone → "Find accounts from another wallet". Needs a paired Account 1.
#[tauri::command]
pub(crate) async fn numbering_scan() -> CmdResult<ScanReport> {
    blocking(|| {
        let paired = pairing::list()?;
        if paired.accounts.is_empty() {
            return Err(pairing::NOT_PAIRED.into());
        }
        let (current, standard, ledger) = ask_phone_for_lists()?;
        check_pin(&standard, &ledger, &paired)?;
        // Account 1 is shared: read each distinct address once.
        let mut unique: Vec<String> = standard.clone();
        unique.extend(ledger.iter().skip(1).cloned());
        let per_chain: Vec<(&chains::Chain, ChainResult)> = std::thread::scope(|s| {
            let handles: Vec<_> = chains::CHAINS.iter().map(|c| (c, s.spawn(|| chain_holdings(c, &unique)))).collect();
            handles
                .into_iter()
                .map(|(c, h)| (c, h.join().unwrap_or_else(|_| Err("balance check failed".into()))))
                .collect()
        });
        let mut holdings: Vec<Vec<Holding>> = vec![Vec::new(); unique.len()];
        let mut errors = Vec::new();
        for (chain, result) in per_chain {
            match result {
                Ok(rows) => {
                    for (i, h) in rows.into_iter().enumerate() {
                        holdings[i].extend(h);
                    }
                }
                Err(e) => errors.push(format!("{}: {e}", chain.watch_name)),
            }
        }
        let index_of = |a: &String| unique.iter().position(|u| u == a).unwrap_or(0);
        let view = |scheme: Scheme, list: &[String]| -> Vec<AccountFunds> {
            list.iter()
                .enumerate()
                .map(|(i, a)| AccountFunds {
                    account: i + 1,
                    path: path(scheme, i),
                    address: verify::checksum(a),
                    holdings: holdings[index_of(a)].clone(),
                })
                .collect()
        };
        let std_view = view(Scheme::Standard, &standard);
        let ll_view = view(Scheme::LedgerLive, &ledger);
        let funded = |v: &[AccountFunds]| v.iter().map(|a| !a.holdings.is_empty()).collect::<Vec<bool>>();
        let advice = advise(current, &funded(&std_view), &funded(&ll_view));
        let complete = errors.is_empty();
        Ok(ScanReport {
            current,
            standard: std_view,
            ledger_live: ll_view,
            advice,
            message: message(advice, complete),
            complete,
            errors,
        })
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    // "abandon ×11 about": Standard m/44'/60'/0'/0/i and Ledger Live m/44'/60'/i'/0/0 (bip_utils
    // 2.9.3; the phone's AccountNumberingTest cross-checks them with web3j).
    const STD: [&str; 3] = [
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "0x6Fac4D18c912343BF86fa7049364Dd4E424Ab9C0",
        "0xb6716976A3ebe8D39aCEB04372f22Ff8e6802D7A",
    ];
    const LL: [&str; 3] = [
        "0x9858EfFD232B4033E47d90003D41EC34EcaEda94",
        "0x78839F6054d7ed13918bAe0473BA31b1Ca9D7265",
        "0x07B5FdfEB4E11826D233403Fe8Db0611CCF4c231",
    ];

    fn ok(req: &Value, list: &[&str]) -> Value {
        json!({"id": req["id"], "status": "ok", "scheme": req["scheme"], "addresses": list.join(",")})
    }
    fn lower(list: &[&str]) -> Vec<String> {
        list.iter().map(|a| a.to_ascii_lowercase()).collect()
    }

    #[test]
    fn request_is_schema_exact() {
        let r = list_request("l-1", Scheme::LedgerLive, 5);
        assert_eq!(r, json!({"id": "l-1", "method": "listAddresses", "scheme": "ledger-live", "count": "5"}));
        assert_eq!(list_request("x", Scheme::Standard, 1)["scheme"], "standard");
    }

    #[test]
    fn accepts_exact_answers_and_declines() {
        let req = list_request("l", Scheme::LedgerLive, 3);
        assert_eq!(parse_list_response(&req, &ok(&req, &LL)).unwrap(), Some(lower(&LL)));
        assert_eq!(parse_list_response(&req, &json!({"id": "l", "status": "rejected"})).unwrap(), None);
        let e = parse_list_response(&req, &json!({"id": "l", "status": "error", "error": "Wallet is not ready"}));
        assert_eq!(e.unwrap_err(), "phone: Wallet is not ready");
    }

    #[test]
    fn refuses_every_drift() {
        let req = list_request("l", Scheme::LedgerLive, 3);
        let good = ok(&req, &LL);
        let with = |k: &str, v: Value| {
            let mut x = good.clone();
            x[k] = v;
            x
        };
        let lowercase = LL.iter().map(|a| a.to_ascii_lowercase()).collect::<Vec<_>>().join(",");
        let bad = [
            with("id", json!("m")),
            with("scheme", json!("standard")),
            with("extra", json!("1")),
            with("status", json!("approved")),
            with("addresses", json!(LL[..2].join(","))),
            with("addresses", json!([LL[0], LL[1], LL[2]])),
            with("addresses", json!(format!("{},{}", LL.join(","), STD[1]))),
            with("addresses", json!(lowercase)),
            with("addresses", json!(format!("{},{},{}", LL[0], LL[1], LL[1]))),
            with("addresses", json!(format!(" {}", LL.join(",")))),
            with("addresses", json!(format!("{},", LL.join(",")))),
            with("addresses", json!("0x12,0x34,0x56")),
            json!({"id": "l", "status": "rejected", "why": "x"}),
            json!({"id": "l", "status": "error"}),
            json!(["not", "an", "object"]),
        ];
        for b in bad {
            assert!(parse_list_response(&req, &b).is_err(), "accepted {b}");
        }
    }

    fn pairings(addr: &str, wallet: &str) -> pairing::Pairings {
        pairing::Pairings {
            version: 2,
            active: Some(addr.to_ascii_lowercase()),
            accounts: vec![pairing::Paired {
                address: addr.to_ascii_lowercase(),
                label: "Account 1".into(),
                wallet: Some(wallet.into()),
                account: Some(1),
                paired_at: String::new(),
            }],
        }
    }

    #[test]
    fn account_1_must_be_shared_and_paired() {
        let p = pairings(STD[0], "standard");
        check_pin(&lower(&STD), &lower(&LL), &p).unwrap();
        // Account 1 differs between the numberings: refused
        let mut other = lower(&LL);
        other[0] = STD[1].to_ascii_lowercase();
        assert!(check_pin(&lower(&STD), &other, &p).is_err());
        // a wallet this Mac has not paired: refused, and the message names the address
        let unpaired = pairings(STD[1], "standard");
        assert!(check_pin(&lower(&STD), &lower(&LL), &unpaired).unwrap_err().contains(STD[0]));
        // a passphrase pairing of the same address does not count as the standard wallet
        assert!(check_pin(&lower(&STD), &lower(&LL), &pairings(STD[0], "passphrase")).is_err());
        assert!(check_pin(&[], &lower(&LL), &p).is_err());
    }

    #[test]
    fn get_address_scheme_is_strict() {
        assert_eq!(Scheme::from_get_address(None).unwrap(), Scheme::Standard);
        assert_eq!(Scheme::from_get_address(Some(&json!("ledger-live"))).unwrap(), Scheme::LedgerLive);
        for bad in [json!("standard"), json!("ledger"), json!(1), json!(null)] {
            assert!(Scheme::from_get_address(Some(&bad)).is_err(), "accepted {bad}");
        }
    }

    #[test]
    fn recommendation_logic() {
        let t = true;
        let f = false;
        use Advice::*;
        use Scheme::*;
        // funds only beyond Account 1 under Ledger Live
        assert_eq!(advise(Standard, &[f, f, f], &[f, t, f]), SwitchToLedgerLive);
        assert_eq!(advise(Standard, &[t, f, f], &[t, f, t]), SwitchToLedgerLive, "Account 1 is shared: ignored");
        assert_eq!(advise(LedgerLive, &[f, f, f], &[f, t, f]), AlreadyLedgerLive);
        // only under Standard
        assert_eq!(advise(Standard, &[f, t, f], &[f, f, f]), AlreadyStandard);
        assert_eq!(advise(LedgerLive, &[f, f, t], &[t, f, f]), SwitchToStandard);
        // both, only Account 1, nothing
        assert_eq!(advise(Standard, &[f, t, f], &[f, f, t]), Both);
        assert_eq!(advise(Standard, &[t, f, f], &[t, f, f]), OnlyAccount1);
        assert_eq!(advise(LedgerLive, &[f, f, f], &[f, f, f]), NoFunds);
        assert_eq!(
            message(SwitchToLedgerLive, true),
            "Your funds are on Ledger Live accounts. Switch account numbering on your phone: Settings → Accounts → Account numbering."
        );
        assert!(message(NoFunds, false).ends_with("so this may be incomplete."));
    }

    #[test]
    fn paths_match_the_phone() {
        assert_eq!(path(Scheme::Standard, 1), "m/44'/60'/0'/0/1");
        assert_eq!(path(Scheme::LedgerLive, 1), "m/44'/60'/1'/0/0");
        assert_eq!(path(Scheme::LedgerLive, 0), path(Scheme::Standard, 0), "Account 1 is the same path");
    }
}

/// Adversarial audit tests (account numbering / listAddresses).
#[cfg(test)]
mod audit_tests {
    use super::*;

    const S0: &str = "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

    /// Hostile phone answers never panic and are refused (multi-byte UTF-8, NULs, huge lists, odd types).
    #[test]
    fn hostile_list_answers_refused_without_panic() {
        let req = list_request("l", Scheme::Standard, 2);
        let many = std::iter::repeat_n(S0, 10_000).collect::<Vec<_>>().join(",");
        let bad = [
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": "0x9858EfFD232B4033E47d90003D41EC34EcaEda9é,0x00"}),
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": "0xé858EfFD232B4033E47d90003D41EC34EcaEda94"}),
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": format!("{S0}\u{0000},{S0}")}),
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": many}),
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": ""}),
            json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": null}),
            json!({"id": "l", "status": "ok", "scheme": null, "addresses": S0}),
            json!({"id": "l", "status": "error", "error": 5}),
            json!({"id": null, "status": "rejected"}),
            json!(null),
        ];
        for b in bad {
            let r = std::panic::catch_unwind(|| parse_list_response(&req, &b));
            assert!(r.as_ref().is_ok_and(|x| x.is_err()), "panicked on or accepted {b}");
        }
        // a request whose count is not a string cannot be satisfied (internal misuse is caught)
        let weird = json!({"id": "l", "method": "listAddresses", "scheme": "standard", "count": 2});
        assert!(parse_list_response(
            &weird,
            &json!({"id": "l", "status": "ok", "scheme": "standard", "addresses": S0})
        )
        .is_err());
    }

    /// The pin check accepts a legacy pairing with no wallet kind for Account 1. Sound: listAddresses
    /// only ever lists the standard wallet, whose Account 1 cannot equal a passphrase wallet's address.
    #[test]
    fn pin_accepts_legacy_pairing_without_wallet_kind() {
        let p = pairing::Pairings {
            version: 2,
            active: Some(S0.to_ascii_lowercase()),
            accounts: vec![pairing::Paired {
                address: S0.to_ascii_lowercase(),
                label: "Account 1".into(),
                wallet: None,
                account: None,
                paired_at: String::new(),
            }],
        };
        let s = vec![S0.to_ascii_lowercase()];
        assert!(check_pin(&s, &s, &p).is_ok());
    }

    /// When the user clears the "Name on this Mac" field, the default label still tells Ledger Live
    /// Account 2 and Standard Account 2 (different addresses) apart; Account 1 is the same address.
    #[test]
    fn default_label_names_the_numbering() {
        let empty = pairing::Pairings { version: 2, active: None, accounts: vec![] };
        let l = |n, w, s| pairing::default_label(&empty, Some(n), Some(w), s);
        assert_eq!(l(2, "standard", Scheme::Standard), "Account 2");
        assert_eq!(l(2, "standard", Scheme::LedgerLive), "Account 2 · Ledger Live");
        assert_eq!(l(1, "standard", Scheme::LedgerLive), "Account 1");
        assert_eq!(l(3, "passphrase", Scheme::LedgerLive), "Account 3 · passphrase · Ledger Live");
        // and it is what a pairing without a typed name is stored as
        let d = std::env::temp_dir().join(format!("pv-numbering-label-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&d).unwrap();
        let p = pairing::add_numbered_in(&d, S0, Some(""), Some("standard"), Some(2), Scheme::LedgerLive).unwrap();
        assert_eq!(p.find(&S0.to_ascii_lowercase()).unwrap().label, "Account 2 · Ledger Live");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Advice is computed only from Account 2+ funding as reported by the nodes; a hostile node that
    /// reports a balance on Ledger Live Account 2+ flips the advice to "switch" (display only).
    #[test]
    fn advice_trusts_node_balances() {
        assert_eq!(advise(Scheme::Standard, &[true, false], &[true, true]), Advice::SwitchToLedgerLive);
        assert!(message(Advice::NoFunds, false).starts_with("No funds found"));
    }
}
