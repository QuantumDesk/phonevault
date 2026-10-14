//! Watch-only Bitcoin accounts: what the phone shares (master fingerprint, account path, account
//! xpub, descriptor), checked strictly, and everything derived from it on this Mac (addresses,
//! scripts, BIP-32 origins for PSBTs, the Sparrow export). No private key is ever here.
//!
//! Supported: BIP-84 native SegWit (`wpkh`, P2WPKH, bc1q…) and BIP-86 Taproot key-path (`tr`,
//! P2TR, bc1p…), accounts 1…20 (= account index 0…19), on Bitcoin, Testnet and Signet.

use bitcoin::bip32::{ChildNumber, DerivationPath, Fingerprint, Xpub};
use bitcoin::key::{CompressedPublicKey, Secp256k1, Verification};
use bitcoin::secp256k1::XOnlyPublicKey;
use bitcoin::{Address, Network, NetworkKind, ScriptBuf};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

/// The phone's names for networks and script types (the USB contract).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Net { Bitcoin, Testnet, Signet }

impl Net {
    pub fn parse(s: &str) -> Result<Net, String> {
        match s { "bitcoin" => Ok(Net::Bitcoin), "testnet" => Ok(Net::Testnet), "signet" => Ok(Net::Signet), _ => Err(format!("unknown Bitcoin network {s:?}")) }
    }
    pub fn wire(self) -> &'static str { match self { Net::Bitcoin => "bitcoin", Net::Testnet => "testnet", Net::Signet => "signet" } }
    pub fn name(self) -> &'static str { match self { Net::Bitcoin => "Bitcoin", Net::Testnet => "Bitcoin Testnet", Net::Signet => "Bitcoin Signet" } }
    pub fn network(self) -> Network {
        // Testnet3 and Testnet4 share addresses (tb1…), tpubs and coin type 1; Testnet4 is the default server.
        match self { Net::Bitcoin => Network::Bitcoin, Net::Testnet => Network::Testnet, Net::Signet => Network::Signet }
    }
    /// BIP-44 coin type: 0 on Bitcoin, 1 on every test network.
    pub fn coin_type(self) -> u32 { if self == Net::Bitcoin { 0 } else { 1 } }
    pub fn kind(self) -> NetworkKind { if self == Net::Bitcoin { NetworkKind::Main } else { NetworkKind::Test } }
    pub fn unit(self) -> &'static str { match self { Net::Bitcoin => "BTC", Net::Testnet => "tBTC", Net::Signet => "sBTC" } }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Kind { P2wpkh, P2tr }

impl Kind {
    pub fn parse(s: &str) -> Result<Kind, String> {
        match s { "p2wpkh" => Ok(Kind::P2wpkh), "p2tr" => Ok(Kind::P2tr), _ => Err(format!("unknown address type {s:?}")) }
    }
    pub fn wire(self) -> &'static str { match self { Kind::P2wpkh => "p2wpkh", Kind::P2tr => "p2tr" } }
    pub fn purpose(self) -> u32 { match self { Kind::P2wpkh => 84, Kind::P2tr => 86 } }
    pub fn name(self) -> &'static str { match self { Kind::P2wpkh => "Native SegWit", Kind::P2tr => "Taproot" } }
    fn desc_fn(self) -> &'static str { match self { Kind::P2wpkh => "wpkh", Kind::P2tr => "tr" } }
    /// Input weight beyond the 41 non-witness bytes: witness item count + signature (+ pubkey).
    /// P2WPKH: 1 + (1 + 72) + (1 + 33) = 108 WU (72 = the longest DER signature + sighash byte).
    /// P2TR key path: 1 + (1 + 64) = 66 WU (SIGHASH_DEFAULT: no sighash byte).
    pub fn input_witness_weight(self) -> u64 { match self { Kind::P2wpkh => 108, Kind::P2tr => 66 } }
    /// scriptPubKey length of an output of this type (P2WPKH 22, P2TR 34).
    pub fn script_len(self) -> u64 { match self { Kind::P2wpkh => 22, Kind::P2tr => 34 } }
}

/// One watch-only account as the phone shared it, validated.
#[derive(Clone, Debug, PartialEq)]
pub struct Account {
    pub net: Net,
    pub kind: Kind,
    /// 1-based, as on the phone ("Account 1" = index 0')
    pub number: u32,
    pub fingerprint: Fingerprint,
    pub xpub: Xpub,
}

pub const MAX_ACCOUNT: u32 = 20;
/// Highest address index the Mac will ever derive or ask the phone to show.
pub const MAX_INDEX: u32 = 1_000_000;

impl Account {
    /// m/purpose'/coin'/(number-1)'
    pub fn path(&self) -> DerivationPath { account_path(self.kind, self.net, self.number) }
    pub fn id(&self) -> String { format!("{}-{}-{}-{}", self.fingerprint, self.net.wire(), self.kind.wire(), self.number) }

    /// The descriptor with both chains (`<0;1>`), `h` for hardened, and its BIP-380 checksum.
    pub fn descriptor(&self) -> String { with_checksum(&self.descriptor_body("<0;1>")) }
    /// Single-chain descriptors (receive = 0, change = 1) for wallets without multipath support.
    pub fn chain_descriptor(&self, chain: u32) -> String { with_checksum(&self.descriptor_body(&chain.to_string())) }
    fn descriptor_body(&self, chains: &str) -> String {
        format!("{}([{}/{}h/{}h/{}h]{}/{}/*)", self.kind.desc_fn(), self.fingerprint, self.kind.purpose(), self.net.coin_type(), self.number - 1, self.xpub, chains)
    }

    fn child_pub(&self, chain: u32, index: u32) -> Result<bitcoin::secp256k1::PublicKey, String> {
        if chain > 1 { return Err("chain must be 0 (receive) or 1 (change)".into()); }
        if index > MAX_INDEX { return Err("address index out of range".into()); }
        let secp = Secp256k1::verification_only();
        let path = [ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?, ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?];
        Ok(self.xpub.derive_pub(&secp, &path).map_err(|e| e.to_string())?.public_key)
    }

    /// Everything about one address of this account.
    pub fn derive(&self, chain: u32, index: u32) -> Result<Derived, String> {
        let secp = Secp256k1::verification_only();
        let pk = self.child_pub(chain, index)?;
        let mut origin = self.path();
        origin = origin.extend([ChildNumber::from_normal_idx(chain).map_err(|e| e.to_string())?, ChildNumber::from_normal_idx(index).map_err(|e| e.to_string())?]);
        let (address, internal) = match self.kind {
            Kind::P2wpkh => (Address::p2wpkh(&CompressedPublicKey(pk), self.net.network()), None),
            Kind::P2tr => { let x = XOnlyPublicKey::from(pk); (Address::p2tr(&secp, x, None, self.net.network()), Some(x)) }
        };
        Ok(Derived { chain, index, script: address.script_pubkey(), address, pubkey: pk, internal_key: internal, origin })
    }

    /// The Taproot output key for an internal key (BIP-86: no script tree).
    pub fn output_key<C: Verification>(secp: &Secp256k1<C>, internal: XOnlyPublicKey) -> XOnlyPublicKey {
        use bitcoin::key::TapTweak;
        internal.tap_tweak(secp, None).0.to_x_only_public_key()
    }
}

/// One derived address and what a PSBT needs to say about it.
#[derive(Clone, Debug)]
pub struct Derived {
    pub chain: u32,
    pub index: u32,
    pub address: Address,
    pub script: ScriptBuf,
    pub pubkey: bitcoin::secp256k1::PublicKey,
    /// P2TR only: the BIP-86 internal (untweaked) key
    pub internal_key: Option<XOnlyPublicKey>,
    /// full path from the master key: m/purpose'/coin'/account'/chain/index
    pub origin: DerivationPath,
}

pub fn account_path(kind: Kind, net: Net, number: u32) -> DerivationPath {
    DerivationPath::from(vec![
        ChildNumber::Hardened { index: kind.purpose() },
        ChildNumber::Hardened { index: net.coin_type() },
        ChildNumber::Hardened { index: number.saturating_sub(1) },
    ])
}

// ---------------------------------------------------------------- BIP-380 descriptor checksum

const INPUT_CHARSET: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";

fn polymod(c: u64, v: u64) -> u64 {
    let c0 = c >> 35;
    let mut c = ((c & 0x7_ffff_ffff) << 5) ^ v;
    for (i, g) in [0xf5dee51989u64, 0xa9fdca3312, 0x1bab10e32d, 0x3706b1677a, 0x644d626ffd].iter().enumerate() {
        if (c0 >> i) & 1 == 1 { c ^= g; }
    }
    c
}

/// The 8-character checksum of a descriptor (without `#…`). None for characters outside the set.
pub fn descriptor_checksum(desc: &str) -> Option<String> {
    let (mut c, mut cls, mut count) = (1u64, 0u64, 0);
    for ch in desc.chars() {
        let pos = INPUT_CHARSET.find(ch)? as u64;
        c = polymod(c, pos & 31);
        cls = cls * 3 + (pos >> 5);
        count += 1;
        if count == 3 { c = polymod(c, cls); cls = 0; count = 0; }
    }
    if count > 0 { c = polymod(c, cls); }
    for _ in 0..8 { c = polymod(c, 0); }
    c ^= 1;
    Some((0..8).map(|j| CHECKSUM_CHARSET[((c >> (5 * (7 - j))) & 31) as usize] as char).collect())
}

pub fn with_checksum(desc: &str) -> String { format!("{desc}#{}", descriptor_checksum(desc).unwrap_or_default()) }

// ---------------------------------------------------------------- btcGetAccount answer

/// Strict check of a btcGetAccount answer for the account that was asked for. Everything the
/// phone says must agree with everything else: the path is the one requested, the xpub is at
/// depth 3 with the requested hardened account index and the network's version bytes, and the
/// descriptor is exactly the one this Mac builds from (fingerprint, path, xpub), checksum included.
pub fn parse_account_response(request: &Value, response: &Value, net: Net, kind: Kind, number: u32) -> Result<Account, String> {
    let obj = response.as_object().ok_or("malformed response")?;
    if obj.get("id") != request.get("id") { return Err("the phone's answer is for a different request".into()); }
    match obj.get("status").and_then(Value::as_str) {
        Some("ok") => {}
        Some("rejected") => return Err("you declined sharing this account on the phone".into()),
        Some("error") => return Err(format!("phone: {}", obj.get("error").and_then(Value::as_str).unwrap_or("error"))),
        _ => return Err("malformed response status".into()),
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    if keys != ["descriptor", "fingerprint", "id", "path", "status", "xpub"] { return Err("account response has unexpected fields".into()); }
    let s = |k: &str| obj[k].as_str().ok_or_else(|| format!("{k} must be a string"));
    let fp = s("fingerprint")?;
    if fp.len() != 8 || !fp.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()) { return Err("fingerprint must be 8 lowercase hex characters".into()); }
    let fingerprint = Fingerprint::from_str(fp).map_err(|e| format!("fingerprint: {e}"))?;
    let path = DerivationPath::from_str(s("path")?).map_err(|_| "malformed derivation path".to_string())?;
    if path != account_path(kind, net, number) { return Err(format!("the phone answered for path {path}, not {}", account_path(kind, net, number))); }
    let xpub = Xpub::from_str(s("xpub")?).map_err(|e| format!("xpub: {e}"))?;
    if xpub.network != net.kind() { return Err(format!("the xpub is for {:?}, not {}", xpub.network, net.name())); }
    if xpub.depth != 3 || xpub.child_number != (ChildNumber::Hardened { index: number - 1 }) { return Err("the xpub is not the account key for that path".into()); }
    let account = Account { net, kind, number, fingerprint, xpub };
    let given = s("descriptor")?;
    let (body, sum) = given.rsplit_once('#').ok_or("descriptor has no checksum")?;
    if descriptor_checksum(body).as_deref() != Some(sum) { return Err("descriptor checksum is wrong".into()); }
    if body.replace('\'', "h") != account.descriptor_body("<0;1>") { return Err("the descriptor does not match the fingerprint, path and xpub".into()); }
    Ok(account)
}

/// Strict check of a btcShowAddress answer: `{id, status:"ok", address}`.
pub fn parse_show_response(request: &Value, response: &Value) -> Result<String, String> {
    let obj = response.as_object().ok_or("malformed response")?;
    if obj.get("id") != request.get("id") { return Err("the phone's answer is for a different request".into()); }
    match obj.get("status").and_then(Value::as_str) {
        Some("ok") => {}
        Some("rejected") => return Err("closed on the phone".into()),
        Some("error") => return Err(format!("phone: {}", obj.get("error").and_then(Value::as_str).unwrap_or("error"))),
        _ => return Err("malformed response status".into()),
    }
    let mut keys: Vec<&str> = obj.keys().map(String::as_str).collect();
    keys.sort();
    if keys != ["address", "id", "status"] { return Err("address response has unexpected fields".into()); }
    let a = obj["address"].as_str().ok_or("address must be a string")?;
    if a.len() > 100 || !a.bytes().all(|b| b.is_ascii_alphanumeric()) { return Err("malformed address".into()); }
    Ok(a.to_string())
}

// ---------------------------------------------------------------- recipients

/// A recipient typed by the user, checked for this network (bech32/bech32m/base58 checksums are
/// verified by the parser; a mainnet address on testnet, or the reverse, is refused).
pub fn parse_recipient(s: &str, net: Net) -> Result<Address, String> {
    let t = s.trim();
    let t = t.strip_prefix("bitcoin:").unwrap_or(t);
    if t.contains('?') { return Err("Paste only the address, without ?amount= or other parameters".into()); }
    let unchecked = Address::from_str(t).map_err(|_| {
        // Well-formed apart from the checksum: almost always a typo in one character.
        let l = t.to_ascii_lowercase();
        let bech = ["bc1", "tb1", "bcrt1"].iter().any(|p| l.starts_with(p)) && l.len() >= 42 && l[l.find('1').unwrap_or(0) + 1..].chars().all(|c| "qpzry9x8gf2tvdw0s3jn54khce6mua7l".contains(c));
        let b58 = (25..=35).contains(&t.len()) && t.starts_with(['1', '3', 'm', 'n', '2']) && t.chars().all(|c| c.is_ascii_alphanumeric() && !"0OIl".contains(c));
        if bech || b58 { "Checksum mismatch: a character is probably wrong".to_string() } else { "Not a Bitcoin address".to_string() }
    })?;
    if !unchecked.is_valid_for_network(net.network()) {
        return Err(if net == Net::Bitcoin { "That is a test-network address, not a Bitcoin address".into() } else { format!("That address is not for {}", net.name()) });
    }
    Ok(unchecked.assume_checked())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use bitcoin::bip32::Xpriv;
    use serde_json::json;

    /// BIP-39 seed of "abandon abandon … about" (no passphrase): the BIP-84/86 test vectors' wallet.
    pub const SEED: &str = "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

    pub fn account(net: Net, kind: Kind, number: u32) -> (Account, Xpriv) {
        let secp = Secp256k1::new();
        let master = Xpriv::new_master(net.kind(), &hex::decode(SEED).unwrap()).unwrap();
        let xprv = master.derive_priv(&secp, &account_path(kind, net, number)).unwrap();
        (Account { net, kind, number, fingerprint: master.fingerprint(&secp), xpub: Xpub::from_priv(&secp, &xprv) }, master)
    }

    #[test]
    fn bip84_vectors() {
        let (a, _) = account(Net::Bitcoin, Kind::P2wpkh, 1);
        assert_eq!(a.fingerprint.to_string(), "73c5da0a");
        // BIP-84: account 0 xpub (zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs as an xpub)
        assert_eq!(a.xpub.to_string(), "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V");
        assert_eq!(a.derive(0, 0).unwrap().address.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert_eq!(a.derive(0, 1).unwrap().address.to_string(), "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g");
        assert_eq!(a.derive(1, 0).unwrap().address.to_string(), "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el");
        assert_eq!(a.derive(0, 0).unwrap().origin.to_string(), "84'/0'/0'/0/0");
    }

    #[test]
    fn bip86_vectors() {
        let (a, _) = account(Net::Bitcoin, Kind::P2tr, 1);
        assert_eq!(a.xpub.to_string(), "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ");
        assert_eq!(a.derive(0, 0).unwrap().address.to_string(), "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr");
        assert_eq!(a.derive(0, 1).unwrap().address.to_string(), "bc1p4qhjn9zdvkux4e44uhx8tc55attvtyu358kutcqkudyccelu0was9fqzwh");
        assert_eq!(a.derive(1, 0).unwrap().address.to_string(), "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7");
        // the internal key is the BIP-86 one, the output key its tweak
        let d = a.derive(0, 0).unwrap();
        assert_eq!(d.internal_key.unwrap().to_string(), "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
    }

    #[test]
    fn testnet_accounts_use_coin_type_1() {
        let (a, _) = account(Net::Testnet, Kind::P2wpkh, 1);
        assert!(a.xpub.to_string().starts_with("tpub"));
        assert_eq!(a.path().to_string(), "84'/1'/0'");
        // BIP-84 testnet vector
        assert_eq!(a.derive(0, 0).unwrap().address.to_string(), "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl");
        let (s, _) = account(Net::Signet, Kind::P2tr, 3);
        assert_eq!(s.path().to_string(), "86'/1'/2'");
        assert!(s.derive(0, 0).unwrap().address.to_string().starts_with("tb1p"));
    }

    #[test]
    fn descriptor_checksums() {
        // BIP-380 / Bitcoin Core examples
        assert_eq!(descriptor_checksum("raw(deadbeef)").unwrap(), "89f8spxm");
        assert_eq!(descriptor_checksum("addr(mkmZxiEcEd8ZqjQWVZuC6so5dFMKEFpN2j)").unwrap(), "02wpgw69");
        assert_eq!(descriptor_checksum("pkh([d34db33f/44'/0'/0']xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL/1/*)").unwrap(), "ml40v0wf");
        let (a, _) = account(Net::Bitcoin, Kind::P2wpkh, 1);
        assert!(a.descriptor().starts_with("wpkh([73c5da0a/84h/0h/0h]xpub6CatWdiZ"));
        assert!(a.descriptor().contains("/<0;1>/*)#"));
        assert!(a.chain_descriptor(1).contains("/1/*)#"));
    }

    fn answer(a: &Account) -> Value {
        json!({"id": "r1", "status": "ok", "fingerprint": a.fingerprint.to_string(), "path": format!("m/{}", a.path()), "xpub": a.xpub.to_string(), "descriptor": a.descriptor()})
    }

    #[test]
    fn account_answers_are_checked_strictly() {
        let req = json!({"id": "r1", "method": "btcGetAccount"});
        let (a, _) = account(Net::Bitcoin, Kind::P2wpkh, 1);
        assert_eq!(parse_account_response(&req, &answer(&a), Net::Bitcoin, Kind::P2wpkh, 1).unwrap(), a);
        // apostrophe form of the same descriptor is fine
        let mut ap = answer(&a);
        let body = format!("wpkh([73c5da0a/84'/0'/0']{}/<0;1>/*)", a.xpub);
        ap["descriptor"] = json!(with_checksum(&body));
        assert!(parse_account_response(&req, &ap, Net::Bitcoin, Kind::P2wpkh, 1).is_ok());
        let (other, _) = account(Net::Bitcoin, Kind::P2wpkh, 2);
        let (tr, _) = account(Net::Bitcoin, Kind::P2tr, 1);
        let (test, _) = account(Net::Testnet, Kind::P2wpkh, 1);
        let mut cases = vec![];
        let mut x = answer(&a); x["fingerprint"] = json!("73C5DA0A"); cases.push(x);
        let mut x = answer(&a); x["fingerprint"] = json!("deadbeef"); cases.push(x); // descriptor then disagrees
        let mut x = answer(&a); x["path"] = json!("m/84'/0'/1'"); cases.push(x);
        let mut x = answer(&a); x["xpub"] = json!(other.xpub.to_string()); cases.push(x); // wrong account key
        let mut x = answer(&a); x["xpub"] = json!(test.xpub.to_string()); cases.push(x); // tpub on mainnet
        let mut x = answer(&a); x["descriptor"] = json!(tr.descriptor()); cases.push(x);
        let mut x = answer(&a); let d = a.descriptor(); x["descriptor"] = json!(format!("{}xxxxxxxx", &d[..d.len() - 8])); cases.push(x);
        let mut x = answer(&a); x["extra"] = json!("1"); cases.push(x);
        let mut x = answer(&a); x["id"] = json!("r2"); cases.push(x);
        let mut x = answer(&a); x.as_object_mut().unwrap().remove("descriptor"); cases.push(x);
        for c in cases { assert!(parse_account_response(&req, &c, Net::Bitcoin, Kind::P2wpkh, 1).is_err(), "accepted {c}"); }
        // the answer must be for the account that was asked for
        assert!(parse_account_response(&req, &answer(&other), Net::Bitcoin, Kind::P2wpkh, 1).is_err());
        assert!(parse_account_response(&req, &answer(&tr), Net::Bitcoin, Kind::P2wpkh, 1).is_err());
        assert!(parse_account_response(&req, &json!({"id": "r1", "status": "rejected"}), Net::Bitcoin, Kind::P2wpkh, 1).unwrap_err().contains("declined"));
    }

    #[test]
    fn show_address_answers() {
        let req = json!({"id": "s1"});
        assert_eq!(parse_show_response(&req, &json!({"id": "s1", "status": "ok", "address": "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"})).unwrap(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");
        assert!(parse_show_response(&req, &json!({"id": "s1", "status": "ok", "address": "bc1q x"})).is_err());
        assert!(parse_show_response(&req, &json!({"id": "s1", "status": "ok", "address": "bc1q", "n": 1})).is_err());
        assert!(parse_show_response(&req, &json!({"id": "s2", "status": "ok", "address": "bc1q"})).is_err());
    }

    #[test]
    fn recipients_are_checked_for_network_and_checksum() {
        assert!(parse_recipient("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Net::Bitcoin).is_ok());
        assert!(parse_recipient("bitcoin:bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Net::Bitcoin).is_ok());
        assert!(parse_recipient(" BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU ", Net::Bitcoin).is_ok());
        assert!(parse_recipient("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", Net::Bitcoin).is_ok());
        assert!(parse_recipient("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy", Net::Bitcoin).is_ok());
        assert!(parse_recipient("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", Net::Bitcoin).is_ok());
        // one character changed: bech32 checksum fails
        assert!(parse_recipient("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv", Net::Bitcoin).unwrap_err().contains("hecksum"));
        assert!(parse_recipient("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3", Net::Bitcoin).is_err());
        // wrong network
        assert!(parse_recipient("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", Net::Bitcoin).unwrap_err().contains("test-network"));
        assert!(parse_recipient("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Net::Testnet).is_err());
        assert!(parse_recipient("tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl", Net::Signet).is_ok());
        assert!(parse_recipient("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu?amount=1", Net::Bitcoin).is_err());
        assert!(parse_recipient("0x7a3b9c1d2e4f5061728394a5b6c7d8e9f0a1b2c3", Net::Bitcoin).is_err());
    }
}
