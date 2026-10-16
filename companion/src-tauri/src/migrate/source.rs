//! What the user pastes as "the old wallet": an EVM address, a Bitcoin extended PUBLIC key
//! (xpub/ypub/zpub, tpub/upub/vpub) or a single Bitcoin address. All public. Anything that looks
//! like a secret (a recovery phrase, an extended private key, a raw or WIF private key) is refused
//! with an explanation and never stored: the assistant moves funds by having the user SEND from the
//! old wallet, it never needs to sign for it.
//!
//! SLIP-132 prefixes are only a hint of the script type: ypub = Nested SegWit (BIP-49), zpub =
//! Native SegWit (BIP-84). A plain xpub is ambiguous (Ledger Live and Trezor Suite export every
//! account as an xpub; Sparrow too for Taproot), so an xpub is scanned as every single-key type.

#![deny(clippy::indexing_slicing)]

use crate::btc::wallet::Net;
use crate::verify;
use bitcoin::address::NetworkUnchecked;
use bitcoin::bip32::Xpub;
use bitcoin::{Address, AddressType};
use serde::Serialize;

/// The longest entry accepted (an xpub is 111 characters, a Taproot address 62).
pub const MAX_INPUT: usize = 160;

/// A single-key Bitcoin script type an old wallet may have used.
#[derive(Serialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum BtcType {
    Native,
    Taproot,
    Nested,
    Legacy,
}

impl BtcType {
    pub fn name(self) -> &'static str {
        match self {
            BtcType::Native => "Native SegWit",
            BtcType::Taproot => "Taproot",
            BtcType::Nested => "Nested SegWit",
            BtcType::Legacy => "Legacy",
        }
    }
    /// What the addresses look like on Bitcoin (shown next to the name).
    pub fn looks(self) -> &'static str {
        match self {
            BtcType::Native => "bc1q…",
            BtcType::Taproot => "bc1p…",
            BtcType::Nested => "3…",
            BtcType::Legacy => "1…",
        }
    }
}

/// One validated entry.
#[derive(Serialize, Clone, Debug, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Source {
    /// An EVM account (the same address on every EVM network).
    Evm { id: String, address: String },
    /// A Bitcoin account's extended public key.
    Xpub {
        id: String,
        prefix: String,
        network: Net,
        /// the script types this key is scanned as, in order
        types: Vec<BtcType>,
        /// a remark for the UI (an ambiguous xpub, an unusual depth)
        note: Option<String>,
    },
    /// One Bitcoin address.
    BtcAddress { id: String, network: Net, btc_type: Option<BtcType> },
}

impl Source {
    /// The canonical text this entry is stored and keyed by.
    pub fn id(&self) -> &str {
        match self {
            Source::Evm { id, .. } | Source::Xpub { id, .. } | Source::BtcAddress { id, .. } => id,
        }
    }
}

/// SLIP-132 version bytes (public keys only) → network, script types, and the standard version.
const XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const TPUB: [u8; 4] = [0x04, 0x35, 0x87, 0xcf];
fn version_info(v: [u8; 4]) -> Option<(&'static str, Net, &'static [BtcType], [u8; 4])> {
    const ALL: &[BtcType] = &[BtcType::Native, BtcType::Taproot, BtcType::Legacy, BtcType::Nested];
    Some(match v {
        XPUB => ("xpub", Net::Bitcoin, ALL, XPUB),
        [0x04, 0x9d, 0x7c, 0xb2] => ("ypub", Net::Bitcoin, &[BtcType::Nested], XPUB),
        [0x04, 0xb2, 0x47, 0x46] => ("zpub", Net::Bitcoin, &[BtcType::Native], XPUB),
        // TODO(signet): test-network keys are scanned on Testnet (Testnet4); Signet keys look the same.
        TPUB => ("tpub", Net::Testnet, ALL, TPUB),
        [0x04, 0x4a, 0x52, 0x62] => ("upub", Net::Testnet, &[BtcType::Nested], TPUB),
        [0x04, 0x5f, 0x1c, 0xf6] => ("vpub", Net::Testnet, &[BtcType::Native], TPUB),
        _ => return None,
    })
}

/// Version bytes of keys that are refused: private keys, and multisig (Ypub/Zpub/Upub/Vpub).
fn refused_version(v: [u8; 4]) -> Option<&'static str> {
    match v {
        // xprv yprv zprv tprv uprv vprv, and the multisig Yprv Zprv Uprv Vprv
        [0x04, 0x88, 0xad, 0xe4]
        | [0x04, 0x9d, 0x78, 0x78]
        | [0x04, 0xb2, 0x43, 0x0c]
        | [0x04, 0x35, 0x83, 0x94]
        | [0x04, 0x4a, 0x4e, 0x28]
        | [0x04, 0x5f, 0x18, 0xbc]
        | [0x02, 0x95, 0xb0, 0x05]
        | [0x02, 0xaa, 0x7a, 0x99]
        | [0x02, 0x42, 0x85, 0xb5]
        | [0x02, 0x57, 0x50, 0x48] => Some(PRIVATE_KEY),
        // Ypub Zpub Upub Vpub
        [0x02, 0x95, 0xb4, 0x3f] | [0x02, 0xaa, 0x7e, 0xd3] | [0x02, 0x42, 0x89, 0xef] | [0x02, 0x57, 0x54, 0x83] => Some(
            "That is a multisig key. Multisig wallets aren't supported here: move those coins from the multisig wallet itself, \
             or paste a receive address from it.",
        ),
        _ => None,
    }
}

pub const PRIVATE_KEY: &str = "That is a PRIVATE key. Don't paste it anywhere, and treat it as exposed if you shared it. \
     Phone Vault never needs it: you move funds by sending from your old wallet. Paste the account's public key (xpub) or an address instead.";
pub const PHRASE: &str =
    "That looks like a recovery phrase. Never type it into a computer. Phone Vault never asks for it: \
     you move funds by sending from your old wallet. Paste an address or the account's public key (xpub) instead.";

/// Validate one pasted entry.
pub fn parse(input: &str) -> Result<Source, String> {
    let s = input.trim();
    if s.is_empty() {
        return Err("Paste a public address or a public key (xpub, ypub or zpub).".into());
    }
    let words = s.split_whitespace().count();
    if words >= 11 && s.split_whitespace().all(|w| w.chars().all(|c| c.is_alphabetic())) {
        return Err(PHRASE.into());
    }
    if s.len() > MAX_INPUT || words > 1 {
        return Err("That doesn't look like an address or an extended public key. Paste one per line.".into());
    }
    let lower = s.to_ascii_lowercase();
    // A raw private key (64 hex digits, with or without 0x): never an address.
    let hex_body = lower.strip_prefix("0x").unwrap_or(&lower);
    if hex_body.len() == 64 && hex_body.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(PRIVATE_KEY.into());
    }
    if lower.starts_with("0x") {
        return parse_evm(s);
    }
    if let Some(data) = bitcoin::base58::decode_check(s).ok().filter(|d| d.len() == 78) {
        return parse_extended(s, &data);
    }
    // WIF private keys: base58check, version 0x80 (mainnet) or 0xef (test), 33 or 34 bytes
    if let Ok(d) = bitcoin::base58::decode_check(s) {
        if matches!(d.first(), Some(0x80 | 0xef)) && (d.len() == 33 || d.len() == 34) {
            return Err(PRIVATE_KEY.into());
        }
    }
    parse_btc_address(s)
}

fn parse_evm(s: &str) -> Result<Source, String> {
    let a = verify::parse_address(s, verify::Case::ChecksumIfMixed).map_err(|e| match e {
        verify::AddressError::Shape => "An Ethereum address is 0x followed by 40 hex characters.".to_string(),
        verify::AddressError::Checksum => "This address fails its checksum (EIP-55): one character is probably wrong. \
                                          Copy it again from the old wallet."
            .to_string(),
    })?;
    if a.bytes().skip(2).all(|b| b == b'0') {
        return Err("That is the zero address, not a wallet.".into());
    }
    Ok(Source::Evm { address: verify::checksum(&a), id: a })
}

/// An extended key (78 bytes after base58check).
fn parse_extended(s: &str, data: &[u8]) -> Result<Source, String> {
    let (version, rest) = data
        .split_first_chunk::<4>()
        .ok_or("This doesn't read as a valid public key (xpub, ypub or zpub). Copy it again from your wallet.")?;
    if let Some(why) = refused_version(*version) {
        return Err(why.into());
    }
    let (prefix, network, types, standard) = version_info(*version)
        .ok_or("This public key has a version this app doesn't know. Use the xpub, ypub or zpub your wallet shows.")?;
    let mut bytes = standard.to_vec();
    bytes.extend_from_slice(rest);
    let x = Xpub::decode(&bytes).map_err(|_| "This extended public key is malformed. Copy it again.".to_string())?;
    let mut notes = Vec::new();
    if types.len() > 1 {
        notes.push(
            "A public key (xpub) doesn't say which address type it was used for, so every type is checked (Native SegWit, Taproot, Legacy, Nested SegWit)."
                .to_string(),
        );
    }
    if x.depth != 3 {
        notes.push(format!(
            "This key is at depth {} instead of an account key (depth 3, like m/84'/0'/0'); its addresses are checked anyway.",
            x.depth
        ));
    }
    Ok(Source::Xpub {
        id: s.to_string(),
        prefix: prefix.into(),
        network,
        types: types.to_vec(),
        note: (!notes.is_empty()).then(|| notes.join(" ")),
    })
}

/// The standard-version public key for an `Xpub` source's text (already validated by `parse`).
pub fn xpub_of(s: &str) -> Result<Xpub, String> {
    let data = bitcoin::base58::decode_check(s).map_err(|_| {
        "This doesn't read as a valid public key (xpub, ypub or zpub). Copy it again from your wallet.".to_string()
    })?;
    let (version, rest) = data
        .split_first_chunk::<4>()
        .ok_or("This doesn't read as a valid public key (xpub, ypub or zpub). Copy it again from your wallet.")?;
    let (_, _, _, standard) = version_info(*version).ok_or("This public key has a version this app doesn't know.")?;
    let mut bytes = standard.to_vec();
    bytes.extend_from_slice(rest);
    Xpub::decode(&bytes).map_err(|_| {
        "This doesn't read as a valid public key (xpub, ypub or zpub). Copy it again from your wallet.".to_string()
    })
}

fn parse_btc_address(s: &str) -> Result<Source, String> {
    let unchecked: Address<NetworkUnchecked> = s.parse().map_err(|_| {
        "That isn't an Ethereum address (0x…), a Bitcoin address, or an extended public key (xpub, ypub, zpub)."
            .to_string()
    })?;
    let net = [Net::Bitcoin, Net::Testnet]
        .into_iter()
        .find(|n| unchecked.is_valid_for_network(n.network()))
        .ok_or("That Bitcoin address is for a network this app doesn't use.")?;
    let a = unchecked.require_network(net.network()).map_err(|_| "That Bitcoin address is for another network.")?;
    let btc_type = match a.address_type() {
        Some(AddressType::P2pkh) => Some(BtcType::Legacy),
        Some(AddressType::P2sh) => Some(BtcType::Nested),
        Some(AddressType::P2wpkh) => Some(BtcType::Native),
        Some(AddressType::P2tr) => Some(BtcType::Taproot),
        _ => None,
    };
    Ok(Source::BtcAddress { id: a.to_string(), network: net, btc_type })
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;

    pub const ZPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    #[test]
    fn evm_addresses_need_a_valid_checksum_when_mixed_case() {
        let good = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8";
        assert_eq!(
            parse(good).unwrap(),
            Source::Evm { id: good.to_ascii_lowercase(), address: verify::checksum(&good.to_ascii_lowercase()) }
        );
        assert!(parse(&good.to_ascii_lowercase()).is_ok());
        assert!(parse(&format!("  {good}\n")).is_ok());
        let typo = good.replacen('C', "c", 1);
        assert!(parse(&typo).unwrap_err().contains("checksum"));
        assert!(parse("0x1234").unwrap_err().contains("40 hex"));
        assert!(parse(&format!("0x{}", "0".repeat(40))).unwrap_err().contains("zero"));
    }

    #[test]
    fn secrets_are_refused_and_named() {
        let phrase = "abandon ".repeat(11) + "about";
        assert_eq!(parse(&phrase).unwrap_err(), PHRASE);
        assert_eq!(
            parse("legal winner thank year wave sausage worth useful legal winner thank yellow").unwrap_err(),
            PHRASE
        );
        assert_eq!(parse(&format!("0x{}", "ab".repeat(32))).unwrap_err(), PRIVATE_KEY);
        assert_eq!(parse(&"ab".repeat(32)).unwrap_err(), PRIVATE_KEY);
        // BIP-32 test vector 1 master xprv
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        assert_eq!(parse(xprv).unwrap_err(), PRIVATE_KEY);
        // a WIF key (the well-known Bitcoin wiki example)
        assert_eq!(parse("5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ").unwrap_err(), PRIVATE_KEY);
        assert_eq!(parse("KwdMAjGmerYanjeui5SHS7JkmpZvVipYvB2LJGU1ZxJwYvP98617").unwrap_err(), PRIVATE_KEY);
    }

    #[test]
    fn extended_keys_by_prefix() {
        let Source::Xpub { prefix, network, types, note, id } = parse(ZPUB).unwrap() else { panic!() };
        assert_eq!(
            (prefix.as_str(), network, types, note, id.as_str()),
            ("zpub", Net::Bitcoin, vec![BtcType::Native], None, ZPUB)
        );
        // the same key as an xpub: every type, with a note
        let x = xpub_of(ZPUB).unwrap().to_string();
        let Source::Xpub { prefix, types, note, .. } = parse(&x).unwrap() else { panic!() };
        assert_eq!(prefix, "xpub");
        assert_eq!(types.len(), 4);
        assert!(note.unwrap().contains("every type"));
        assert_eq!(xpub_of(&x).unwrap(), xpub_of(ZPUB).unwrap());
        // one character changed: the checksum fails, so it is not a key (and not an address)
        let bad = ZPUB.replacen('R', "S", 1);
        assert!(parse(&bad).is_err());
    }

    #[test]
    fn bitcoin_addresses_by_type_and_network() {
        let cases = [
            ("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu", Net::Bitcoin, Some(BtcType::Native)),
            ("BC1QCR8TE4KR609GCAWUTMRZA0J4XV80JY8Z306FYU", Net::Bitcoin, Some(BtcType::Native)),
            ("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", Net::Bitcoin, Some(BtcType::Legacy)),
            ("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", Net::Bitcoin, Some(BtcType::Nested)),
            ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", Net::Bitcoin, Some(BtcType::Taproot)),
            ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", Net::Testnet, Some(BtcType::Native)),
        ];
        for (a, net, t) in cases {
            // bech32 addresses are kept lowercase; base58 ones as they are
            let want = if a.to_ascii_lowercase().starts_with("bc1") || a.starts_with("tb1") {
                a.to_ascii_lowercase()
            } else {
                a.to_string()
            };
            assert_eq!(parse(a).unwrap(), Source::BtcAddress { id: want, network: net, btc_type: t }, "{a}");
        }
        assert!(parse("bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyv").is_err(), "bad bech32 checksum");
        assert!(parse("hello").is_err());
        assert!(parse(&"x".repeat(MAX_INPUT + 1)).is_err());
        assert!(parse("bc1q… two words").is_err());
    }
}
