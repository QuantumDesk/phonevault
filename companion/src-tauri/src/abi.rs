//! The few pieces of the Solidity ABI this app reads and writes: function selectors, the Transfer
//! event topic, and 32-byte words. Almost everything decoded here comes from a node or a contract
//! (untrusted): every offset and length is checked, nothing is indexed unchecked, and a word that
//! does not have the expected shape is `None`, never a panic or a truncated value.

#![deny(clippy::indexing_slicing)]

/// `transfer(address,uint256)` (ERC-20).
pub const SEL_TRANSFER: &str = "a9059cbb";
/// `approve(address,uint256)` (ERC-20).
pub const SEL_APPROVE: &str = "095ea7b3";
/// `balanceOf(address)` (ERC-20 and ERC-721).
pub const SEL_BALANCE_OF: &str = "70a08231";
/// `ownerOf(uint256)` (ERC-721).
pub const SEL_OWNER_OF: &str = "6352211e";
/// `name()`.
pub const SEL_NAME: &str = "06fdde03";
/// `symbol()`.
pub const SEL_SYMBOL: &str = "95d89b41";
/// `tokenURI(uint256)` (ERC-721 metadata).
pub const SEL_TOKEN_URI: &str = "c87b56dd";
/// `tokenOfOwnerByIndex(address,uint256)` (ERC-721 enumerable).
pub const SEL_TOKEN_OF_OWNER_BY_INDEX: &str = "2f745c59";

macro_rules! transfer_event {
    () => {
        "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
    };
}
/// keccak256("Transfer(address,address,uint256)"), the topic of ERC-20 and ERC-721 transfers:
/// as 64 hex digits, and as the `0x` topic string nodes use.
pub const TRANSFER_EVENT: &str = transfer_event!();
pub const TRANSFER_TOPIC: &str = concat!("0x", transfer_event!());

/// The 32-byte word starting at byte `offset`; None past the end (or on overflow).
pub fn word_at(bytes: &[u8], offset: usize) -> Option<&[u8]> {
    bytes.get(offset..offset.checked_add(32)?)
}

/// A 32-byte word as a u128: None unless it is exactly 32 bytes with the high 16 bytes zero.
pub fn u128_of_word(word: &[u8]) -> Option<u128> {
    let w: &[u8; 32] = word.try_into().ok()?;
    let (high, low) = w.split_at(16);
    if high.iter().any(|b| *b != 0) {
        return None;
    }
    Some(u128::from_be_bytes(low.try_into().ok()?))
}

/// The 32-byte word at byte `offset` as a usize (an ABI offset or length); None if out of range.
pub fn usize_at(bytes: &[u8], offset: usize) -> Option<usize> {
    usize::try_from(u128_of_word(word_at(bytes, offset)?)?).ok()
}

/// An address word (12 zero bytes, then 20 bytes) as lowercase `0x` + 40 hex; None for anything
/// else, including a word that is not exactly 32 bytes.
pub fn address_of_word(word: &[u8]) -> Option<String> {
    let w: &[u8; 32] = word.try_into().ok()?;
    let (pad, addr) = w.split_at(12);
    pad.iter().all(|b| *b == 0).then(|| format!("0x{}", hex::encode(addr)))
}

/// The same for a word written as 64 hex digits (no `0x`; callers strip it as their input
/// allows): lowercase `0x` + 40 hex, or None.
pub fn address_of_word_hex(hex64: &str) -> Option<String> {
    if hex64.len() != 64 || !hex64.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (pad, addr) = (hex64.get(..24)?, hex64.get(24..)?);
    pad.bytes().all(|b| b == b'0').then(|| format!("0x{}", addr.to_ascii_lowercase()))
}

/// A word written as 64 hex digits as a u128: None unless the high 32 digits are zero.
pub fn u128_of_word_hex(hex64: &str) -> Option<u128> {
    if hex64.len() != 64 || !hex64.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let (high, low) = (hex64.get(..32)?, hex64.get(32..)?);
    if !high.bytes().all(|b| b == b'0') {
        return None;
    }
    u128::from_str_radix(low, 16).ok()
}

/// An address as a word: 64 lowercase hex digits, left-padded (no `0x`). Not validated: callers
/// pass an address they checked.
pub fn address_word_hex(address: &str) -> String {
    format!("{:0>64}", address.trim_start_matches("0x").to_ascii_lowercase())
}

/// A returned `string` (or a legacy `bytes32`), printable characters only, capped. The contract
/// (anyone's) chooses these bytes: every offset and length is checked, never trusted.
pub fn decode_string(ret: &[u8]) -> Option<String> {
    let raw: Vec<u8> = if ret.len() == 32 {
        ret.iter().copied().take_while(|b| *b != 0).collect()
    } else {
        let off = usize_at(ret, 0)?;
        let len = usize_at(ret, off)?;
        if len > 4096 {
            return None;
        }
        let start = off.checked_add(32)?;
        ret.get(start..start.checked_add(len)?)?.to_vec()
    };
    let s = String::from_utf8(raw).ok()?;
    let s: String = s.chars().filter(|c| !c.is_control()).take(200).collect();
    let s = s.trim().to_string();
    (!s.is_empty()).then_some(s)
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::verify::keccak256;

    #[test]
    fn selectors_and_topic_are_the_signatures_hashes() {
        let sel = |sig: &str| hex::encode(&keccak256(sig.as_bytes())[..4]);
        assert_eq!(sel("transfer(address,uint256)"), SEL_TRANSFER);
        assert_eq!(sel("approve(address,uint256)"), SEL_APPROVE);
        assert_eq!(sel("balanceOf(address)"), SEL_BALANCE_OF);
        assert_eq!(sel("ownerOf(uint256)"), SEL_OWNER_OF);
        assert_eq!(sel("name()"), SEL_NAME);
        assert_eq!(sel("symbol()"), SEL_SYMBOL);
        assert_eq!(sel("tokenURI(uint256)"), SEL_TOKEN_URI);
        assert_eq!(sel("tokenOfOwnerByIndex(address,uint256)"), SEL_TOKEN_OF_OWNER_BY_INDEX);
        assert_eq!(hex::encode(keccak256(b"Transfer(address,address,uint256)")), TRANSFER_EVENT);
        assert_eq!(TRANSFER_TOPIC, format!("0x{TRANSFER_EVENT}"));
    }

    #[test]
    fn words_have_exact_shapes() {
        let mut w = [0u8; 32];
        w[31] = 7;
        assert_eq!(u128_of_word(&w), Some(7));
        assert_eq!(u128_of_word(&w[..31]), None);
        assert_eq!(u128_of_word(&[0u8; 64]), None);
        w[15] = 1;
        assert_eq!(u128_of_word(&w), None);
        let mut a = [0u8; 32];
        a[12..].copy_from_slice(&[0xab; 20]);
        assert_eq!(address_of_word(&a), Some(format!("0x{}", "ab".repeat(20))));
        a[11] = 1;
        assert_eq!(address_of_word(&a), None);
        assert_eq!(address_of_word(&[0u8; 33]), None);
        let h = format!("{:0>64}", "AB".repeat(20));
        assert_eq!(address_of_word_hex(&h), Some(format!("0x{}", "ab".repeat(20))));
        assert_eq!(address_of_word_hex(&format!("1{}", &h[1..])), None);
        assert_eq!(address_of_word_hex(&h[1..]), None);
        assert_eq!(u128_of_word_hex(&format!("{:0>64}", "ff")), Some(255));
        assert_eq!(u128_of_word_hex(&format!("1{:0>63}", "")), None);
        assert_eq!(u128_of_word_hex(&format!("{:0>64}", "fg")), None);
        assert_eq!(address_word_hex("0xABc"), format!("{:0>64}", "abc"));
        assert_eq!(word_at(&[0u8; 64], 32).map(<[u8]>::len), Some(32));
        assert_eq!(word_at(&[0u8; 64], 33), None);
        assert_eq!(word_at(&[0u8; 64], usize::MAX), None);
        assert_eq!(usize_at(&w, 0), None);
    }

    #[test]
    fn strings_decode_abi_and_bytes32() {
        let mut abi = vec![0u8; 96];
        abi[31] = 32;
        abi[63] = 5;
        abi[64..69].copy_from_slice(b"Pixel");
        assert_eq!(decode_string(&abi).as_deref(), Some("Pixel"));
        let mut b32 = [0u8; 32];
        b32[..3].copy_from_slice(b"MKR");
        assert_eq!(decode_string(&b32).as_deref(), Some("MKR"));
        abi[63] = 200; // length past the end
        assert!(decode_string(&abi).is_none());
    }

    /// `decode_string` (name(), symbol() and tokenURI() of any contract that sends the user an NFT)
    /// refuses an ABI offset or length that overflows or points past the return data.
    #[test]
    fn abi_string_offsets_that_overflow_are_refused() {
        use std::panic::catch_unwind;
        let mut ret = vec![0u8; 64];
        ret[16..32].copy_from_slice(&((u64::MAX - 15) as u128).to_be_bytes());
        assert_eq!(catch_unwind(|| decode_string(&ret)).ok(), Some(None));
        // the length word overflowing the end, and the largest offsets
        for (off, len) in
            [(32u128, u64::MAX as u128), (u128::MAX, 1), (usize::MAX as u128 - 31, 0), (usize::MAX as u128, 0)]
        {
            let mut r = vec![0u8; 96];
            r[16..32].copy_from_slice(&off.to_be_bytes());
            r[48..64].copy_from_slice(&len.to_be_bytes());
            assert_eq!(catch_unwind(|| decode_string(&r)).ok(), Some(None), "off {off} len {len}");
        }
    }
}
