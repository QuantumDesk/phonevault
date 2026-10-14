//! Unsigned 256-bit amounts and their exact decimal text.

/// Unsigned 256-bit integer, most significant limb first (so the derived order is numeric).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug, Hash)]
pub struct U256([u64; 4]);

impl U256 {
    pub fn from_u128(v: u128) -> U256 {
        U256([0, 0, (v >> 64) as u64, v as u64])
    }
    #[deny(clippy::indexing_slicing)]
    pub(super) fn from_be(bytes: &[u8]) -> Option<U256> {
        let mut full = [0u8; 32];
        full.get_mut(32usize.checked_sub(bytes.len())?..)?.copy_from_slice(bytes);
        let mut l = [0u64; 4];
        for (limb, chunk) in l.iter_mut().zip(full.as_chunks::<8>().0) {
            *limb = u64::from_be_bytes(*chunk);
        }
        Some(U256(l))
    }
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 4]
    }
    pub(super) fn checked_add(self, o: U256) -> Option<U256> {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for i in (0..4).rev() {
            let s = self.0[i] as u128 + o.0[i] as u128 + carry;
            out[i] = s as u64;
            carry = s >> 64;
        }
        if carry != 0 {
            None
        } else {
            Some(U256(out))
        }
    }
    /// self − o, for self ≥ o.
    pub(super) fn sub(self, o: U256) -> U256 {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for i in (0..4).rev() {
            let mut d = self.0[i] as i128 - o.0[i] as i128 - borrow;
            borrow = if d < 0 {
                d += 1i128 << 64;
                1
            } else {
                0
            };
            out[i] = d as u64;
        }
        U256(out)
    }
    pub fn to_decimal(self) -> String {
        if self.is_zero() {
            return "0".into();
        }
        let mut limbs = self.0;
        let mut digits = Vec::new();
        while limbs != [0; 4] {
            let mut rem = 0u128;
            for limb in limbs.iter_mut() {
                let cur = (rem << 64) | *limb as u128;
                *limb = (cur / 10) as u64;
                rem = cur % 10;
            }
            digits.push(b'0' + rem as u8);
        }
        digits.reverse();
        String::from_utf8(digits).unwrap_or_default()
    }
    pub(super) fn to_u128(self) -> Option<u128> {
        if self.0[0] == 0 && self.0[1] == 0 {
            Some(((self.0[2] as u128) << 64) | self.0[3] as u128)
        } else {
            None
        }
    }
}

/// Decimal text of `raw` with `decimals` places, trailing zeros trimmed (exact, any size).
pub(super) fn format_decimal(raw: &str, decimals: u32) -> String {
    let d = decimals as usize;
    if d == 0 {
        return raw.to_string();
    }
    let padded = if raw.len() <= d { format!("{}{}", "0".repeat(d + 1 - raw.len()), raw) } else { raw.to_string() };
    let (whole, frac) = padded.split_at(padded.len() - d);
    let frac = frac.trim_end_matches('0');
    if frac.is_empty() {
        whole.to_string()
    } else {
        format!("{whole}.{frac}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u256_arithmetic_and_decimal() {
        let max = U256([u64::MAX; 4]);
        assert_eq!(max.to_decimal(), "115792089237316195423570985008687907853269984665640564039457584007913129639935");
        assert!(max.checked_add(U256::from_u128(1)).is_none());
        assert_eq!(U256::from_u128(1000).sub(U256::from_u128(1)).to_decimal(), "999");
        assert_eq!(
            U256::from_u128(u128::MAX).checked_add(U256::from_u128(1)).unwrap().to_decimal(),
            "340282366920938463463374607431768211456"
        );
        assert_eq!(format_decimal("1300000000000", 18), "0.0000013");
        assert_eq!(format_decimal("100000000", 6), "100");
    }
}
