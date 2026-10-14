//! A small, strict DER reader for the Android KeyDescription extension.
//!
//! Only what the attestation schema needs: definite lengths (minimal encoding), high tag numbers
//! (the AuthorizationList uses EXPLICIT tags up to [7xx]), INTEGER/ENUMERATED as unsigned
//! values, BOOLEAN as exactly 0x00/0xFF, OCTET STRING, NULL, SEQUENCE and SET. Anything else is
//! an error, never a guess. X.509 itself is parsed by `x509-parser`; this is only for the
//! extension payload, which `x509-parser` hands over as raw bytes.

pub const CLASS_UNIVERSAL: u8 = 0;
pub const CLASS_CONTEXT: u8 = 2;

pub const TAG_BOOLEAN: u32 = 1;
pub const TAG_INTEGER: u32 = 2;
pub const TAG_OCTET_STRING: u32 = 4;
pub const TAG_NULL: u32 = 5;
pub const TAG_ENUMERATED: u32 = 10;
pub const TAG_SEQUENCE: u32 = 16;
pub const TAG_SET: u32 = 17;

/// Nesting is shallow in the schema; this bounds any recursion a caller might do.
const MAX_LEN: usize = 1 << 20;

#[derive(Debug, Clone, Copy)]
pub struct Tlv<'a> {
    pub class: u8,
    pub constructed: bool,
    pub tag: u32,
    pub value: &'a [u8],
}

#[derive(Debug, Clone)]
pub struct Reader<'a> {
    buf: &'a [u8],
}

fn err<T>(m: &str) -> Result<T, String> {
    Err(format!("attestation extension: {m}"))
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn read(&mut self) -> Result<Tlv<'a>, String> {
        let b = &self.buf;
        if b.len() < 2 {
            return err("truncated element");
        }
        let first = b[0];
        let class = first >> 6;
        let constructed = first & 0x20 != 0;
        let mut pos = 1;
        let mut tag = (first & 0x1f) as u32;
        if tag == 0x1f {
            // high tag number: base-128, minimal (no leading 0x80), at most 4 bytes, value >= 31
            tag = 0;
            let mut n = 0;
            loop {
                let byte = *b.get(pos).ok_or("attestation extension: truncated tag")?;
                if n == 0 && byte == 0x80 {
                    return err("non-minimal tag encoding");
                }
                tag = (tag << 7) | (byte & 0x7f) as u32;
                pos += 1;
                n += 1;
                if byte & 0x80 == 0 {
                    break;
                }
                if n >= 4 {
                    return err("tag number too large");
                }
            }
            if tag < 0x1f {
                return err("non-minimal tag encoding");
            }
        }
        let lb = *b.get(pos).ok_or("attestation extension: truncated length")?;
        pos += 1;
        let len: usize = if lb < 0x80 {
            lb as usize
        } else if lb == 0x80 {
            return err("indefinite length is not DER");
        } else {
            let n = (lb & 0x7f) as usize;
            if n > 3 {
                return err("length too large");
            }
            let bytes = b.get(pos..pos + n).ok_or("attestation extension: truncated length")?;
            if bytes[0] == 0 {
                return err("non-minimal length encoding");
            }
            let mut l = 0usize;
            for &x in bytes {
                l = (l << 8) | x as usize;
            }
            if l < 0x80 {
                return err("non-minimal length encoding");
            }
            pos += n;
            l
        };
        if len > MAX_LEN {
            return err("element too large");
        }
        let value = b.get(pos..pos + len).ok_or("attestation extension: element runs past its container")?;
        self.buf = &b[pos + len..];
        Ok(Tlv { class, constructed, tag, value })
    }

    /// Read one element that must be exactly (class, constructed, tag).
    pub fn expect(&mut self, class: u8, constructed: bool, tag: u32, what: &str) -> Result<&'a [u8], String> {
        let t = self.read()?;
        if t.class != class || t.constructed != constructed || t.tag != tag {
            return Err(format!("attestation extension: {what} has the wrong type"));
        }
        Ok(t.value)
    }

    pub fn sequence(&mut self, what: &str) -> Result<Reader<'a>, String> {
        Ok(Reader::new(self.expect(CLASS_UNIVERSAL, true, TAG_SEQUENCE, what)?))
    }
    pub fn set(&mut self, what: &str) -> Result<Reader<'a>, String> {
        Ok(Reader::new(self.expect(CLASS_UNIVERSAL, true, TAG_SET, what)?))
    }
    pub fn uint(&mut self, what: &str) -> Result<u64, String> {
        uint(self.expect(CLASS_UNIVERSAL, false, TAG_INTEGER, what)?, what)
    }
    pub fn enumerated(&mut self, what: &str) -> Result<u64, String> {
        uint(self.expect(CLASS_UNIVERSAL, false, TAG_ENUMERATED, what)?, what)
    }
    pub fn octets(&mut self, what: &str) -> Result<&'a [u8], String> {
        self.expect(CLASS_UNIVERSAL, false, TAG_OCTET_STRING, what)
    }
    pub fn boolean(&mut self, what: &str) -> Result<bool, String> {
        boolean(self.expect(CLASS_UNIVERSAL, false, TAG_BOOLEAN, what)?, what)
    }
    pub fn end(&self, what: &str) -> Result<(), String> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(format!("attestation extension: trailing data in {what}"))
        }
    }
}

/// A non-negative INTEGER/ENUMERATED body that fits in u64, minimally encoded.
pub fn uint(v: &[u8], what: &str) -> Result<u64, String> {
    if v.is_empty() {
        return Err(format!("attestation extension: {what} is an empty integer"));
    }
    if v[0] & 0x80 != 0 {
        return Err(format!("attestation extension: {what} is negative"));
    }
    if v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        return Err(format!("attestation extension: {what} is not minimally encoded"));
    }
    let body = if v[0] == 0 && v.len() > 1 { &v[1..] } else { v };
    if body.len() > 8 {
        return Err(format!("attestation extension: {what} is too large"));
    }
    Ok(body.iter().fold(0u64, |a, &b| (a << 8) | b as u64))
}

pub fn boolean(v: &[u8], what: &str) -> Result<bool, String> {
    match v {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(format!("attestation extension: {what} is not a DER boolean")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_short_long_and_high_tags() {
        // [709] EXPLICIT { OCTET STRING 'ab' }
        let bytes = [0xbf, 0x85, 0x45, 0x04, 0x04, 0x02, b'a', b'b'];
        let mut r = Reader::new(&bytes);
        let t = r.read().unwrap();
        assert_eq!((t.class, t.constructed, t.tag), (CLASS_CONTEXT, true, 709));
        assert_eq!(Reader::new(t.value).octets("x").unwrap(), b"ab");
        assert!(r.is_empty());
        let mut long = vec![0x04, 0x81, 0x80];
        long.extend(std::iter::repeat_n(7u8, 0x80));
        assert_eq!(Reader::new(&long).octets("x").unwrap().len(), 0x80);
    }

    #[test]
    fn refuses_non_der() {
        assert!(Reader::new(&[0x04, 0x80, 0x00, 0x00]).read().is_err(), "indefinite length");
        assert!(Reader::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).read().is_err(), "long form for a short length");
        assert!(Reader::new(&[0x04, 0x82, 0x00, 0x05, 1, 2, 3, 4, 5]).read().is_err(), "leading zero length byte");
        assert!(Reader::new(&[0x04, 0x05, 1, 2]).read().is_err(), "length past the end");
        assert!(Reader::new(&[0xbf, 0x80, 0x05, 0x00]).read().is_err(), "non-minimal tag");
        assert!(Reader::new(&[0xbf, 0x1e, 0x00]).read().is_err(), "high-tag form for a low tag");
        assert!(uint(&[0x00, 0x05], "x").is_err(), "non-minimal integer");
        assert!(uint(&[0x80], "x").is_err(), "negative");
        assert_eq!(uint(&[0x00, 0x80], "x").unwrap(), 128);
        assert!(boolean(&[0x01], "x").is_err(), "BER true is not DER");
        assert!(boolean(&[0xff], "x").unwrap());
    }
}
