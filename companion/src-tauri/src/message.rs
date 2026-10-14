//! Independent recomputation of what the phone signs for `personal_sign` (EIP-191 0x45) and
//! `eth_signTypedData_v4` (EIP-712). The phone's Java implementation (Eip712.java, StrictJson.java,
//! PersonalMessage.java) is NOT trusted: this module re-parses the original request with the same
//! strict rules and limits and derives the digest on its own. Both are tested against the shared
//! vectors in app/src/test/resources/message-signing-vectors.json.
//!
//! serde_json is deliberately not used for the typed data itself: it silently keeps the last of
//! two duplicate keys and rounds large integers to f64 without `arbitrary_precision`.

use crate::verify::{keccak256, parse_address, AddressError, Case};
use std::collections::{BTreeMap, BTreeSet};

// ---- limits: identical to the phone (vault-os/docs/message-signing.md)
pub const MAX_TYPED_DATA_BYTES: usize = 24 * 1024;
pub const MAX_MESSAGE_BYTES: usize = 8192;
const MAX_DEPTH: usize = 16;
const MAX_STRUCT_TYPES: usize = 32;
const MAX_FIELDS_PER_STRUCT: usize = 48;
const MAX_ARRAY_LENGTH: usize = 128;
const MAX_ARRAY_DIMENSIONS: usize = 3;
const MAX_VALUES: i64 = 1024;
const MAX_DYNAMIC_BYTES: usize = 4096;
const MAX_STRING_BYTES: usize = 4096;
const MAX_NAME_LENGTH: usize = 64;
const MAX_INTEGER_LITERAL: usize = 80;
const DOMAIN_TYPE: &str = "EIP712Domain";
const DOMAIN_FIELDS: [(&str, &str); 5] = [
    ("name", "string"),
    ("version", "string"),
    ("chainId", "uint256"),
    ("verifyingContract", "address"),
    ("salt", "bytes32"),
];

#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct MessageError(pub String);
impl From<MessageError> for String {
    fn from(e: MessageError) -> String {
        e.0
    }
}
fn err(m: impl Into<String>) -> MessageError {
    MessageError(m.into())
}

// ------------------------------------------------------------------ EIP-191

/// keccak256("\x19Ethereum Signed Message:\n" ‖ len ‖ message).
pub fn personal_digest(message: &[u8]) -> [u8; 32] {
    let mut pre = b"\x19Ethereum Signed Message:\n".to_vec();
    pre.extend(message.len().to_string().as_bytes());
    pre.extend(message);
    keccak256(&pre)
}

// ------------------------------------------------------------------ strict JSON

#[derive(Debug, Clone, PartialEq)]
enum J {
    Obj(Vec<(String, J)>),
    Arr(Vec<J>),
    Str(String),
    Num(String),
    Bool(bool),
}

struct Parser<'a> {
    s: &'a [u8],
    at: usize,
    text: &'a str,
}

fn parse_json(text: &str) -> Result<J, MessageError> {
    let mut p = Parser { s: text.as_bytes(), at: 0, text };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.at != p.s.len() {
        return Err(err("trailing data after JSON value"));
    }
    Ok(v)
}

impl<'a> Parser<'a> {
    fn peek(&self) -> u8 {
        *self.s.get(self.at).unwrap_or(&0)
    }
    fn ws(&mut self) {
        while matches!(self.peek(), b' ' | b'\t' | b'\n' | b'\r') {
            self.at += 1;
        }
    }
    fn value(&mut self, depth: usize) -> Result<J, MessageError> {
        if depth > MAX_DEPTH {
            return Err(err(format!("JSON nesting deeper than {MAX_DEPTH}")));
        }
        match self.peek() {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => Ok(J::Str(self.string()?)),
            b't' => self.literal("true").map(|_| J::Bool(true)),
            b'f' => self.literal("false").map(|_| J::Bool(false)),
            b'n' => Err(err("null is not allowed in typed data")),
            b'-' | b'0'..=b'9' => self.number(),
            0 if self.at >= self.s.len() => Err(err("JSON ended early")),
            _ => Err(err(format!("unexpected character in JSON at offset {}", self.at))),
        }
    }
    fn object(&mut self, depth: usize) -> Result<J, MessageError> {
        self.at += 1;
        let mut members: Vec<(String, J)> = Vec::new();
        self.ws();
        if self.peek() == b'}' {
            self.at += 1;
            return Ok(J::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != b'"' {
                return Err(err("JSON object keys must be strings"));
            }
            let key = self.string()?;
            if members.iter().any(|(k, _)| *k == key) {
                return Err(err(format!("duplicate JSON key: {key}")));
            }
            self.ws();
            if self.peek() != b':' {
                return Err(err("missing ':' after JSON key"));
            }
            self.at += 1;
            self.ws();
            let v = self.value(depth + 1)?;
            members.push((key, v));
            self.ws();
            let next = self.peek();
            self.at += 1;
            if next == b'}' {
                return Ok(J::Obj(members));
            }
            if next != b',' {
                return Err(err("missing ',' between JSON object members"));
            }
        }
    }
    fn array(&mut self, depth: usize) -> Result<J, MessageError> {
        self.at += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == b']' {
            self.at += 1;
            return Ok(J::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth + 1)?);
            self.ws();
            let next = self.peek();
            self.at += 1;
            if next == b']' {
                return Ok(J::Arr(items));
            }
            if next != b',' {
                return Err(err("missing ',' between JSON array elements"));
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, MessageError> {
        let h = self.s.get(self.at..self.at + 4).ok_or_else(|| err("truncated \\u escape"))?;
        let h = std::str::from_utf8(h).map_err(|_| err("invalid \\u escape"))?;
        if !h.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(err("invalid \\u escape"));
        }
        self.at += 4;
        Ok(u32::from_str_radix(h, 16).unwrap())
    }
    fn string(&mut self) -> Result<String, MessageError> {
        self.at += 1;
        let mut out = String::new();
        loop {
            // Iterate by char so raw multi-byte UTF-8 is copied intact.
            let rest = &self.text[self.at..];
            let c = rest.chars().next().ok_or_else(|| err("unterminated JSON string"))?;
            self.at += c.len_utf8();
            match c {
                '"' => return Ok(out),
                c if (c as u32) < 0x20 => return Err(err("raw control character in JSON string")),
                '\\' => {
                    let e = self.peek();
                    self.at += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            if (0xD800..0xDC00).contains(&u) {
                                if self.peek() != b'\\' || self.s.get(self.at + 1) != Some(&b'u') {
                                    return Err(err("unpaired surrogate in JSON string"));
                                }
                                self.at += 2;
                                let low = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&low) {
                                    return Err(err("unpaired surrogate in JSON string"));
                                }
                                out.push(char::from_u32(0x10000 + ((u - 0xD800) << 10) + (low - 0xDC00)).unwrap());
                            } else if (0xDC00..0xE000).contains(&u) {
                                return Err(err("unpaired surrogate in JSON string"));
                            } else {
                                out.push(char::from_u32(u).unwrap());
                            }
                        }
                        _ => return Err(err("invalid JSON escape")),
                    }
                }
                c => out.push(c),
            }
        }
    }
    fn number(&mut self) -> Result<J, MessageError> {
        let start = self.at;
        let digit = |p: &Self| p.peek().is_ascii_digit();
        if self.peek() == b'-' {
            self.at += 1;
        }
        if self.peek() == b'0' {
            self.at += 1;
        } else if matches!(self.peek(), b'1'..=b'9') {
            while digit(self) {
                self.at += 1;
            }
        } else {
            return Err(err("invalid JSON number"));
        }
        if self.peek() == b'.' {
            self.at += 1;
            if !digit(self) {
                return Err(err("invalid JSON number"));
            }
            while digit(self) {
                self.at += 1;
            }
        }
        if matches!(self.peek(), b'e' | b'E') {
            self.at += 1;
            if matches!(self.peek(), b'+' | b'-') {
                self.at += 1;
            }
            if !digit(self) {
                return Err(err("invalid JSON number"));
            }
            while digit(self) {
                self.at += 1;
            }
        }
        Ok(J::Num(self.text[start..self.at].to_string()))
    }
    fn literal(&mut self, word: &str) -> Result<(), MessageError> {
        if !self.text[self.at..].starts_with(word) {
            return Err(err("invalid JSON literal"));
        }
        self.at += word.len();
        Ok(())
    }
}

fn obj<'a>(j: &'a J, what: &str) -> Result<&'a Vec<(String, J)>, MessageError> {
    match j {
        J::Obj(m) => Ok(m),
        _ => Err(err(format!("{what} must be a JSON object"))),
    }
}
fn get<'a>(m: &'a [(String, J)], key: &str) -> Option<&'a J> {
    m.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}
fn keys(m: &[(String, J)]) -> BTreeSet<&str> {
    m.iter().map(|(k, _)| k.as_str()).collect()
}
fn exact_keys(m: &[(String, J)], what: &str, expected: &[&str]) -> Result<(), MessageError> {
    if keys(m) != expected.iter().copied().collect() || m.len() != expected.len() {
        return Err(err(format!("{what} must have exactly the fields {expected:?}")));
    }
    Ok(())
}

// ------------------------------------------------------------------ EIP-712 types

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Bool,
    Address,
    Uint(usize),
    Int(usize),
    FixedBytes(usize),
    Bytes,
    Str,
}

fn size_suffix(s: &str) -> Option<usize> {
    if s.is_empty() || s.len() > 3 || s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

fn atomic_kind(base: &str) -> Option<Kind> {
    match base {
        "bool" => return Some(Kind::Bool),
        "address" => return Some(Kind::Address),
        "string" => return Some(Kind::Str),
        "bytes" => return Some(Kind::Bytes),
        _ => {}
    }
    if let Some(n) = base.strip_prefix("bytes") {
        return size_suffix(n).filter(|n| (1..=32).contains(n)).map(Kind::FixedBytes);
    }
    if let Some(n) = base.strip_prefix("uint") {
        return size_suffix(n).filter(|n| (8..=256).contains(n) && n % 8 == 0).map(Kind::Uint);
    }
    if let Some(n) = base.strip_prefix("int") {
        return size_suffix(n).filter(|n| (8..=256).contains(n) && n % 8 == 0).map(Kind::Int);
    }
    None
}

fn is_identifier(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphabetic() || c == '_' || c == '$')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
}
fn valid_name(s: &str) -> bool {
    s.len() <= MAX_NAME_LENGTH && is_identifier(s)
}
fn reserved_name(s: &str) -> bool {
    if matches!(s, "bool" | "address" | "string" | "byte" | "function" | "tuple") {
        return true;
    }
    ["uint", "int", "bytes", "ufixed", "fixed"]
        .iter()
        .any(|p| s.strip_prefix(p).is_some_and(|r| r.bytes().all(|b| b.is_ascii_digit() || b == b'x')))
}

/// (base, dimensions) of a field type, or None if the syntax is invalid. Each dimension is
/// Some(fixed length) or None for a dynamic array; the last one is the outermost.
fn split_type(t: &str) -> Option<(&str, Vec<Option<usize>>)> {
    let base_end = t.find('[').unwrap_or(t.len());
    let base = &t[..base_end];
    if !is_identifier(base) {
        return None;
    }
    let mut dims = Vec::new();
    let mut rest = &t[base_end..];
    while !rest.is_empty() {
        let close = rest.find(']')?;
        if !rest.starts_with('[') {
            return None;
        }
        let inner = &rest[1..close];
        if inner.is_empty() {
            dims.push(None);
        } else {
            if inner.len() > 4 || inner.starts_with('0') || !inner.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            dims.push(Some(inner.parse().ok()?));
        }
        rest = &rest[close + 1..];
    }
    Some((base, dims))
}

type Types = BTreeMap<String, Vec<(String, String)>>;

fn parse_types(raw: &J) -> Result<Types, MessageError> {
    let declared = obj(raw, "types")?;
    if declared.len() > MAX_STRUCT_TYPES {
        return Err(err(format!("more than {MAX_STRUCT_TYPES} types")));
    }
    if get(declared, DOMAIN_TYPE).is_none() {
        return Err(err("types must define EIP712Domain"));
    }
    let mut types = Types::new();
    for (name, value) in declared {
        if !valid_name(name) || reserved_name(name) {
            return Err(err(format!("invalid type name: {name}")));
        }
        let list = match value {
            J::Arr(l) => l,
            _ => return Err(err(format!("type {name} must be a list of fields"))),
        };
        if list.len() > MAX_FIELDS_PER_STRUCT {
            return Err(err(format!("type {name} has too many fields")));
        }
        let mut fields = Vec::new();
        for item in list {
            let f = obj(item, "field")?;
            exact_keys(f, "field", &["name", "type"])?;
            let (Some(J::Str(fname)), Some(J::Str(ftype))) = (get(f, "name"), get(f, "type")) else {
                return Err(err(format!("field name and type of {name} must be strings")));
            };
            if !valid_name(fname) {
                return Err(err(format!("invalid field name in {name}: {fname}")));
            }
            if fields.iter().any(|(n, _): &(String, String)| n == fname) {
                return Err(err(format!("duplicate field {fname} in {name}")));
            }
            fields.push((fname.clone(), ftype.clone()));
        }
        types.insert(name.clone(), fields);
    }
    for (owner, fields) in &types {
        for (_, t) in fields {
            let (base, dims) = split_type(t).ok_or_else(|| err(format!("invalid type in {owner}: {t}")))?;
            if dims.iter().any(|d| d.is_some_and(|n| n > MAX_ARRAY_LENGTH)) {
                return Err(err(format!("fixed array longer than {MAX_ARRAY_LENGTH} in {owner}")));
            }
            if dims.len() > MAX_ARRAY_DIMENSIONS {
                return Err(err(format!("too many array dimensions in {owner}")));
            }
            if atomic_kind(base).is_some() {
                continue;
            }
            if base == DOMAIN_TYPE {
                return Err(err("EIP712Domain cannot be used as a field type"));
            }
            if !types.contains_key(base) {
                return Err(err(format!("unknown type {base} in {owner}")));
            }
        }
    }
    let mut cursor = 0;
    for (name, t) in &types[DOMAIN_TYPE] {
        while cursor < DOMAIN_FIELDS.len() && DOMAIN_FIELDS[cursor].0 != name {
            cursor += 1;
        }
        if cursor == DOMAIN_FIELDS.len() {
            return Err(err(format!("EIP712Domain field {name} is unknown or out of order")));
        }
        if DOMAIN_FIELDS[cursor].1 != t {
            return Err(err(format!("EIP712Domain field {name} must be {}", DOMAIN_FIELDS[cursor].1)));
        }
        cursor += 1;
    }
    Ok(types)
}

fn base_type(t: &str) -> &str {
    &t[..t.find('[').unwrap_or(t.len())]
}

fn dependencies(types: &Types, t: &str) -> BTreeSet<String> {
    fn collect(types: &Types, t: &str, found: &mut BTreeSet<String>) {
        if !found.insert(t.to_string()) {
            return;
        }
        for (_, ft) in &types[t] {
            let b = base_type(ft);
            if atomic_kind(b).is_none() && types.contains_key(b) {
                collect(types, b, found);
            }
        }
    }
    let mut found = BTreeSet::new();
    collect(types, t, &mut found);
    found.remove(t);
    found
}

fn encode_type_of(types: &Types, t: &str) -> String {
    let one =
        |t: &str| format!("{t}({})", types[t].iter().map(|(n, ft)| format!("{ft} {n}")).collect::<Vec<_>>().join(","));
    let mut out = one(t);
    for dep in dependencies(types, t) {
        out.push_str(&one(&dep));
    }
    out
}

// ------------------------------------------------------------------ values

fn spend(budget: &mut i64) -> Result<(), MessageError> {
    *budget -= 1;
    if *budget < 0 {
        return Err(err(format!("typed data has more than {MAX_VALUES} values")));
    }
    Ok(())
}

/// Parse and encode in one pass: returns the 32-byte EIP-712 encoding of the value.
fn encode_value(types: &Types, t: &str, raw: &J, path: &str, budget: &mut i64) -> Result<[u8; 32], MessageError> {
    if t.ends_with(']') {
        spend(budget)?;
        let open = t.rfind('[').unwrap();
        let (element, size) = (&t[..open], &t[open + 1..t.len() - 1]);
        let list = match raw {
            J::Arr(l) => l,
            _ => return Err(err(format!("{path} must be an array"))),
        };
        if list.len() > MAX_ARRAY_LENGTH {
            return Err(err(format!("{path} has more than {MAX_ARRAY_LENGTH} elements")));
        }
        if !size.is_empty() && list.len() != size.parse::<usize>().unwrap() {
            return Err(err(format!("{path} must have exactly {size} elements")));
        }
        let mut concat = Vec::with_capacity(32 * list.len());
        for (i, item) in list.iter().enumerate() {
            concat.extend(encode_value(types, element, item, &format!("{path}[{i}]"), budget)?);
        }
        return Ok(keccak256(&concat));
    }
    let Some(kind) = atomic_kind(t) else { return hash_struct(types, t, raw, path, budget) };
    spend(budget)?;
    match (kind, raw) {
        (Kind::Bool, J::Bool(b)) => {
            let mut w = [0u8; 32];
            w[31] = *b as u8;
            Ok(w)
        }
        (Kind::Bool, _) => Err(err(format!("{path} must be true or false"))),
        (Kind::Address, J::Str(s)) => {
            let lower = parse_address(s, Case::ChecksumIfMixed).map_err(|e| match e {
                AddressError::Shape => err(format!("{path} must be a 0x-prefixed 20-byte address")),
                AddressError::Checksum => err(format!("{path} fails its EIP-55 checksum")),
            })?;
            let mut w = [0u8; 32];
            w[12..].copy_from_slice(&hex::decode(lower.trim_start_matches("0x")).unwrap());
            Ok(w)
        }
        (Kind::Address, _) => Err(err(format!("{path} must be a 0x-prefixed 20-byte address"))),
        (Kind::Uint(bits), _) => integer(raw, false, bits, path),
        (Kind::Int(bits), _) => integer(raw, true, bits, path),
        (Kind::FixedBytes(n), _) => {
            let b = hex_bytes(raw, path)?;
            if b.len() != n {
                return Err(err(format!("{path} must be exactly {n} bytes")));
            }
            let mut w = [0u8; 32];
            w[..n].copy_from_slice(&b);
            Ok(w)
        }
        (Kind::Bytes, _) => {
            let b = hex_bytes(raw, path)?;
            if b.len() > MAX_DYNAMIC_BYTES {
                return Err(err(format!("{path} exceeds {MAX_DYNAMIC_BYTES} bytes")));
            }
            Ok(keccak256(&b))
        }
        (Kind::Str, J::Str(s)) => {
            if s.len() > MAX_STRING_BYTES {
                return Err(err(format!("{path} exceeds {MAX_STRING_BYTES} bytes")));
            }
            Ok(keccak256(s.as_bytes()))
        }
        (Kind::Str, _) => Err(err(format!("{path} must be a string"))),
    }
}

fn is_decimal(s: &str) -> bool {
    let d = s.strip_prefix('-').unwrap_or(s);
    !d.is_empty()
        && d.bytes().all(|b| b.is_ascii_digit())
        && (d == "0" || !d.starts_with('0'))
        && s != "-0"
        && s.len() <= MAX_INTEGER_LITERAL
}

/// Range-checked whole number → 32-byte two's-complement word.
fn integer(raw: &J, signed: bool, bits: usize, path: &str) -> Result<[u8; 32], MessageError> {
    let (negative, magnitude): (bool, Vec<u8>) = match raw {
        J::Num(lit) if is_decimal(lit) => (lit.starts_with('-'), decimal_to_be(lit.trim_start_matches('-'))),
        J::Num(_) => return Err(err(format!("{path} must be a whole number"))),
        J::Str(s)
            if s.starts_with("0x") && (3..=66).contains(&s.len()) && s[2..].bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            let h = &s[2..];
            let padded = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
            (false, hex::decode(padded).unwrap())
        }
        J::Str(s) if is_decimal(s) => (s.starts_with('-'), decimal_to_be(s.trim_start_matches('-'))),
        J::Str(_) => return Err(err(format!("{path} must be a decimal or 0x-hex whole number"))),
        _ => return Err(err(format!("{path} must be a number"))),
    };
    let mag = strip(&magnitude);
    let bit_len = bit_length(mag);
    // unsigned: v < 2^bits. signed: -2^(bits-1) <= v < 2^(bits-1).
    let ok = if !signed {
        !negative && bit_len <= bits
    } else if !negative {
        bit_len < bits
    } else {
        bit_len < bits || (bit_len == bits && is_power_of_two(mag))
    };
    if !ok {
        return Err(err(format!("{path} is out of range for {}{bits}", if signed { "int" } else { "uint" })));
    }
    let mut w = [0u8; 32];
    w[32 - mag.len()..].copy_from_slice(mag);
    if negative && !mag.is_empty() {
        for b in w.iter_mut() {
            *b = !*b;
        }
        for b in w.iter_mut().rev() {
            let (v, carry) = b.overflowing_add(1);
            *b = v;
            if !carry {
                break;
            }
        }
    }
    Ok(w)
}

fn decimal_to_be(digits: &str) -> Vec<u8> {
    let mut out: Vec<u8> = vec![0; 40]; // 80 decimal digits < 2^266
    for d in digits.bytes() {
        let mut carry = (d - b'0') as u32;
        for b in out.iter_mut().rev() {
            let v = *b as u32 * 10 + carry;
            *b = v as u8;
            carry = v >> 8;
        }
    }
    out
}
fn strip(b: &[u8]) -> &[u8] {
    let i = b.iter().position(|&x| x != 0).unwrap_or(b.len());
    &b[i..]
}
fn bit_length(b: &[u8]) -> usize {
    if b.is_empty() {
        0
    } else {
        (b.len() - 1) * 8 + (8 - b[0].leading_zeros() as usize)
    }
}
fn is_power_of_two(b: &[u8]) -> bool {
    !b.is_empty() && b[0].is_power_of_two() && b[1..].iter().all(|&x| x == 0)
}

fn hex_bytes(raw: &J, path: &str) -> Result<Vec<u8>, MessageError> {
    match raw {
        J::Str(s) if s.starts_with("0x") && s.len() % 2 == 0 && s[2..].bytes().all(|b| b.is_ascii_hexdigit()) => {
            Ok(hex::decode(&s[2..]).unwrap())
        }
        _ => Err(err(format!("{path} must be 0x-prefixed hex bytes"))),
    }
}

fn hash_struct(types: &Types, t: &str, raw: &J, path: &str, budget: &mut i64) -> Result<[u8; 32], MessageError> {
    spend(budget)?;
    let m = obj(raw, path)?;
    let fields = &types[t];
    let expected: BTreeSet<&str> = fields.iter().map(|(n, _)| n.as_str()).collect();
    if keys(m) != expected {
        return Err(err(format!("{path} ({t}) fields do not match its type")));
    }
    let mut data = keccak256(encode_type_of(types, t).as_bytes()).to_vec();
    for (name, ft) in fields {
        data.extend(encode_value(types, ft, get(m, name).unwrap(), &format!("{path}.{name}"), budget)?);
    }
    Ok(keccak256(&data))
}

/// Strictly parse `eth_signTypedData_v4` JSON text and compute its EIP-712 digest.
pub fn typed_data_digest(text: &str) -> Result<[u8; 32], MessageError> {
    let (domain_separator, message_hash) = typed_data_hashes(text)?;
    let mut pre = vec![0x19, 0x01];
    pre.extend(domain_separator);
    pre.extend(message_hash);
    Ok(keccak256(&pre))
}

/// Strictly parse `eth_signTypedData_v4` JSON text → (domain separator, message hash).
pub(crate) fn typed_data_hashes(text: &str) -> Result<([u8; 32], [u8; 32]), MessageError> {
    if text.len() > MAX_TYPED_DATA_BYTES {
        return Err(err(format!("typed data exceeds {MAX_TYPED_DATA_BYTES} bytes")));
    }
    let root = parse_json(text).map_err(|e| err(format!("typed data is not strict JSON: {}", e.0)))?;
    let top = obj(&root, "typed data")?;
    exact_keys(top, "typed data", &["types", "primaryType", "domain", "message"])?;
    let types = parse_types(get(top, "types").unwrap())?;
    let J::Str(primary) = get(top, "primaryType").unwrap() else { return Err(err("primaryType must be a string")) };
    if primary == DOMAIN_TYPE {
        return Err(err("primaryType must not be EIP712Domain"));
    }
    if !types.contains_key(primary.as_str()) {
        return Err(err(format!("primaryType {primary} is not defined in types")));
    }
    let mut used = dependencies(&types, primary);
    used.insert(primary.clone());
    used.insert(DOMAIN_TYPE.to_string());
    if let Some(unused) = types.keys().find(|k| !used.contains(*k)) {
        return Err(err(format!("type {unused} is defined but not used")));
    }
    let mut budget = MAX_VALUES;
    let domain_separator = hash_struct(&types, DOMAIN_TYPE, get(top, "domain").unwrap(), "domain", &mut budget)?;
    let message_hash = hash_struct(&types, primary, get(top, "message").unwrap(), "message", &mut budget)?;
    Ok((domain_separator, message_hash))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// EIP-712 `encodeType` of `t` in the typed data `text`.
    pub(crate) fn encode_type(text: &str, t: &str) -> String {
        let root = parse_json(text).unwrap();
        let types = parse_types(get(obj(&root, "").unwrap(), "types").unwrap()).unwrap();
        encode_type_of(&types, t)
    }

    #[test]
    fn strict_json_keeps_numbers_exact_and_refuses_ambiguity() {
        assert_eq!(
            parse_json("{\"a\":115792089237316195423570985008687907853269984665640564039457584007913129639935}")
                .unwrap(),
            J::Obj(vec![(
                "a".into(),
                J::Num("115792089237316195423570985008687907853269984665640564039457584007913129639935".into())
            )])
        );
        assert_eq!(parse_json("[\"\\ud83d\\ude00\\u00e9\"]").unwrap(), J::Arr(vec![J::Str("\u{1F600}\u{e9}".into())]));
        // The same list as MessageRequestTest.strictJsonKeepsNumbersExactAndRefusesAmbiguity on the phone.
        for bad in [
            "{\"a\":1,\"a\":2}",
            "{\"a\":null}",
            "{\"a\":01}",
            "{\"a\":1.}",
            "{\"a\":.5}",
            "{\"a\":+1}",
            "{\"a\":\"\\x41\"}",
            "{\"a\":\"\\ud800\"}",
            "{\"a\":\"\\udc00x\"}",
            "{'a':1}",
            "{\"a\":1,}",
            "[1,]",
            "{\"a\":1} x",
            "",
            "{\"a\":tru}",
            "{\"a\":NaN}",
            "{\"a\":\"line\nbreak\"}",
        ] {
            assert!(parse_json(bad).is_err(), "accepted {bad:?}");
        }
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 2), "]".repeat(MAX_DEPTH + 2));
        assert!(parse_json(&deep).is_err());
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(parse_json(&ok).is_ok());
    }

    #[test]
    fn integers_are_range_checked_and_twos_complement() {
        let n = |s: &str| J::Num(s.into());
        assert_eq!(integer(&n("-1"), true, 8, "x").unwrap(), [0xff; 32]);
        assert_eq!(integer(&n("-128"), true, 8, "x").unwrap()[31], 0x80);
        assert!(integer(&n("-129"), true, 8, "x").is_err());
        assert!(integer(&n("128"), true, 8, "x").is_err());
        assert!(integer(&n("255"), false, 8, "x").is_ok());
        assert!(integer(&n("256"), false, 8, "x").is_err());
        assert!(integer(&J::Str("0xff".into()), true, 8, "x").is_err());
        assert!(integer(&J::Str("-0".into()), false, 8, "x").is_err());
        assert!(integer(&J::Str("0x".into()), false, 8, "x").is_err());
        assert!(integer(&J::Bool(true), false, 8, "x").is_err());
    }
}
