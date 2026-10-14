//! Native messaging frame codec (also used on the companion socket).

use std::io::{Read, Write};

/// Native messaging framing: a 32-bit length in native byte order, then that many bytes of UTF-8
/// JSON. The same framing is used on the companion socket. `Ok(None)` is a clean end of stream.
pub fn read_frame(r: &mut impl Read, max: usize) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_ne_bytes(len) as usize;
    if n > max {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, format!("frame of {n} bytes exceeds {max}")));
    }
    let mut body = vec![0u8; n];
    r.read_exact(&mut body)?;
    Ok(Some(body))
}

pub fn write_frame(w: &mut impl Write, body: &[u8], max: usize) -> std::io::Result<()> {
    if body.len() > max {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("frame of {} bytes exceeds {max}", body.len()),
        ));
    }
    let mut buf = Vec::with_capacity(body.len() + 4);
    buf.extend_from_slice(&(body.len() as u32).to_ne_bytes());
    buf.extend_from_slice(body);
    w.write_all(&buf)?;
    w.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_cap() {
        let mut buf = vec![];
        write_frame(&mut buf, br#"{"a":1}"#, 100).unwrap();
        assert_eq!(&buf[..4], &7u32.to_ne_bytes());
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 100).unwrap().unwrap(), br#"{"a":1}"#);
        assert!(read_frame(&mut r, 100).unwrap().is_none(), "clean EOF");
        assert!(write_frame(&mut vec![], &[0u8; 101], 100).is_err());
        let mut big = (1_000_000u32).to_ne_bytes().to_vec();
        big.extend_from_slice(b"xx");
        assert!(read_frame(&mut &big[..], 1000).is_err(), "oversize length refused before reading");
        let mut short = 10u32.to_ne_bytes().to_vec();
        short.extend_from_slice(b"abc");
        assert!(read_frame(&mut &short[..], 100).is_err(), "truncated body");
    }
}
