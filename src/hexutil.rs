//! Plain hex encode/decode, written from scratch (no crate does this for us).

use crate::error::VeilproofError;

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

pub fn decode(s: &str) -> Result<Vec<u8>, VeilproofError> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(VeilproofError::Deserialization(
            "hex string has odd length".to_string(),
        ));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8, VeilproofError> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(VeilproofError::Deserialization(format!(
            "invalid hex digit: {}",
            c as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let data = vec![0u8, 1, 2, 254, 255, 16, 32];
        let hex = encode(&data);
        let back = decode(&hex).unwrap();
        assert_eq!(data, back);
    }

    #[test]
    fn rejects_odd_length() {
        assert!(decode("abc").is_err());
    }

    #[test]
    fn rejects_bad_digit() {
        assert!(decode("zz").is_err());
    }
}
