//! Byte and hex serialization for statements and proofs. The wire format is
//! deliberately simple: every field is a big-endian integer written as a
//! 4-byte length prefix followed by that many bytes, fields appear in a
//! fixed declared order, and there is nothing else in the buffer. That
//! makes every proof type below trivial to encode, decode, and reject if
//! truncated or malformed, no panics on any input.

use crate::error::VeilproofError;
use crate::hexutil;
use num_bigint::BigUint;

pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer { buf: Vec::new() }
    }

    pub fn write_biguint(&mut self, x: &BigUint) {
        let bytes = x.to_bytes_be();
        self.buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        self.buf.extend_from_slice(&bytes);
    }

    pub fn write_u32(&mut self, x: u32) {
        self.buf.extend_from_slice(&x.to_be_bytes());
    }

    pub fn buf_extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

impl Default for Writer {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn read_biguint(&mut self) -> Result<BigUint, VeilproofError> {
        let len = self.read_u32()? as usize;
        if self.pos + len > self.data.len() {
            return Err(VeilproofError::Deserialization(
                "buffer too short for declared field length".to_string(),
            ));
        }
        let bytes = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Ok(BigUint::from_bytes_be(bytes))
    }

    pub fn read_bytes(&mut self, len: usize) -> Result<Vec<u8>, VeilproofError> {
        if self.pos + len > self.data.len() {
            return Err(VeilproofError::Deserialization(
                "buffer too short for requested byte span".to_string(),
            ));
        }
        let out = self.data[self.pos..self.pos + len].to_vec();
        self.pos += len;
        Ok(out)
    }

    pub fn read_u32(&mut self) -> Result<u32, VeilproofError> {
        if self.pos + 4 > self.data.len() {
            return Err(VeilproofError::Deserialization(
                "buffer too short for length prefix".to_string(),
            ));
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.data[self.pos..self.pos + 4]);
        self.pos += 4;
        Ok(u32::from_be_bytes(b))
    }

    pub fn expect_exhausted(&self) -> Result<(), VeilproofError> {
        if self.pos != self.data.len() {
            return Err(VeilproofError::Deserialization(
                "trailing bytes after decoding all expected fields".to_string(),
            ));
        }
        Ok(())
    }
}

/// A type that can be turned into a canonical byte encoding and back.
pub trait ProofBytes: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError>;

    fn to_hex(&self) -> String {
        hexutil::encode(&self.to_bytes())
    }

    fn from_hex(s: &str) -> Result<Self, VeilproofError> {
        let bytes = hexutil::decode(s)?;
        Self::from_bytes(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_reader_round_trip() {
        let mut w = Writer::new();
        w.write_biguint(&BigUint::from(12345u32));
        w.write_u32(7);
        w.write_biguint(&BigUint::from(0u32));
        let bytes = w.into_bytes();

        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_biguint().unwrap(), BigUint::from(12345u32));
        assert_eq!(r.read_u32().unwrap(), 7);
        assert_eq!(r.read_biguint().unwrap(), BigUint::from(0u32));
        r.expect_exhausted().unwrap();
    }

    #[test]
    fn reader_rejects_truncated_buffer() {
        let mut w = Writer::new();
        w.write_biguint(&BigUint::from(999u32));
        let mut bytes = w.into_bytes();
        bytes.truncate(bytes.len() - 1);
        let mut r = Reader::new(&bytes);
        assert!(r.read_biguint().is_err());
    }

    #[test]
    fn reader_rejects_trailing_bytes() {
        let mut w = Writer::new();
        w.write_u32(1);
        let mut bytes = w.into_bytes();
        bytes.push(0xff);
        let mut r = Reader::new(&bytes);
        let _ = r.read_u32().unwrap();
        assert!(r.expect_exhausted().is_err());
    }
}
