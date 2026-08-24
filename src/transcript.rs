//! The Fiat-Shamir transform: turn an interactive Sigma protocol into a
//! non-interactive one by replacing the verifier's random challenge with a
//! hash of the entire statement and the prover's first message. Every proof
//! in this crate builds one of these, appends every public value in a fixed
//! order, and reduces the hash output modulo q to get its challenge.

use crate::group;
use crate::sha256::sha256;
use num_bigint::BigUint;

pub struct Transcript {
    buf: Vec<u8>,
}

impl Transcript {
    /// Start a transcript labeled with the protocol name, so that a
    /// challenge computed for one proof type can never collide with a
    /// challenge computed for another, even over identical group elements.
    pub fn new(label: &str) -> Self {
        let mut t = Transcript { buf: Vec::new() };
        t.append_bytes(b"veilproof-transcript-v1");
        t.append_bytes(label.as_bytes());
        t
    }

    /// Append length-prefixed bytes, so two different sequences of fields
    /// can never hash to the same transcript by having their boundaries
    /// slide (classic canonicalization bug this avoids).
    pub fn append_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(&(data.len() as u64).to_be_bytes());
        self.buf.extend_from_slice(data);
    }

    pub fn append_element(&mut self, label: &str, x: &BigUint) {
        self.append_bytes(label.as_bytes());
        self.append_bytes(&x.to_bytes_be());
    }

    pub fn append_u32(&mut self, label: &str, x: u32) {
        self.append_bytes(label.as_bytes());
        self.append_bytes(&x.to_be_bytes());
    }

    /// The Fiat-Shamir challenge: SHA-256 of the full transcript so far,
    /// interpreted as a big-endian integer and reduced modulo q.
    pub fn challenge_scalar(&self) -> BigUint {
        let digest = sha256(&self.buf);
        BigUint::from_bytes_be(&digest) % group::q()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_is_deterministic() {
        let mut t1 = Transcript::new("test");
        t1.append_element("x", &BigUint::from(5u32));
        let mut t2 = Transcript::new("test");
        t2.append_element("x", &BigUint::from(5u32));
        assert_eq!(t1.challenge_scalar(), t2.challenge_scalar());
    }

    #[test]
    fn challenge_is_sensitive_to_labels_not_just_bytes() {
        // Same bytes, different field boundaries, must not collide.
        let mut t1 = Transcript::new("test");
        t1.append_bytes(b"ab");
        t1.append_bytes(b"cd");
        let mut t2 = Transcript::new("test");
        t2.append_bytes(b"a");
        t2.append_bytes(b"bcd");
        assert_ne!(t1.challenge_scalar(), t2.challenge_scalar());
    }

    #[test]
    fn challenge_is_less_than_q() {
        let mut t = Transcript::new("test");
        t.append_element("x", &BigUint::from(123456789u64));
        assert!(t.challenge_scalar() < group::q());
    }
}
