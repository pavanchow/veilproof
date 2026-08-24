//! Schnorr proof of knowledge of a discrete log: prove knowledge of `x` such
//! that `y = g^x mod p`, without revealing `x`.
//!
//! Interactive Sigma protocol:
//!   1. Prover picks random k, sends t = g^k.
//!   2. Verifier sends a random challenge c.
//!   3. Prover replies z = k + c*x mod q.
//!   4. Verifier checks g^z == t * y^c mod p.
//!
//! Made non-interactive with Fiat-Shamir: c = H(g, y, t) mod q, computed by
//! both sides instead of sent over a channel.

use crate::error::VeilproofError;
use crate::group;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use crate::transcript::Transcript;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlogStatement {
    pub y: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DlogProof {
    pub t: BigUint,
    pub z: BigUint,
}

fn build_transcript(y: &BigUint, t: &BigUint) -> Transcript {
    let mut tr = Transcript::new("schnorr-dlog-v1");
    tr.append_element("g", &group::g());
    tr.append_element("y", y);
    tr.append_element("t", t);
    tr
}

/// Prove knowledge of `x` such that `y = g^x mod p`.
pub fn prove(x: &BigUint, rng: &mut impl RngCore) -> (DlogStatement, DlogProof) {
    let p = group::p();
    let g = group::g();
    let x = group::reduce_scalar(x);

    let y = g.modpow(&x, &p);
    let k = group::random_scalar(rng);
    let t = g.modpow(&k, &p);

    let c = build_transcript(&y, &t).challenge_scalar();
    let z = (&k + &c * &x) % group::q();

    (DlogStatement { y }, DlogProof { t, z })
}

/// The raw Fiat-Shamir input for a Schnorr proof: the exact bytes hashed to
/// derive the challenge. Returned alongside the proof so a tracer can show a
/// student the canonicalized transcript that pins the challenge.
pub struct DlogTrace {
    pub transcript_bytes: Vec<u8>,
}

/// Like `prove`, but also returns the exact transcript bytes fed to the
/// Fiat-Shamir hash, for the `--trace` teaching output. The proof itself is
/// identical to what `prove` would produce from the same rng.
pub fn prove_traced(
    x: &BigUint,
    rng: &mut impl RngCore,
) -> (DlogStatement, DlogProof, DlogTrace) {
    let p = group::p();
    let g = group::g();
    let x = group::reduce_scalar(x);

    let y = g.modpow(&x, &p);
    let k = group::random_scalar(rng);
    let t = g.modpow(&k, &p);

    let tr = build_transcript(&y, &t);
    let transcript_bytes = tr.input_bytes();
    let c = tr.challenge_scalar();
    let z = (&k + &c * &x) % group::q();

    (
        DlogStatement { y },
        DlogProof { t, z },
        DlogTrace { transcript_bytes },
    )
}

/// Verify a Schnorr proof of knowledge of a discrete log. Never panics:
/// malformed or out-of-group values are rejected as typed errors.
pub fn verify(stmt: &DlogStatement, proof: &DlogProof) -> Result<bool, VeilproofError> {
    let p = group::p();
    let g = group::g();

    group::check_element(&stmt.y)?;
    group::check_element(&proof.t)?;
    group::check_scalar(&proof.z)?;

    let c = build_transcript(&stmt.y, &proof.t).challenge_scalar();

    let lhs = g.modpow(&proof.z, &p);
    let rhs = (&proof.t * stmt.y.modpow(&c, &p)) % &p;

    Ok(lhs == rhs)
}

impl ProofBytes for DlogStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.y);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let y = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(DlogStatement { y })
    }
}

impl ProofBytes for DlogProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.t);
        w.write_biguint(&self.z);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let t = r.read_biguint()?;
        let z = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(DlogProof { t, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([42u8; 32])
    }

    #[test]
    fn completeness_valid_proof_verifies() {
        let x = BigUint::from(12345u64);
        let (stmt, proof) = prove(&x, &mut rng());
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_wrong_witness_fails() {
        let x1 = BigUint::from(111u64);
        let x2 = BigUint::from(222u64);
        let (_stmt1, proof1) = prove(&x1, &mut rng());
        // A proof built for x1 checked against the statement for x2 must fail.
        let (stmt2, _proof2) = prove(&x2, &mut rng());
        assert!(!verify(&stmt2, &proof1).unwrap());
    }

    #[test]
    fn soundness_tampered_t_fails() {
        let x = BigUint::from(999u64);
        let (stmt, mut proof) = prove(&x, &mut rng());
        let mut t_bytes = proof.t.to_bytes_be();
        let last = t_bytes.len() - 1;
        t_bytes[last] ^= 0x01;
        proof.t = BigUint::from_bytes_be(&t_bytes);
        // A single flipped byte almost always knocks t out of the order-q
        // subgroup entirely, which verify() correctly rejects as a typed
        // error rather than accepting. Either outcome (Err, or Ok(false))
        // is a rejection, the only thing that must never happen is Ok(true).
        match verify(&stmt, &proof) {
            Ok(accepted) => assert!(!accepted, "tampered t must not verify"),
            Err(_) => {}
        }
    }

    #[test]
    fn soundness_tampered_z_fails() {
        let x = BigUint::from(999u64);
        let (stmt, mut proof) = prove(&x, &mut rng());
        proof.z = (&proof.z + BigUint::from(1u32)) % group::q();
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn determinism_same_seed_same_proof() {
        let x = BigUint::from(555u64);
        let (stmt1, proof1) = prove(&x, &mut DeterministicRng::from_seed([9u8; 32]));
        let (stmt2, proof2) = prove(&x, &mut DeterministicRng::from_seed([9u8; 32]));
        assert_eq!(stmt1, stmt2);
        assert_eq!(proof1, proof2);
    }

    #[test]
    fn zero_knowledge_witness_not_in_serialized_bytes() {
        // A witness value chosen to be distinctive in its byte pattern.
        let x = BigUint::from(0xDEADBEEFu64);
        let (stmt, proof) = prove(&x, &mut rng());
        let mut all_bytes = stmt.to_bytes();
        all_bytes.extend(proof.to_bytes());
        let x_bytes = x.to_bytes_be();
        assert!(
            !all_bytes
                .windows(x_bytes.len())
                .any(|w| w == x_bytes.as_slice()),
            "witness bytes must never appear in the serialized proof"
        );
    }

    #[test]
    fn serialization_round_trips() {
        let x = BigUint::from(4242u64);
        let (stmt, proof) = prove(&x, &mut rng());
        let stmt2 = DlogStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let proof2 = DlogProof::from_bytes(&proof.to_bytes()).unwrap();
        assert_eq!(stmt, stmt2);
        assert_eq!(proof, proof2);
        assert!(verify(&stmt2, &proof2).unwrap());
    }

    #[test]
    fn hex_round_trips() {
        let x = BigUint::from(77u64);
        let (stmt, proof) = prove(&x, &mut rng());
        let hex = proof.to_hex();
        let proof2 = DlogProof::from_hex(&hex).unwrap();
        assert_eq!(proof, proof2);
        assert!(verify(&stmt, &proof2).unwrap());
    }

    #[test]
    fn hostile_statement_rejected_not_panicking() {
        let bad = DlogStatement { y: BigUint::from(1u32) };
        let (_ok_stmt, proof) = prove(&BigUint::from(5u64), &mut rng());
        let result = verify(&bad, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn hostile_t_out_of_range_rejected() {
        let x = BigUint::from(5u64);
        let (stmt, mut proof) = prove(&x, &mut rng());
        proof.t = group::p(); // t == p is out of [1, p)
        assert!(verify(&stmt, &proof).is_err());
    }
}
