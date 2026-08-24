//! Chaum-Pedersen proof of equality of two discrete logs: prove knowledge of
//! a single `x` such that `y1 = g^x mod p` AND `y2 = h^x mod p`, without
//! revealing `x`. This is what convinces a verifier that two public values
//! share the same secret exponent, the workhorse behind verifiable shuffles,
//! DLEQ proofs, and "this ciphertext was re-encrypted honestly" statements.
//!
//! Sigma protocol:
//!   1. Prover picks random k, sends t1 = g^k, t2 = h^k.
//!   2. Verifier sends a random challenge c.
//!   3. Prover replies z = k + c*x mod q.
//!   4. Verifier checks g^z == t1 * y1^c mod p AND h^z == t2 * y2^c mod p.
//!
//! Made non-interactive with Fiat-Shamir: c = H(g, h, y1, y2, t1, t2) mod q.
//! Because a single `z` has to satisfy both equations at once, the only way
//! to pass is for `y1` and `y2` to really share one exponent.

use crate::error::VeilproofError;
use crate::group;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use crate::transcript::Transcript;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DleqStatement {
    pub y1: BigUint,
    pub y2: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DleqProof {
    pub t1: BigUint,
    pub t2: BigUint,
    pub z: BigUint,
}

fn build_transcript(y1: &BigUint, y2: &BigUint, t1: &BigUint, t2: &BigUint) -> Transcript {
    let mut tr = Transcript::new("chaum-pedersen-dleq-v1");
    tr.append_element("g", &group::g());
    tr.append_element("h", &group::h());
    tr.append_element("y1", y1);
    tr.append_element("y2", y2);
    tr.append_element("t1", t1);
    tr.append_element("t2", t2);
    tr
}

/// Prove that `y1 = g^x` and `y2 = h^x` share the same exponent `x`.
pub fn prove(x: &BigUint, rng: &mut impl RngCore) -> (DleqStatement, DleqProof) {
    let p = group::p();
    let g = group::g();
    let h = group::h();
    let x = group::reduce_scalar(x);

    let y1 = g.modpow(&x, &p);
    let y2 = h.modpow(&x, &p);

    let k = group::random_scalar(rng);
    let t1 = g.modpow(&k, &p);
    let t2 = h.modpow(&k, &p);

    let c = build_transcript(&y1, &y2, &t1, &t2).challenge_scalar();
    let z = (&k + &c * &x) % group::q();

    (DleqStatement { y1, y2 }, DleqProof { t1, t2, z })
}

/// Verify a Chaum-Pedersen equality proof. Never panics: every element is
/// subgroup-checked and every scalar range-checked before the arithmetic.
pub fn verify(stmt: &DleqStatement, proof: &DleqProof) -> Result<bool, VeilproofError> {
    let p = group::p();
    let g = group::g();
    let h = group::h();

    group::check_element(&stmt.y1)?;
    group::check_element(&stmt.y2)?;
    group::check_element(&proof.t1)?;
    group::check_element(&proof.t2)?;
    group::check_scalar(&proof.z)?;

    let c = build_transcript(&stmt.y1, &stmt.y2, &proof.t1, &proof.t2).challenge_scalar();

    let lhs1 = g.modpow(&proof.z, &p);
    let rhs1 = (&proof.t1 * stmt.y1.modpow(&c, &p)) % &p;
    if lhs1 != rhs1 {
        return Ok(false);
    }

    let lhs2 = h.modpow(&proof.z, &p);
    let rhs2 = (&proof.t2 * stmt.y2.modpow(&c, &p)) % &p;
    Ok(lhs2 == rhs2)
}

impl ProofBytes for DleqStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.y1);
        w.write_biguint(&self.y2);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let y1 = r.read_biguint()?;
        let y2 = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(DleqStatement { y1, y2 })
    }
}

impl ProofBytes for DleqProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.t1);
        w.write_biguint(&self.t2);
        w.write_biguint(&self.z);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let t1 = r.read_biguint()?;
        let t2 = r.read_biguint()?;
        let z = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(DleqProof { t1, t2, z })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([64u8; 32])
    }

    #[test]
    fn completeness_equal_exponents_verify() {
        let (stmt, proof) = prove(&BigUint::from(31337u64), &mut rng());
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_unequal_exponents_fail() {
        // Build a statement where y1 and y2 use DIFFERENT exponents, then try
        // to attach a proof to it. No honest prover can, and a proof made for
        // one matched statement will not verify against this mismatched one.
        let p = group::p();
        let g = group::g();
        let h = group::h();
        let y1 = g.modpow(&BigUint::from(5u64), &p);
        let y2 = h.modpow(&BigUint::from(6u64), &p); // different exponent
        let mismatched = DleqStatement { y1, y2 };
        let (_ok_stmt, proof) = prove(&BigUint::from(5u64), &mut rng());
        assert!(!verify(&mismatched, &proof).unwrap());
    }

    #[test]
    fn soundness_tampered_z_fails() {
        let (stmt, mut proof) = prove(&BigUint::from(88u64), &mut rng());
        proof.z = (&proof.z + BigUint::from(1u32)) % group::q();
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_swapped_t_fails() {
        // Swapping t1 and t2 breaks the two-equation binding.
        let (stmt, proof) = prove(&BigUint::from(88u64), &mut rng());
        let swapped = DleqProof {
            t1: proof.t2.clone(),
            t2: proof.t1.clone(),
            z: proof.z.clone(),
        };
        assert!(!verify(&stmt, &swapped).unwrap());
    }

    #[test]
    fn zero_knowledge_witness_not_in_serialized_bytes() {
        let x = BigUint::from(0xC0FFEEu64);
        let (stmt, proof) = prove(&x, &mut rng());
        let mut all = stmt.to_bytes();
        all.extend(proof.to_bytes());
        let xb = x.to_bytes_be();
        assert!(!all.windows(xb.len()).any(|w| w == xb.as_slice()));
    }

    #[test]
    fn determinism_same_seed_same_proof() {
        let a = prove(&BigUint::from(9u64), &mut DeterministicRng::from_seed([3u8; 32]));
        let b = prove(&BigUint::from(9u64), &mut DeterministicRng::from_seed([3u8; 32]));
        assert_eq!(a, b);
    }

    #[test]
    fn round_trip_serialization() {
        let (stmt, proof) = prove(&BigUint::from(1234u64), &mut rng());
        let s2 = DleqStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let p2 = DleqProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(verify(&s2, &p2).unwrap());
    }

    #[test]
    fn hostile_element_rejected_not_panicking() {
        let (mut stmt, proof) = prove(&BigUint::from(7u64), &mut rng());
        stmt.y1 = BigUint::from(1u32); // identity, rejected
        assert!(verify(&stmt, &proof).is_err());
    }
}
