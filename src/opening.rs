//! Proof of knowledge of a Pedersen commitment opening: given a public
//! commitment `C = g^m * h^r mod p`, prove knowledge of `(m, r)` without
//! revealing either.
//!
//! Sigma protocol:
//!   1. Prover picks random k_m, k_r, sends t = g^k_m * h^k_r.
//!   2. Challenge c = H(g, h, C, t) mod q.
//!   3. Prover replies z_m = k_m + c*m mod q, z_r = k_r + c*r mod q.
//!   4. Verifier checks g^z_m * h^z_r == t * C^c mod p.

use crate::error::VeilproofError;
use crate::group;
use crate::pedersen::Commitment;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use crate::transcript::Transcript;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningStatement {
    pub c: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpeningProof {
    pub t: BigUint,
    pub z_m: BigUint,
    pub z_r: BigUint,
}

fn build_transcript(c: &BigUint, t: &BigUint) -> Transcript {
    let mut tr = Transcript::new("pedersen-opening-v1");
    tr.append_element("g", &group::g());
    tr.append_element("h", &group::h());
    tr.append_element("c", c);
    tr.append_element("t", t);
    tr
}

/// Prove knowledge of the opening `(m, r)` of commitment `C = commit(m, r)`.
pub fn prove(
    m: &BigUint,
    r: &BigUint,
    rng: &mut impl RngCore,
) -> (OpeningStatement, OpeningProof) {
    let p = group::p();
    let g = group::g();
    let h = group::h();
    let q = group::q();

    let m = group::reduce_scalar(m);
    let r = group::reduce_scalar(r);

    let c_commit = Commitment(( &g.modpow(&m, &p) * &h.modpow(&r, &p) ) % &p);

    let k_m = group::random_scalar(rng);
    let k_r = group::random_scalar(rng);
    let t = (&g.modpow(&k_m, &p) * &h.modpow(&k_r, &p)) % &p;

    let chal = build_transcript(&c_commit.0, &t).challenge_scalar();

    let z_m = (&k_m + &chal * &m) % &q;
    let z_r = (&k_r + &chal * &r) % &q;

    (
        OpeningStatement { c: c_commit.0 },
        OpeningProof { t, z_m, z_r },
    )
}

pub fn verify(stmt: &OpeningStatement, proof: &OpeningProof) -> Result<bool, VeilproofError> {
    let p = group::p();
    let g = group::g();
    let h = group::h();

    group::check_element(&stmt.c)?;
    group::check_element(&proof.t)?;
    group::check_scalar(&proof.z_m)?;
    group::check_scalar(&proof.z_r)?;

    let chal = build_transcript(&stmt.c, &proof.t).challenge_scalar();

    let lhs = (&g.modpow(&proof.z_m, &p) * &h.modpow(&proof.z_r, &p)) % &p;
    let rhs = (&proof.t * stmt.c.modpow(&chal, &p)) % &p;

    Ok(lhs == rhs)
}

impl ProofBytes for OpeningStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.c);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let c = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(OpeningStatement { c })
    }
}

impl ProofBytes for OpeningProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.t);
        w.write_biguint(&self.z_m);
        w.write_biguint(&self.z_r);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let t = r.read_biguint()?;
        let z_m = r.read_biguint()?;
        let z_r = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(OpeningProof { t, z_m, z_r })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([3u8; 32])
    }

    #[test]
    fn completeness_valid_opening_verifies() {
        let (stmt, proof) = prove(&BigUint::from(42u32), &BigUint::from(17u32), &mut rng());
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_wrong_witness_fails() {
        let (stmt, _proof) = prove(&BigUint::from(42u32), &BigUint::from(17u32), &mut rng());
        let (_stmt2, proof2) = prove(&BigUint::from(43u32), &BigUint::from(17u32), &mut rng());
        assert!(!verify(&stmt, &proof2).unwrap());
    }

    #[test]
    fn soundness_tampered_proof_fails() {
        let (stmt, mut proof) = prove(&BigUint::from(8u32), &BigUint::from(2u32), &mut rng());
        proof.z_m = (&proof.z_m + BigUint::from(1u32)) % group::q();
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn determinism() {
        let a = prove(&BigUint::from(1u32), &BigUint::from(1u32), &mut DeterministicRng::from_seed([1u8;32]));
        let b = prove(&BigUint::from(1u32), &BigUint::from(1u32), &mut DeterministicRng::from_seed([1u8;32]));
        assert_eq!(a, b);
    }

    #[test]
    fn zero_knowledge_witness_not_in_bytes() {
        let m = BigUint::from(0xABCDEFu32);
        let (stmt, proof) = prove(&m, &BigUint::from(999u32), &mut rng());
        let mut bytes = stmt.to_bytes();
        bytes.extend(proof.to_bytes());
        let m_bytes = m.to_bytes_be();
        assert!(!bytes.windows(m_bytes.len()).any(|w| w == m_bytes.as_slice()));
    }

    #[test]
    fn round_trip_serialization() {
        let (stmt, proof) = prove(&BigUint::from(5u32), &BigUint::from(6u32), &mut rng());
        let s2 = OpeningStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let p2 = OpeningProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(verify(&s2, &p2).unwrap());
    }
}
