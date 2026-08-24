//! OR-proof that a Pedersen commitment `C = g^b * h^r mod p` opens to
//! `b in {0, 1}`, without revealing which. Standard Cramer-Damgard-
//! Schoenmakers simulated-branch composition of two Schnorr proofs (base
//! `h`) made non-interactive with Fiat-Shamir.
//!
//! The two branches are discrete-log statements w.r.t. base `h`:
//!   branch 0: target0 = C,             claim: target0 = h^r  (true iff b=0)
//!   branch 1: target1 = C * g^-1,      claim: target1 = h^r  (true iff b=1)
//!
//! The prover genuinely proves the branch matching the real bit, and
//! *simulates* the other branch (picking its response and challenge first,
//! then solving for a commitment that satisfies the verification equation).
//! The single Fiat-Shamir challenge `c` is split as `c = c0 + c1 mod q`; the
//! prover is only able to produce a real challenge share for the branch it
//! actually knows, so a value that is not a bit (0 or 1) cannot be proven.

use crate::error::VeilproofError;
use crate::group;
use crate::pedersen::Commitment;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use crate::transcript::Transcript;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitStatement {
    pub c: BigUint,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BitProof {
    pub t0: BigUint,
    pub t1: BigUint,
    pub c0: BigUint,
    pub c1: BigUint,
    pub z0: BigUint,
    pub z1: BigUint,
}

fn targets(c: &BigUint) -> (BigUint, BigUint) {
    let p = group::p();
    let g_inv = group::subgroup_inverse(&group::g());
    let target0 = c.clone();
    let target1 = (c * &g_inv) % &p;
    (target0, target1)
}

fn build_transcript(c: &BigUint, t0: &BigUint, t1: &BigUint) -> Transcript {
    let mut tr = Transcript::new("bit-or-proof-v1");
    tr.append_element("g", &group::g());
    tr.append_element("h", &group::h());
    tr.append_element("c", c);
    tr.append_element("t0", t0);
    tr.append_element("t1", t1);
    tr
}

/// Prove that the commitment to bit `b` (0 or 1) with blinding `r` opens
/// honestly. `b` is a `bool` at the API level specifically so a caller
/// cannot even attempt to pass a non-bit value in.
pub fn prove(b: bool, r: &BigUint, rng: &mut impl RngCore) -> (BitStatement, BitProof) {
    let p = group::p();
    let h = group::h();
    let q = group::q();
    let r = group::reduce_scalar(r);

    let m = if b { BigUint::from(1u32) } else { BigUint::from(0u32) };
    let commitment = Commitment((&group::g().modpow(&m, &p) * &h.modpow(&r, &p)) % &p);
    let (target0, target1) = targets(&commitment.0);

    let (t0, t1, c0, c1, z0, z1) = if !b {
        // Real branch is 0: we know r such that target0 = h^r.
        let k0 = group::random_scalar(rng);
        let t0 = h.modpow(&k0, &p);

        // Simulate branch 1.
        let z1 = group::random_scalar(rng);
        let c1 = group::random_scalar(rng);
        let target1_inv = group::subgroup_inverse(&target1);
        let t1 = (&h.modpow(&z1, &p) * &target1_inv.modpow(&c1, &p)) % &p;

        let c = build_transcript(&commitment.0, &t0, &t1).challenge_scalar();
        let c0 = ((&c + &q) - &c1) % &q;
        let z0 = (&k0 + &c0 * &r) % &q;

        (t0, t1, c0, c1, z0, z1)
    } else {
        // Real branch is 1: we know r such that target1 = h^r.
        let k1 = group::random_scalar(rng);
        let t1 = h.modpow(&k1, &p);

        // Simulate branch 0.
        let z0 = group::random_scalar(rng);
        let c0 = group::random_scalar(rng);
        let target0_inv = group::subgroup_inverse(&target0);
        let t0 = (&h.modpow(&z0, &p) * &target0_inv.modpow(&c0, &p)) % &p;

        let c = build_transcript(&commitment.0, &t0, &t1).challenge_scalar();
        let c1 = ((&c + &q) - &c0) % &q;
        let z1 = (&k1 + &c1 * &r) % &q;

        (t0, t1, c0, c1, z0, z1)
    };

    (
        BitStatement { c: commitment.0 },
        BitProof { t0, t1, c0, c1, z0, z1 },
    )
}

pub fn verify(stmt: &BitStatement, proof: &BitProof) -> Result<bool, VeilproofError> {
    let p = group::p();
    let q = group::q();
    let h = group::h();

    group::check_element(&stmt.c)?;
    group::check_element(&proof.t0)?;
    group::check_element(&proof.t1)?;
    group::check_scalar(&proof.c0)?;
    group::check_scalar(&proof.c1)?;
    group::check_scalar(&proof.z0)?;
    group::check_scalar(&proof.z1)?;

    let (target0, target1) = targets(&stmt.c);

    let expected_c = build_transcript(&stmt.c, &proof.t0, &proof.t1).challenge_scalar();
    if (&proof.c0 + &proof.c1) % &q != expected_c {
        return Ok(false);
    }

    let lhs0 = h.modpow(&proof.z0, &p);
    let rhs0 = (&proof.t0 * target0.modpow(&proof.c0, &p)) % &p;
    if lhs0 != rhs0 {
        return Ok(false);
    }

    let lhs1 = h.modpow(&proof.z1, &p);
    let rhs1 = (&proof.t1 * target1.modpow(&proof.c1, &p)) % &p;
    if lhs1 != rhs1 {
        return Ok(false);
    }

    Ok(true)
}

impl ProofBytes for BitStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.c);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let c = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(BitStatement { c })
    }
}

impl ProofBytes for BitProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.t0);
        w.write_biguint(&self.t1);
        w.write_biguint(&self.c0);
        w.write_biguint(&self.c1);
        w.write_biguint(&self.z0);
        w.write_biguint(&self.z1);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let t0 = r.read_biguint()?;
        let t1 = r.read_biguint()?;
        let c0 = r.read_biguint()?;
        let c1 = r.read_biguint()?;
        let z0 = r.read_biguint()?;
        let z1 = r.read_biguint()?;
        r.expect_exhausted()?;
        Ok(BitProof { t0, t1, c0, c1, z0, z1 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([21u8; 32])
    }

    #[test]
    fn completeness_bit_zero_verifies() {
        let (stmt, proof) = prove(false, &BigUint::from(7u32), &mut rng());
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn completeness_bit_one_verifies() {
        let (stmt, proof) = prove(true, &BigUint::from(9u32), &mut rng());
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_forged_non_bit_commitment_fails() {
        // Hand-craft a commitment to the value 2 (not a bit) and attempt to
        // forge an OR-proof for it by simulating both branches freely, with
        // no real branch to anchor the challenge split.
        let p = group::p();
        let q = group::q();
        let mut r = rng();
        let r_val = BigUint::from(13u32);
        let m = BigUint::from(2u32); // not a bit
        let commitment =
            Commitment((&group::g().modpow(&m, &p) * &group::h().modpow(&r_val, &p)) % &p);

        let z0 = group::random_scalar(&mut r);
        let c0 = group::random_scalar(&mut r);
        let z1 = group::random_scalar(&mut r);
        let c1 = group::random_scalar(&mut r);
        let (target0, target1) = targets(&commitment.0);
        let t0 = (&group::h().modpow(&z0, &p)
            * &group::subgroup_inverse(&target0).modpow(&c0, &p))
            % &p;
        let t1 = (&group::h().modpow(&z1, &p)
            * &group::subgroup_inverse(&target1).modpow(&c1, &p))
            % &p;

        // These fully-simulated branches only satisfy the verification
        // equations for the challenge split (c0, c1) chosen here, but the
        // *real* Fiat-Shamir challenge over (commitment, t0, t1) is
        // essentially never equal to c0 + c1 mod q for a value that is not
        // an honestly-composed bit proof.
        let expected_c = build_transcript(&commitment.0, &t0, &t1).challenge_scalar();
        assert_ne!((&c0 + &c1) % &q, expected_c);

        let forged = BitStatement { c: commitment.0 };
        let forged_proof = BitProof { t0, t1, c0, c1, z0, z1 };
        assert!(!verify(&forged, &forged_proof).unwrap());
    }

    #[test]
    fn soundness_tampered_proof_fails() {
        let (stmt, mut proof) = prove(true, &BigUint::from(4u32), &mut rng());
        proof.z1 = (&proof.z1 + BigUint::from(1u32)) % group::q();
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn zero_knowledge_bit_value_not_directly_serialized() {
        // The bit itself (0 or 1) never appears as a standalone field: the
        // proof only carries commitments and Sigma-protocol responses.
        let (_stmt, proof) = prove(true, &BigUint::from(2u32), &mut rng());
        let bytes = proof.to_bytes();
        // A crude but concrete check: the single-byte encodings of 0 and 1
        // do not appear as a length-prefixed one-byte field anywhere, i.e.
        // there is no 4-byte length prefix of exactly 1 immediately
        // followed by 0x00 or 0x01.
        let mut suspicious = false;
        for w in bytes.windows(5) {
            if w[0..4] == [0, 0, 0, 1] && (w[4] == 0x00 || w[4] == 0x01) {
                suspicious = true;
            }
        }
        assert!(!suspicious, "a raw single-byte 0/1 field leaked the bit");
    }

    #[test]
    fn round_trip_serialization() {
        let (stmt, proof) = prove(false, &BigUint::from(3u32), &mut rng());
        let s2 = BitStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let p2 = BitProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(verify(&s2, &p2).unwrap());
    }

    #[test]
    fn determinism() {
        let a = prove(true, &BigUint::from(5u32), &mut DeterministicRng::from_seed([4u8; 32]));
        let b = prove(true, &BigUint::from(5u32), &mut DeterministicRng::from_seed([4u8; 32]));
        assert_eq!(a, b);
    }
}
