//! Range proof that a committed value lies in `[0, 2^n)`, built by
//! committing to each bit of the value separately, proving each bit
//! commitment is honestly a bit with the OR-proof in `bit_proof`, and tying
//! the bits back to the value commitment through the Pedersen homomorphism:
//!
//!   C = product_i (C_i)^(2^i)  =  g^(sum b_i 2^i) * h^(sum r_i 2^i)
//!     =  g^m * h^r
//!
//! as long as the prover picks the overall blinding `r = sum r_i * 2^i mod
//! q`. A verifier who only sees the bit commitments and their OR-proofs, and
//! recomputes that product, is convinced `m` is a sum of n verified bits and
//! therefore in `[0, 2^n)`, without learning `m` or any individual bit.
//!
//! `n` is kept modest (this crate supports up to 32) since the proof size
//! and verification cost are both linear in `n`.

pub const MAX_BITS: u32 = 32;

use crate::bit_proof::{self, BitProof, BitStatement};
use crate::error::VeilproofError;
use crate::group;
use crate::pedersen::Commitment;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeStatement {
    pub c: BigUint,
    pub n: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RangeProof {
    pub bit_commitments: Vec<BigUint>,
    pub bit_proofs: Vec<BitProof>,
}

/// Prove that `m` lies in `[0, 2^n)`. Returns an error, rather than a
/// broken proof, if `m` is not actually in that range or `n` exceeds
/// `MAX_BITS`: this construction cannot be honestly run on an out-of-range
/// value, there is no witness to feed it.
pub fn prove(
    m: &BigUint,
    n: u32,
    rng: &mut impl RngCore,
) -> Result<(RangeStatement, RangeProof, BigUint), VeilproofError> {
    if n == 0 || n > MAX_BITS {
        return Err(VeilproofError::RangeTooLarge(format!(
            "n must be in 1..={MAX_BITS}, got {n}"
        )));
    }
    let bound = BigUint::from(2u32).pow(n);
    if m >= &bound {
        return Err(VeilproofError::InvalidWitness(format!(
            "value is not in [0, 2^{n}), no honest range proof exists"
        )));
    }

    let mut bit_commitments = Vec::with_capacity(n as usize);
    let mut bit_proofs = Vec::with_capacity(n as usize);
    let mut r_total = BigUint::from(0u32);

    for i in 0..n {
        let bit = m.bit(i as u64);
        let r_i = group::random_scalar(rng);
        let (stmt, proof) = bit_proof::prove(bit, &r_i, rng);
        bit_commitments.push(stmt.c);
        bit_proofs.push(proof);

        let weight = BigUint::from(2u32).pow(i);
        r_total = (r_total + &r_i * &weight) % group::q();
    }

    let commitment = Commitment(
        crate::pedersen::commit(m, &r_total).0,
    );

    Ok((
        RangeStatement { c: commitment.0, n },
        RangeProof { bit_commitments, bit_proofs },
        r_total,
    ))
}

/// Verify a range proof: every bit commitment must carry a valid bit
/// OR-proof, and the weighted product of the bit commitments must
/// reconstruct the claimed value commitment exactly.
pub fn verify(stmt: &RangeStatement, proof: &RangeProof) -> Result<bool, VeilproofError> {
    if stmt.n == 0 || stmt.n > MAX_BITS {
        return Err(VeilproofError::RangeTooLarge(format!(
            "n must be in 1..={MAX_BITS}, got {}",
            stmt.n
        )));
    }
    if proof.bit_commitments.len() != stmt.n as usize || proof.bit_proofs.len() != stmt.n as usize
    {
        return Err(VeilproofError::InvalidProof(
            "bit commitment or bit proof count does not match n".to_string(),
        ));
    }

    group::check_element(&stmt.c)?;

    let p = group::p();
    let mut acc = BigUint::from(1u32);

    for (i, (ci, bp)) in proof
        .bit_commitments
        .iter()
        .zip(proof.bit_proofs.iter())
        .enumerate()
    {
        group::check_element(ci)?;
        let bit_stmt = BitStatement { c: ci.clone() };
        if !bit_proof::verify(&bit_stmt, bp)? {
            return Ok(false);
        }
        let weight = BigUint::from(2u32).pow(i as u32);
        acc = (&acc * ci.modpow(&weight, &p)) % &p;
    }

    Ok(acc == stmt.c)
}

impl ProofBytes for RangeStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_biguint(&self.c);
        w.write_u32(self.n);
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let c = r.read_biguint()?;
        let n = r.read_u32()?;
        r.expect_exhausted()?;
        Ok(RangeStatement { c, n })
    }
}

impl ProofBytes for RangeProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.bit_commitments.len() as u32);
        for c in &self.bit_commitments {
            w.write_biguint(c);
        }
        for bp in &self.bit_proofs {
            let inner = bp.to_bytes();
            w.write_u32(inner.len() as u32);
            w.buf_extend(&inner);
        }
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let count = r.read_u32()? as usize;
        if count > MAX_BITS as usize {
            return Err(VeilproofError::RangeTooLarge(
                "declared bit count exceeds MAX_BITS".to_string(),
            ));
        }
        let mut bit_commitments = Vec::with_capacity(count);
        for _ in 0..count {
            bit_commitments.push(r.read_biguint()?);
        }
        let mut bit_proofs = Vec::with_capacity(count);
        for _ in 0..count {
            let len = r.read_u32()? as usize;
            let chunk = r.read_bytes(len)?;
            bit_proofs.push(BitProof::from_bytes(&chunk)?);
        }
        r.expect_exhausted()?;
        Ok(RangeProof { bit_commitments, bit_proofs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([77u8; 32])
    }

    #[test]
    fn completeness_value_in_range_verifies() {
        let (stmt, proof, _r) = prove(&BigUint::from(42u32), 8, &mut rng()).unwrap();
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn completeness_zero_and_max_endpoints() {
        let (stmt0, proof0, _) = prove(&BigUint::from(0u32), 6, &mut rng()).unwrap();
        assert!(verify(&stmt0, &proof0).unwrap());

        let max_val = BigUint::from(2u32).pow(6) - BigUint::from(1u32);
        let (stmt_max, proof_max, _) = prove(&max_val, 6, &mut rng()).unwrap();
        assert!(verify(&stmt_max, &proof_max).unwrap());
    }

    #[test]
    fn out_of_range_value_cannot_be_honestly_proven() {
        let too_big = BigUint::from(2u32).pow(8); // exactly 2^8, out of [0, 2^8)
        let result = prove(&too_big, 8, &mut rng());
        assert!(result.is_err());
    }

    #[test]
    fn forged_out_of_range_proof_fails() {
        // Build a real, valid 4-bit proof for value 5, then splice in an
        // extra high bit commitment that would push the represented value
        // to 5 + 16 = 21, outside [0, 2^4). The verifier's weighted-product
        // check must catch commitment/statement mismatch.
        let (stmt, mut proof, _r) = prove(&BigUint::from(5u32), 4, &mut rng()).unwrap();
        let (extra_stmt, extra_proof) = bit_proof::prove(true, &BigUint::from(3u32), &mut rng());
        proof.bit_commitments[0] = extra_stmt.c;
        proof.bit_proofs[0] = extra_proof;
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_tampered_bit_commitment_fails() {
        let (stmt, mut proof, _r) = prove(&BigUint::from(10u32), 5, &mut rng()).unwrap();
        // Swap in a validly-formed but different bit commitment.
        let (alt_stmt, alt_proof) = bit_proof::prove(false, &BigUint::from(1u32), &mut rng());
        proof.bit_commitments[2] = alt_stmt.c;
        proof.bit_proofs[2] = alt_proof;
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn zero_knowledge_witness_not_in_bytes() {
        let m = BigUint::from(0x1337u32);
        let (stmt, proof, _r) = prove(&m, 16, &mut rng()).unwrap();
        let mut bytes = stmt.to_bytes();
        bytes.extend(proof.to_bytes());
        let m_bytes = m.to_bytes_be();
        assert!(!bytes.windows(m_bytes.len()).any(|w| w == m_bytes.as_slice()));
    }

    #[test]
    fn determinism() {
        let (s1, p1, r1) = prove(&BigUint::from(3u32), 4, &mut DeterministicRng::from_seed([5u8; 32])).unwrap();
        let (s2, p2, r2) = prove(&BigUint::from(3u32), 4, &mut DeterministicRng::from_seed([5u8; 32])).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(p1, p2);
        assert_eq!(r1, r2);
    }

    #[test]
    fn round_trip_serialization() {
        let (stmt, proof, _r) = prove(&BigUint::from(9u32), 5, &mut rng()).unwrap();
        let s2 = RangeStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let p2 = RangeProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(verify(&s2, &p2).unwrap());
    }

    #[test]
    fn rejects_n_too_large() {
        assert!(prove(&BigUint::from(1u32), 33, &mut rng()).is_err());
    }
}
