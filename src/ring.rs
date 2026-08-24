//! 1-of-n ring proof: given a public list of keys `y_0 .. y_{n-1}` with each
//! `y_i = g^{x_i} mod p`, prove knowledge of the secret `x_j` behind ONE of
//! them without revealing which `j`. This is the anonymity primitive behind
//! ring signatures and "I am an authorized member of this set" statements.
//!
//! It is an n-way Cramer-Damgard-Schoenmakers OR of Schnorr discrete-log
//! proofs (base `g`). The prover runs the real Sigma protocol for the one
//! index it knows and simulates every other index by choosing that index's
//! response and challenge share first, then solving for a commitment that
//! satisfies the verification equation. A single Fiat-Shamir challenge `c`
//! ties them together: the shares must sum to `c mod q`, and only the index
//! whose secret the prover actually holds can have its share pinned last.
//!
//! Verifier equations, for every i in 0..n:
//!   g^{z_i} == t_i * y_i^{c_i} mod p,   and   sum_i c_i == H(g, y*, t*) mod q.

use crate::error::VeilproofError;
use crate::group;
use crate::rng::RngCore;
use crate::serialize::{ProofBytes, Reader, Writer};
use crate::transcript::Transcript;
use num_bigint::BigUint;

/// Upper bound on ring size, so a hostile serialized proof cannot ask the
/// verifier to allocate an unbounded number of ring entries.
pub const MAX_RING: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingStatement {
    pub ys: Vec<BigUint>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RingProof {
    pub ts: Vec<BigUint>,
    pub cs: Vec<BigUint>,
    pub zs: Vec<BigUint>,
}

fn build_transcript(ys: &[BigUint], ts: &[BigUint]) -> Transcript {
    let mut tr = Transcript::new("ring-1-of-n-v1");
    tr.append_element("g", &group::g());
    tr.append_u32("n", ys.len() as u32);
    for (i, y) in ys.iter().enumerate() {
        tr.append_u32("yi", i as u32);
        tr.append_element("y", y);
    }
    for (i, t) in ts.iter().enumerate() {
        tr.append_u32("ti", i as u32);
        tr.append_element("t", t);
    }
    tr
}

/// Prove knowledge of the discrete log of `ys[index]`. The full public ring
/// `ys` is supplied by the caller (the decoys are other people's public
/// keys); this function checks that the witness genuinely opens the claimed
/// index before building anything, so it can never emit a proof it does not
/// hold the secret for.
pub fn prove(
    x: &BigUint,
    index: usize,
    ys: &[BigUint],
    rng: &mut impl RngCore,
) -> Result<(RingStatement, RingProof), VeilproofError> {
    let p = group::p();
    let q = group::q();
    let g = group::g();
    let n = ys.len();

    if n == 0 || n > MAX_RING {
        return Err(VeilproofError::RangeTooLarge(format!(
            "ring size must be in 1..={MAX_RING}, got {n}"
        )));
    }
    if index >= n {
        return Err(VeilproofError::InvalidWitness(
            "index is outside the ring".to_string(),
        ));
    }
    let x = group::reduce_scalar(x);
    if g.modpow(&x, &p) != ys[index] {
        return Err(VeilproofError::InvalidWitness(
            "witness does not open ys[index]".to_string(),
        ));
    }

    let mut ts = vec![BigUint::from(0u32); n];
    let mut cs = vec![BigUint::from(0u32); n];
    let mut zs = vec![BigUint::from(0u32); n];

    // Simulate every decoy branch, and remember the running sum of their
    // challenge shares so the real branch can absorb the remainder.
    let mut c_others = BigUint::from(0u32);
    for (i, yi) in ys.iter().enumerate() {
        if i == index {
            continue;
        }
        let zi = group::random_scalar(rng);
        let ci = group::random_scalar(rng);
        let yi_inv = group::subgroup_inverse(yi);
        // t_i = g^{z_i} * y_i^{-c_i}, which forces g^{z_i} == t_i * y_i^{c_i}.
        ts[i] = (&g.modpow(&zi, &p) * &yi_inv.modpow(&ci, &p)) % &p;
        cs[i] = ci.clone();
        zs[i] = zi;
        c_others = (&c_others + &ci) % &q;
    }

    // Real branch: commit honestly, then pin its challenge share last.
    let k = group::random_scalar(rng);
    ts[index] = g.modpow(&k, &p);

    let c = build_transcript(ys, &ts).challenge_scalar();
    // c_index = c - sum(other shares) mod q.
    let c_index = ((&c + &q) - (&c_others % &q)) % &q;
    let z_index = (&k + &c_index * &x) % &q;
    cs[index] = c_index;
    zs[index] = z_index;

    Ok((RingStatement { ys: ys.to_vec() }, RingProof { ts, cs, zs }))
}

/// Verify a ring proof: the challenge shares must sum to the Fiat-Shamir
/// challenge over the whole ring, and every branch's Schnorr equation must
/// hold. Never panics on malformed input.
pub fn verify(stmt: &RingStatement, proof: &RingProof) -> Result<bool, VeilproofError> {
    let p = group::p();
    let q = group::q();
    let g = group::g();
    let n = stmt.ys.len();

    if n == 0 || n > MAX_RING {
        return Err(VeilproofError::RangeTooLarge(format!(
            "ring size must be in 1..={MAX_RING}, got {n}"
        )));
    }
    if proof.ts.len() != n || proof.cs.len() != n || proof.zs.len() != n {
        return Err(VeilproofError::InvalidProof(
            "ring proof component counts do not match the ring size".to_string(),
        ));
    }

    for y in &stmt.ys {
        group::check_element(y)?;
    }
    for t in &proof.ts {
        group::check_element(t)?;
    }
    for c in &proof.cs {
        group::check_scalar(c)?;
    }
    for z in &proof.zs {
        group::check_scalar(z)?;
    }

    let expected_c = build_transcript(&stmt.ys, &proof.ts).challenge_scalar();
    let mut c_sum = BigUint::from(0u32);
    for c in &proof.cs {
        c_sum = (&c_sum + c) % &q;
    }
    if c_sum != expected_c {
        return Ok(false);
    }

    for i in 0..n {
        let lhs = g.modpow(&proof.zs[i], &p);
        let rhs = (&proof.ts[i] * stmt.ys[i].modpow(&proof.cs[i], &p)) % &p;
        if lhs != rhs {
            return Ok(false);
        }
    }

    Ok(true)
}

impl ProofBytes for RingStatement {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.ys.len() as u32);
        for y in &self.ys {
            w.write_biguint(y);
        }
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let n = r.read_u32()? as usize;
        if n > MAX_RING {
            return Err(VeilproofError::RangeTooLarge(
                "declared ring size exceeds MAX_RING".to_string(),
            ));
        }
        let mut ys = Vec::with_capacity(n);
        for _ in 0..n {
            ys.push(r.read_biguint()?);
        }
        r.expect_exhausted()?;
        Ok(RingStatement { ys })
    }
}

impl ProofBytes for RingProof {
    fn to_bytes(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.write_u32(self.ts.len() as u32);
        for t in &self.ts {
            w.write_biguint(t);
        }
        for c in &self.cs {
            w.write_biguint(c);
        }
        for z in &self.zs {
            w.write_biguint(z);
        }
        w.into_bytes()
    }

    fn from_bytes(data: &[u8]) -> Result<Self, VeilproofError> {
        let mut r = Reader::new(data);
        let n = r.read_u32()? as usize;
        if n > MAX_RING {
            return Err(VeilproofError::RangeTooLarge(
                "declared ring size exceeds MAX_RING".to_string(),
            ));
        }
        let mut ts = Vec::with_capacity(n);
        for _ in 0..n {
            ts.push(r.read_biguint()?);
        }
        let mut cs = Vec::with_capacity(n);
        for _ in 0..n {
            cs.push(r.read_biguint()?);
        }
        let mut zs = Vec::with_capacity(n);
        for _ in 0..n {
            zs.push(r.read_biguint()?);
        }
        r.expect_exhausted()?;
        Ok(RingProof { ts, cs, zs })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rng::DeterministicRng;

    fn rng() -> DeterministicRng {
        DeterministicRng::from_seed([55u8; 32])
    }

    /// Build a ring of `n` public keys where the caller knows the secret at
    /// `index`, and return (secret, index, ys).
    fn build_ring(n: usize, index: usize, r: &mut impl RngCore) -> (BigUint, usize, Vec<BigUint>) {
        let p = group::p();
        let g = group::g();
        let mut ys = Vec::with_capacity(n);
        let mut secret = BigUint::from(0u32);
        for i in 0..n {
            let xi = group::random_scalar(r);
            if i == index {
                secret = xi.clone();
            }
            ys.push(g.modpow(&xi, &p));
        }
        (secret, index, ys)
    }

    #[test]
    fn completeness_various_positions_verify() {
        for index in [0usize, 2, 4] {
            let mut r = rng();
            let (x, idx, ys) = build_ring(5, index, &mut r);
            let (stmt, proof) = prove(&x, idx, &ys, &mut r).unwrap();
            assert!(verify(&stmt, &proof).unwrap(), "ring proof at index {index} must verify");
        }
    }

    #[test]
    fn completeness_ring_of_one() {
        let mut r = rng();
        let (x, idx, ys) = build_ring(1, 0, &mut r);
        let (stmt, proof) = prove(&x, idx, &ys, &mut r).unwrap();
        assert!(verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn prover_without_the_secret_is_rejected() {
        // The caller claims index 1 but hands the secret for a key that is
        // not at index 1: prove() must refuse rather than emit a bad proof.
        let mut r = rng();
        let (_x, _idx, ys) = build_ring(4, 2, &mut r);
        let wrong_secret = BigUint::from(999u64);
        assert!(prove(&wrong_secret, 1, &ys, &mut r).is_err());
    }

    #[test]
    fn soundness_tampered_response_fails() {
        let mut r = rng();
        let (x, idx, ys) = build_ring(4, 1, &mut r);
        let (stmt, mut proof) = prove(&x, idx, &ys, &mut r).unwrap();
        proof.zs[3] = (&proof.zs[3] + BigUint::from(1u32)) % group::q();
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn soundness_forged_ring_of_strangers_fails() {
        // A forger who knows NO secret in the ring picks all challenge shares
        // and responses freely. The branch equations can be satisfied, but the
        // shares will not sum to the real Fiat-Shamir challenge.
        let mut r = rng();
        let p = group::p();
        let g = group::g();
        let n = 3;
        let mut ys = Vec::new();
        for _ in 0..n {
            let xi = group::random_scalar(&mut r);
            ys.push(g.modpow(&xi, &p));
        }
        let mut ts = Vec::new();
        let mut cs = Vec::new();
        let mut zs = Vec::new();
        for yi in &ys {
            let zi = group::random_scalar(&mut r);
            let ci = group::random_scalar(&mut r);
            let yi_inv = group::subgroup_inverse(yi);
            ts.push((&g.modpow(&zi, &p) * &yi_inv.modpow(&ci, &p)) % &p);
            cs.push(ci);
            zs.push(zi);
        }
        let stmt = RingStatement { ys };
        let proof = RingProof { ts, cs, zs };
        assert!(!verify(&stmt, &proof).unwrap());
    }

    #[test]
    fn anonymity_proof_shape_does_not_reveal_index() {
        // Two proofs over the SAME ring, one made at index 0 and one at index
        // 3, must be structurally identical: the number of commitments,
        // challenge shares, and responses is the same regardless of which
        // position held the real secret. That structural symmetry is what
        // hides the index. (Exact byte length can still wobble by a byte
        // because a big-endian bignum drops leading zeros, an encoding
        // artifact unrelated to the secret index, so it is not asserted here.)
        let mut r2 = DeterministicRng::from_seed([200u8; 32]);
        let p = group::p();
        let g = group::g();
        let mut secrets = Vec::new();
        let mut keys = Vec::new();
        for _ in 0..5 {
            let xi = group::random_scalar(&mut r2);
            secrets.push(xi.clone());
            keys.push(g.modpow(&xi, &p));
        }
        let mut r = rng();
        let (s_a, p_a) = prove(&secrets[0], 0, &keys, &mut r).unwrap();
        let (s_b, p_b) = prove(&secrets[3], 3, &keys, &mut r).unwrap();
        assert!(verify(&s_a, &p_a).unwrap());
        assert!(verify(&s_b, &p_b).unwrap());
        assert_eq!(p_a.ts.len(), p_b.ts.len());
        assert_eq!(p_a.cs.len(), p_b.cs.len());
        assert_eq!(p_a.zs.len(), p_b.zs.len());
    }

    #[test]
    fn determinism_same_seed_same_proof() {
        let (x, idx, ys) = build_ring(4, 2, &mut DeterministicRng::from_seed([12u8; 32]));
        let a = prove(&x, idx, &ys, &mut DeterministicRng::from_seed([13u8; 32])).unwrap();
        let b = prove(&x, idx, &ys, &mut DeterministicRng::from_seed([13u8; 32])).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn round_trip_serialization() {
        let mut r = rng();
        let (x, idx, ys) = build_ring(4, 1, &mut r);
        let (stmt, proof) = prove(&x, idx, &ys, &mut r).unwrap();
        let s2 = RingStatement::from_bytes(&stmt.to_bytes()).unwrap();
        let p2 = RingProof::from_bytes(&proof.to_bytes()).unwrap();
        assert!(verify(&s2, &p2).unwrap());
    }

    #[test]
    fn oversize_ring_is_rejected() {
        let mut r = rng();
        let big: Vec<BigUint> = (0..(MAX_RING + 1))
            .map(|_| group::g().modpow(&group::random_scalar(&mut r), &group::p()))
            .collect();
        assert!(prove(&BigUint::from(1u32), 0, &big, &mut r).is_err());
        let stmt = RingStatement { ys: big };
        let proof = RingProof { ts: vec![], cs: vec![], zs: vec![] };
        assert!(verify(&stmt, &proof).is_err());
    }

    #[test]
    fn hostile_element_rejected_not_panicking() {
        let mut r = rng();
        let (x, idx, ys) = build_ring(3, 0, &mut r);
        let (mut stmt, proof) = prove(&x, idx, &ys, &mut r).unwrap();
        stmt.ys[1] = BigUint::from(1u32); // identity
        assert!(verify(&stmt, &proof).is_err());
    }
}
