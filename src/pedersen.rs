//! Pedersen commitments: `C = g^m * h^r mod p`, hiding `m` behind a random
//! blinding factor `r` while staying additively homomorphic.

use crate::group;
use num_bigint::BigUint;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commitment(pub BigUint);

/// Commit to `m` with blinding `r`. Both are reduced modulo q before use,
/// matching the fact that exponents in this group only matter mod q.
pub fn commit(m: &BigUint, r: &BigUint) -> Commitment {
    let p = group::p();
    let m = group::reduce_scalar(m);
    let r = group::reduce_scalar(r);
    let gm = group::g().modpow(&m, &p);
    let hr = group::h().modpow(&r, &p);
    Commitment((&gm * &hr) % &p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_is_deterministic_for_same_inputs() {
        let a = commit(&BigUint::from(5u32), &BigUint::from(9u32));
        let b = commit(&BigUint::from(5u32), &BigUint::from(9u32));
        assert_eq!(a, b);
    }

    #[test]
    fn different_blinding_gives_different_commitment() {
        let a = commit(&BigUint::from(5u32), &BigUint::from(9u32));
        let b = commit(&BigUint::from(5u32), &BigUint::from(10u32));
        assert_ne!(a, b);
    }

    #[test]
    fn commitment_is_a_valid_group_element() {
        let c = commit(&BigUint::from(3u32), &BigUint::from(7u32));
        group::check_element(&c.0).expect("commitment must land in the subgroup");
    }

    #[test]
    fn homomorphic_addition() {
        // C(m1, r1) * C(m2, r2) == C(m1+m2, r1+r2)
        let p = group::p();
        let c1 = commit(&BigUint::from(3u32), &BigUint::from(11u32));
        let c2 = commit(&BigUint::from(4u32), &BigUint::from(13u32));
        let product = (&c1.0 * &c2.0) % &p;
        let combined = commit(&BigUint::from(7u32), &BigUint::from(24u32));
        assert_eq!(product, combined.0);
    }
}
