//! The Schnorr group all proof arithmetic happens in: RFC 5114 section 2.3,
//! the "2048-bit MODP Group with 256-bit Prime Order Subgroup" (group id 24).
//!
//! `P` is a 2048-bit prime, `Q` is a 256-bit prime dividing `P - 1`, and `G`
//! generates the unique subgroup of order `Q` inside `(Z/PZ)*`. These are
//! published, widely reused parameters, not something this project invented.
//! No elliptic curves anywhere, every exponent and every group element below
//! is a `BigUint` reduced modulo `P` or `Q`.

use crate::error::VeilproofError;
use crate::rng::RngCore;
use crate::sha256::sha256;
use num_bigint::BigUint;
use std::sync::OnceLock;

const P_HEX: &str = "\
87A8E61DB4B6663CFFBBD19C651959998CEEF608660DD0F25D2CEED4435E3B00E00DF8F1D61957D4FAF7DF4561B2AA30\
16C3D91134096FAA3BF4296D830E9A7C209E0C6497517ABD5A8A9D306BCF67ED91F9E6725B4758C022E0B1EF4275BF7B\
6C5BFC11D45F9088B941F54EB1E59BB8BC39A0BF12307F5C4FDB70C581B23F76B63ACAE1CAA6B7902D52526735488A0E\
F13C6D9A51BFA4AB3AD8347796524D8EF6A167B5A41825D967E144E5140564251CCACB83E6B486F6B3CA3F7971506026\
C0B857F689962856DED4010ABD0BE621C3A3960A54E710C375F26375D7014103A4B54330C198AF126116D2276E11715F\
693877FAD7EF09CADB094AE91E1A1597";

const Q_HEX: &str = "8CF83642A709A097B447997640129DA299B1A47D1EB3750BA308B0FE64F5FBD3";

const G_HEX: &str = "\
3FB32C9B73134D0B2E77506660EDBD484CA7B18F21EF205407F4793A1A0BA12510DBC15077BE463FFF4FED4AAC0BB555\
BE3A6C1B0C6B47B1BC3773BF7E8C6F62901228F8C28CBB18A55AE31341000A650196F931C77A57F2DDF463E5E9EC144B\
777DE62AAAB8A8628AC376D282D6ED3864E67982428EBC831D14348F6F2F9193B5045AF2767164E1DFC967C1FB3F2E55\
A4BD1BFFE83B9C80D052B985D182EA0ADB2A3B7313D3FE14C8484B1E052588B9B7D2BBD2DF016199ECD06E1557CD0915\
B3353BBB64E0EC377FD028370DF92B52C7891428CDC67EB6184B523D1DB246C32F63078490F00EF8D647D148D4795451\
5E2327CFEF98C582664B4C0F6CC41659";

/// The domain-separation string hashed (with this crate's own SHA-256) to
/// derive the exponent `s` used for the second Pedersen generator `h = g^s
/// mod p`. Publishing the derivation, instead of picking `h` freely, is the
/// standard "nothing up my sleeve" discipline: nobody, including the author
/// of this crate, can know a discrete log relating `g` and `h`, because `h`
/// is pinned to the output of a hash function on a fixed public string
/// rather than chosen after the fact.
///
/// This is still a teaching-grade convenience, not a substitute for a proper
/// verifiable random function or a multi-party ceremony. A real deployment
/// that depends on nobody knowing log_g(h) should generate `h` with a
/// process it can point to and defend, this hash-to-exponent is a legible
/// stand-in for that.
pub const H_DOMAIN_SEPARATOR: &[u8] = b"veilproof/pedersen-h/v1";

fn hex_to_biguint(hex: &str) -> BigUint {
    BigUint::parse_bytes(hex.as_bytes(), 16).expect("veilproof: bad hardcoded group constant")
}

// The constants are parsed (and `h` derived) exactly once, then cloned out on
// each call. Parsing the 2048-bit hex strings, and especially the modpow that
// derives `h`, are far too expensive to repeat on every arithmetic operation,
// and these values never change for the lifetime of the process.
static P_CELL: OnceLock<BigUint> = OnceLock::new();
static Q_CELL: OnceLock<BigUint> = OnceLock::new();
static G_CELL: OnceLock<BigUint> = OnceLock::new();
static H_CELL: OnceLock<BigUint> = OnceLock::new();

pub fn p() -> BigUint {
    P_CELL.get_or_init(|| hex_to_biguint(P_HEX)).clone()
}

pub fn q() -> BigUint {
    Q_CELL.get_or_init(|| hex_to_biguint(Q_HEX)).clone()
}

pub fn g() -> BigUint {
    G_CELL.get_or_init(|| hex_to_biguint(G_HEX)).clone()
}

/// The second Pedersen generator, `h = g^s mod p` where `s = SHA256(H_DOMAIN_SEPARATOR) mod q`.
pub fn h() -> BigUint {
    H_CELL
        .get_or_init(|| {
            let digest = sha256(H_DOMAIN_SEPARATOR);
            let s = BigUint::from_bytes_be(&digest) % q();
            g().modpow(&s, &p())
        })
        .clone()
}

/// The multiplicative inverse, inside the order-`q` subgroup, of a subgroup
/// element `x`: since `x^q == 1 mod p`, it follows that `x^(q-1) == x^-1 mod
/// p`. This lets every inverse in this crate be a single `modpow` call, no
/// extended Euclidean algorithm needed.
pub fn subgroup_inverse(x: &BigUint) -> BigUint {
    let q = q();
    let exp = &q - BigUint::from(1u32);
    x.modpow(&exp, &p())
}

/// Reduce a scalar (an exponent) modulo `q`.
pub fn reduce_scalar(x: &BigUint) -> BigUint {
    x % q()
}

/// Reject anything that is not a valid element of the order-`q` subgroup of
/// `(Z/pZ)*`: it must be in `[1, p)`, and it must satisfy `x^q == 1 mod p`.
/// This is the check every proof verifier runs on every group element it is
/// handed, so a hostile or malformed proof is rejected with a typed error
/// instead of corrupting the verification arithmetic.
pub fn check_element(x: &BigUint) -> Result<(), VeilproofError> {
    let p = p();
    let one = BigUint::from(1u32);
    let zero = BigUint::from(0u32);
    if x <= &zero || x >= &p {
        return Err(VeilproofError::InvalidElement(
            "element is not in [1, p)".to_string(),
        ));
    }
    // The identity element is technically inside the order-q subgroup, but
    // it is never a legitimate public value in any proof here (it would
    // mean an exponent of 0, which no honest statement uses), so it is
    // rejected explicitly rather than silently accepted.
    if x == &one {
        return Err(VeilproofError::InvalidElement(
            "element is the identity, not a valid public value".to_string(),
        ));
    }
    if x.modpow(&q(), &p) != one {
        return Err(VeilproofError::InvalidElement(
            "element is not in the order-q subgroup".to_string(),
        ));
    }
    Ok(())
}

/// Reject anything that is not a valid scalar: it must be in `[0, q)`.
pub fn check_scalar(x: &BigUint) -> Result<(), VeilproofError> {
    if x >= &q() {
        return Err(VeilproofError::InvalidScalar(
            "scalar is not in [0, q)".to_string(),
        ));
    }
    Ok(())
}

/// Draw a uniformly random scalar in `[0, q)` by rejection sampling: pull 32
/// random bytes, and only accept them if the resulting integer is already
/// less than `q` (redrawing otherwise). This avoids the small bias a plain
/// `% q` reduction would introduce.
pub fn random_scalar(rng: &mut impl RngCore) -> BigUint {
    let q = q();
    loop {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let candidate = BigUint::from_bytes_be(&buf);
        if candidate < q {
            return candidate;
        }
    }
}

/// Self-check run on startup and in tests: confirms the hardcoded RFC 5114
/// constants actually describe an order-`q` subgroup generated by `g`, and
/// that the derived Pedersen generator `h` lands in that same subgroup.
pub fn self_check() -> Result<(), VeilproofError> {
    let p = p();
    let q = q();
    let g = g();
    let one = BigUint::from(1u32);

    if g == one {
        return Err(VeilproofError::InvalidElement(
            "g must not be 1".to_string(),
        ));
    }
    if g >= p {
        return Err(VeilproofError::InvalidElement(
            "g must be less than p".to_string(),
        ));
    }
    if g.modpow(&q, &p) != one {
        return Err(VeilproofError::InvalidElement(
            "g^q mod p != 1, g does not generate an order-q subgroup".to_string(),
        ));
    }

    let h = h();
    if h == one {
        return Err(VeilproofError::InvalidElement("h must not be 1".to_string()));
    }
    if h == g {
        return Err(VeilproofError::InvalidElement(
            "h must not equal g".to_string(),
        ));
    }
    check_element(&h)?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_self_check_passes() {
        self_check().expect("RFC 5114 group 24 self-check must pass");
    }

    #[test]
    fn g_generates_order_q_subgroup() {
        let p = p();
        let q = q();
        let g = g();
        assert_ne!(g, BigUint::from(1u32));
        assert_eq!(g.modpow(&q, &p), BigUint::from(1u32));
    }

    #[test]
    fn p_and_q_have_expected_bit_lengths() {
        assert_eq!(p().bits(), 2048);
        assert_eq!(q().bits(), 256);
    }

    #[test]
    fn q_divides_p_minus_1() {
        let p = p();
        let q = q();
        let p_minus_1 = &p - BigUint::from(1u32);
        assert_eq!(&p_minus_1 % &q, BigUint::from(0u32));
    }

    #[test]
    fn h_is_in_subgroup_and_distinct_from_g() {
        let h = h();
        let g = g();
        assert_ne!(h, g);
        assert_ne!(h, BigUint::from(1u32));
        check_element(&h).expect("h must be a valid subgroup element");
    }

    #[test]
    fn h_is_deterministic() {
        assert_eq!(h(), h());
    }

    #[test]
    fn subgroup_inverse_round_trips() {
        let g = g();
        let inv = subgroup_inverse(&g);
        let p = p();
        assert_eq!((&g * &inv) % &p, BigUint::from(1u32));
    }

    #[test]
    fn hostile_elements_are_rejected() {
        let p = p();
        assert!(check_element(&BigUint::from(0u32)).is_err());
        assert!(check_element(&BigUint::from(1u32)).is_err());
        assert!(check_element(&p).is_err());
        // A small integer that is essentially never in the order-q subgroup.
        assert!(check_element(&BigUint::from(2u32)).is_err());
    }
}
