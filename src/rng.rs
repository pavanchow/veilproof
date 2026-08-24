//! Randomness sources for this crate.
//!
//! `DeterministicRng` is a hand-written counter-mode hash DRBG built on the
//! SHA-256 in this crate. It exists so tests (and anyone who wants a
//! reproducible transcript) can drive a proof from a fixed seed and get the
//! same bytes every time. `OsRng` reads real entropy from the operating
//! system and is what CLI commands use for actual nonces.

use crate::error::VeilproofError;
use crate::sha256::sha256;

/// A source of random bytes, implemented by the deterministic hash DRBG. The
/// DRBG cannot fail once seeded, so this stays infallible. Real entropy is
/// pulled once, fallibly, when seeding from the OS (see `from_os`).
pub trait RngCore {
    fn fill_bytes(&mut self, buf: &mut [u8]);
}

/// A seeded, deterministic random byte stream: block `i` is
/// `SHA256(seed || i_be64)`, blocks are concatenated as needed. Same seed,
/// same sequence, every time, on every machine.
pub struct DeterministicRng {
    seed: [u8; 32],
    counter: u64,
}

impl DeterministicRng {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        DeterministicRng { seed, counter: 0 }
    }

    pub fn from_seed_bytes(seed_material: &[u8]) -> Self {
        DeterministicRng {
            seed: sha256(seed_material),
            counter: 0,
        }
    }

    /// Seed the DRBG from 32 bytes of operating-system entropy. This is the
    /// one place the crate touches the OS randomness source, and it does so
    /// fallibly: a read failure comes back as a typed error, never a panic.
    /// Every nonce a proof needs is then expanded deterministically from that
    /// seed, so a single successful read backs a whole run.
    pub fn from_os() -> Result<Self, VeilproofError> {
        use std::io::Read;
        let mut seed = [0u8; 32];
        let mut f = std::fs::File::open("/dev/urandom")
            .map_err(|e| VeilproofError::Entropy(format!("cannot open /dev/urandom: {e}")))?;
        f.read_exact(&mut seed)
            .map_err(|e| VeilproofError::Entropy(format!("cannot read OS entropy: {e}")))?;
        Ok(DeterministicRng::from_seed(seed))
    }

    fn next_block(&mut self) -> [u8; 32] {
        let mut input = Vec::with_capacity(40);
        input.extend_from_slice(&self.seed);
        input.extend_from_slice(&self.counter.to_be_bytes());
        self.counter += 1;
        sha256(&input)
    }
}

impl RngCore for DeterministicRng {
    fn fill_bytes(&mut self, buf: &mut [u8]) {
        let mut filled = 0;
        while filled < buf.len() {
            let block = self.next_block();
            let take = (buf.len() - filled).min(32);
            buf[filled..filled + take].copy_from_slice(&block[..take]);
            filled += take;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_rng_reproducible() {
        let mut a = DeterministicRng::from_seed([7u8; 32]);
        let mut b = DeterministicRng::from_seed([7u8; 32]);
        let mut buf_a = [0u8; 100];
        let mut buf_b = [0u8; 100];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn deterministic_rng_different_seeds_diverge() {
        let mut a = DeterministicRng::from_seed([1u8; 32]);
        let mut b = DeterministicRng::from_seed([2u8; 32]);
        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];
        a.fill_bytes(&mut buf_a);
        b.fill_bytes(&mut buf_b);
        assert_ne!(buf_a, buf_b);
    }
}
