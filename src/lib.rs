//! Veilproof: a from-scratch zero-knowledge proof toolkit in Rust.
//!
//! Everything happens in the RFC 5114 "2048-bit MODP Group with 256-bit
//! Prime Order Subgroup" (group id 24), a Schnorr group with a hardcoded,
//! self-checked generator. No elliptic curves. The only third-party crates
//! are `num-bigint` and `num-integer` for the bignum backend, and `clap` for
//! the command line. SHA-256, the Fiat-Shamir transform, the deterministic
//! RNG, and every Sigma protocol are implemented in this crate.
//!
//! This is teaching-grade code: readable end to end, tested for
//! completeness and soundness, but not audited. Do not use it in
//! production.

pub mod bit_proof;
pub mod chaum_pedersen;
pub mod error;
pub mod group;
pub mod hexutil;
pub mod opening;
pub mod pedersen;
pub mod range_proof;
pub mod ring;
pub mod rng;
pub mod schnorr;
pub mod serialize;
pub mod sha256;
pub mod transcript;

pub use error::VeilproofError;
