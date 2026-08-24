# Veilproof

**A zero-knowledge proof system in Rust that you can read end to end, no black box, no elliptic curves, no crypto crates.**

Veilproof is a small, from-scratch toolkit for proving you know a secret, or that a hidden number satisfies a property, without ever revealing the secret itself. Every piece of cryptography in it, the modular arithmetic, the hash function, the challenge derivation, the proof composition, is written out in the open so a reader can follow exactly why a verifier is convinced, and exactly why a liar gets caught.

## What it is

All arithmetic happens in the RFC 5114 "2048-bit MODP Group with 256-bit Prime Order Subgroup" (group id 24), a classic Schnorr group with a published, well-known generator. There are no elliptic curves anywhere in this codebase. SHA-256, the seeded deterministic RNG, and every Sigma protocol are hand-written, the only third-party crates are `num-bigint` and `num-integer` for the bignum backend and `clap` for the command line.

## Proofs supported

- **Schnorr proof of knowledge of a discrete log**: prove you know `x` such that `y = g^x mod p`, without revealing `x`.
- **Pedersen commitment opening proof**: prove you know `(m, r)` behind a public commitment `C = g^m * h^r mod p`, without revealing either.
- **Bit OR-proof**: prove a Pedersen-committed value is exactly 0 or 1, without saying which, using the standard simulated-branch OR composition.
- **Range proof**: prove a committed value lies in `[0, 2^n)` for a modest `n` (up to 32), by composing `n` bit proofs and tying them back to the value commitment through the Pedersen homomorphism.
- **Chaum-Pedersen equality proof**: prove one secret `x` satisfies both `y1 = g^x mod p` and `y2 = h^x mod p`, so two public values share the same exponent, without revealing `x`.
- **1-of-n ring proof**: given a public list of keys, prove you know the secret behind one of them without revealing which, the anonymity primitive behind ring signatures, built as an n-way OR.

Every Sigma protocol above is made non-interactive with the Fiat-Shamir transform: the verifier's random challenge is replaced with a SHA-256 hash of the full transcript and statement, reduced modulo the group order.

## Teaching-grade, not audited, do not use in production

This project exists to be read and to be correct on the properties it claims, not to be a production cryptography library. It has not been audited, it has not been reviewed by anyone outside this project, and it makes convenience choices (documented in `DESIGN.md`) that a real deployment should not inherit blindly, most notably the derivation of the second Pedersen generator `h`. Do not use Veilproof to protect anything that matters.

## Usage

Build and test:

```
cargo build --release
cargo test
```

Prove and verify a discrete-log statement:

```
veilproof prove-dlog --secret 424242
# prints a statement (y) and a proof (t, z), both hex-encoded

veilproof verify-dlog --statement <hex> --proof <hex>
# prints accept or reject
```

Prove one secret sits behind two public values on different bases:

```
veilproof prove-dleq --secret 424242
veilproof verify-dleq --statement <hex> --proof <hex>
```

Prove membership in a ring of keys without revealing which one is yours:

```
veilproof ring-demo --size 5 --index 2
```

Run the full range-proof demo:

```
veilproof demo
```

This builds a Pedersen commitment to a hidden 16-bit value, produces a 16-bit range proof from bit commitments and OR-proofs, verifies it, and prints the transcript, with the secret value and blinding factor deliberately withheld from the output.

## Library

Everything above is also a plain Rust library (`veilproof`), with typed errors instead of panics: a proof built from out-of-range or non-subgroup elements is rejected with a `VeilproofError`, never a crash, even on hostile input.

```rust
use num_bigint::BigUint;
use veilproof::{schnorr, rng::DeterministicRng};

let mut rng = DeterministicRng::from_seed([7u8; 32]);
let (statement, proof) = schnorr::prove(&BigUint::from(42u32), &mut rng);
assert!(schnorr::verify(&statement, &proof).unwrap());
```

## Browser demo

`docs/index.html` is a self-contained, dependency-free port of the same math to JavaScript, using native `BigInt`, the same group constants, the same hand-written SHA-256, and the same Fiat-Shamir logic. A proof produced in the browser verifies by the same equations as a proof produced by the Rust code, and vice versa.

By Pavan Nallamothu.
