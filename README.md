<img src="docs/logo.svg" alt="Veilproof logo" width="96">

# Veilproof: a zero-knowledge proof system in Rust

Veilproof is a zero-knowledge proof system written from scratch in Rust, with no crypto crates and no elliptic curves, that you can read end to end. It is a small toolkit of Sigma protocols (Schnorr, Pedersen, bit OR, range, Chaum-Pedersen equality, and 1-of-n ring proofs) made non-interactive with Fiat-Shamir, letting you prove you know a secret, or that a hidden number satisfies a property, without ever revealing it. It is a teaching-grade, dependency-light reference for learning how zero-knowledge proofs actually work, not a production library.

**[Live demo](https://pavanchow.github.io/veilproof/)** · MIT licensed · written in Rust · teaching-grade, not audited

Built from scratch by [Pavan Nallamothu](https://pavanchow.github.io/) ([LinkedIn](https://www.linkedin.com/in/pavanchow/), [GitHub](https://github.com/pavanchow)).

Veilproof is a small, from-scratch toolkit for proving you know a secret, or that a hidden number satisfies a property, without ever revealing the secret itself. Every piece of cryptography in it, the modular arithmetic, the hash function, the challenge derivation, the proof composition, is written out in the open so a reader can follow exactly why a verifier is convinced, and exactly why a liar gets caught.

## A Rust Schnorr proof from scratch

All arithmetic happens in the RFC 5114 "2048-bit MODP Group with 256-bit Prime Order Subgroup" (group id 24), a classic Schnorr group with a published, well-known generator. There are no elliptic curves anywhere in this codebase. SHA-256, the seeded deterministic RNG, and every Sigma protocol are hand-written, the only third-party crates are `num-bigint` and `num-integer` for the bignum backend and `clap` for the command line.

## Proofs supported

- **Schnorr proof of knowledge of a discrete log**: prove you know `x` such that `y = g^x mod p`, without revealing `x`.
- **Pedersen commitment opening proof**: prove you know `(m, r)` behind a public commitment `C = g^m * h^r mod p`, without revealing either.
- **Bit OR-proof**: prove a Pedersen-committed value is exactly 0 or 1, without saying which, using the standard simulated-branch OR composition.
- **Range proof**: prove a committed value lies in `[0, 2^n)` for a modest `n` (up to 32), by composing `n` bit proofs and tying them back to the value commitment through the Pedersen homomorphism.
- **Chaum-Pedersen equality proof**: prove one secret `x` satisfies both `y1 = g^x mod p` and `y2 = h^x mod p`, so two public values share the same exponent, without revealing `x`.
- **1-of-n ring proof**: given a public list of keys, prove you know the secret behind one of them without revealing which, the anonymity primitive behind ring signatures, built as an n-way OR.

Every Sigma protocol above is made non-interactive with the Fiat-Shamir transform: the verifier's random challenge is replaced with a SHA-256 hash of the full transcript and statement, reduced modulo the group order.

## Sigma protocol tutorial

Every proof here is a three-move Sigma protocol: the prover sends a commitment, a challenge is derived, and the prover sends a response the verifier can check. `DESIGN.md` walks through each one with its exact verification equation. To see the machinery with your own eyes, run any proof with `--trace` and the tool prints the exact length-prefixed byte array fed into SHA-256 at the Fiat-Shamir step, before reduction, which is the clearest way to understand transcript canonicalization.

```
veilproof prove-dlog --secret 42 --trace
```

## Pedersen commitment implementation

A Pedersen commitment is `C = g^m * h^r mod p`: hiding, because the random blinding `r` masks `m`, and additively homomorphic, so `C(m1, r1) * C(m2, r2) = C(m1 + m2, r1 + r2)`. The whole implementation is in `src/pedersen.rs`, and `DESIGN.md` explains the "nothing up my sleeve" derivation of the second generator `h`. The bit, range, and equality proofs are all built on top of it.

## Zero knowledge range proof without dependencies

The range proof shows a committed value lies in `[0, 2^n)` without revealing it, and it needs no elliptic curve library, no trusted setup, and no proving toolchain. It decomposes the value into bits, proves each bit is honestly 0 or 1 with an OR-proof, and ties the bits back to the value commitment through the Pedersen homomorphism. The full construction is in `src/range_proof.rs`.

## Veilproof vs Arkworks vs Circom

Veilproof solves a deliberately smaller problem than a general proving framework, and that is the point. Arkworks and Circom build succinct proofs over arbitrary circuits on elliptic curves, which is powerful and necessarily large. Veilproof covers a fixed menu of Sigma protocols in a Schnorr group, so it can stay small enough to read in a sitting. The comparison below is about comprehensibility and footprint, not capability.

| | Veilproof | Arkworks | Circom + snarkjs |
|---|---|---|---|
| Lines of code | about 2,800 (with tests) | very large, many crates | large, compiler plus JS toolchain |
| Cryptographic setting | Schnorr group over a finite field, no curves | elliptic curves and pairings | elliptic curves and pairings |
| Dependencies | 3 (`num-bigint`, `num-integer`, `clap`) | many | a compiler toolchain plus `snarkjs` |
| Trusted setup | none | depends on the scheme | usually required |
| Binary size | about 1.2 MB | large | large |
| Learning curve | readable end to end | steep | steep |
| Best for | learning how ZK proofs actually work | production succinct proofs over general circuits | production circuits and dapps |

Numbers for Arkworks and Circom are left qualitative on purpose, they span whole ecosystems and vary by feature set. The honest claim is narrow: for understanding the mechanics of a zero-knowledge proof, Veilproof is smaller, dependency-light, and readable in one sitting.

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

Prove and verify a range claim, with the value withheld:

```
veilproof prove-range --value 2026 --bits 16
veilproof verify-range --statement <hex> --proof <hex>
```

Prove membership in a ring of keys without revealing which one is yours:

```
veilproof prove-ring --size 5 --index 2
veilproof verify-ring --statement <hex> --proof <hex>
```

There are also two self-contained demos, `veilproof demo` (a full range proof) and `veilproof ring-demo`, that build and verify a proof in one command and print the transcript.

## MCP server for agents

`mcp/` is a Model Context Protocol server that exposes the verifiers (`verify_dlog`, `verify_dleq`, `verify_range`, `verify_ring`) as tools, so an AI agent can produce a proof and then mathematically verify its own output. Each tool shells out to the `veilproof` binary, so verification stays anchored to the audited Rust code. See `mcp/README.md` for setup.

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

## License

MIT licensed. By Pavan Nallamothu (pavanchow).
