use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use veilproof::rng::{DeterministicRng, RngCore};
use veilproof::serialize::ProofBytes;
use veilproof::{bit_proof, chaum_pedersen, group, hexutil, range_proof, ring, schnorr};

#[derive(Parser)]
#[command(name = "veilproof", about = "A teaching-grade zero-knowledge proof toolkit")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Prove knowledge of a secret discrete log x, without revealing it.
    ProveDlog {
        #[arg(long)]
        secret: String,
        /// Print the exact byte array fed to SHA-256 at the Fiat-Shamir step,
        /// before reduction, so the canonicalization is fully visible.
        #[arg(long)]
        trace: bool,
    },
    /// Verify a Schnorr discrete-log proof.
    VerifyDlog {
        #[arg(long)]
        statement: String,
        #[arg(long)]
        proof: String,
    },
    /// Prove a committed value lies in [0, 2^bits). Prints the statement and
    /// proof as hex, with the value and blinding withheld.
    ProveRange {
        #[arg(long)]
        value: String,
        #[arg(long, default_value_t = 16)]
        bits: u32,
    },
    /// Verify a range proof.
    VerifyRange {
        #[arg(long)]
        statement: String,
        #[arg(long)]
        proof: String,
    },
    /// Build a ring of `size` keys, prove membership at `index`, and print the
    /// ring statement and proof as hex. The proof does not reveal the index.
    ProveRing {
        #[arg(long, default_value_t = 5)]
        size: usize,
        #[arg(long, default_value_t = 2)]
        index: usize,
    },
    /// Verify a ring membership proof.
    VerifyRing {
        #[arg(long)]
        statement: String,
        #[arg(long)]
        proof: String,
    },
    /// Prove one secret x satisfies y1 = g^x and y2 = h^x (equal discrete logs).
    ProveDleq {
        #[arg(long)]
        secret: String,
    },
    /// Verify a Chaum-Pedersen equality-of-discrete-logs proof.
    VerifyDleq {
        #[arg(long)]
        statement: String,
        #[arg(long)]
        proof: String,
    },
    /// Build a ring of `size` public keys, prove membership at `index`
    /// without revealing which, and verify it.
    RingDemo {
        #[arg(long, default_value_t = 5)]
        size: usize,
        #[arg(long, default_value_t = 2)]
        index: usize,
    },
    /// Run a full range-proof prove/verify cycle and print the transcript.
    Demo,
}

fn main() {
    if let Err(e) = group::self_check() {
        eprintln!("veilproof: group self-check failed: {e}");
        std::process::exit(1);
    }

    let cli = Cli::parse();
    match cli.command {
        Command::ProveDlog { secret, trace } => cmd_prove_dlog(&secret, trace),
        Command::VerifyDlog { statement, proof } => cmd_verify_dlog(&statement, &proof),
        Command::ProveRange { value, bits } => cmd_prove_range(&value, bits),
        Command::VerifyRange { statement, proof } => cmd_verify_range(&statement, &proof),
        Command::ProveRing { size, index } => cmd_prove_ring(size, index),
        Command::VerifyRing { statement, proof } => cmd_verify_ring(&statement, &proof),
        Command::ProveDleq { secret } => cmd_prove_dleq(&secret),
        Command::VerifyDleq { statement, proof } => cmd_verify_dleq(&statement, &proof),
        Command::RingDemo { size, index } => cmd_ring_demo(size, index),
        Command::Demo => cmd_demo(),
    }
}

fn cmd_prove_dleq(secret: &str) {
    let x = parse_biguint_decimal(secret);
    let mut rng = os_rng_or_exit();
    let (stmt, proof) = chaum_pedersen::prove(&x, &mut rng);
    println!("statement (y1 = g^x mod p, y2 = h^x mod p):");
    println!("  {}", stmt.to_hex());
    println!("proof (t1, t2, z):");
    println!("  {}", proof.to_hex());
    println!();
    println!("this convinces a verifier both public values share one secret x, without revealing x.");
}

fn cmd_verify_dleq(statement_hex: &str, proof_hex: &str) {
    let stmt = match chaum_pedersen::DleqStatement::from_hex(statement_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("reject: could not decode statement: {e}");
            std::process::exit(1);
        }
    };
    let proof = match chaum_pedersen::DleqProof::from_hex(proof_hex) {
        Ok(p) => p,
        Err(e) => {
            println!("reject: could not decode proof: {e}");
            std::process::exit(1);
        }
    };
    match chaum_pedersen::verify(&stmt, &proof) {
        Ok(true) => println!("accept"),
        Ok(false) => {
            println!("reject");
            std::process::exit(1);
        }
        Err(e) => {
            println!("reject: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_ring_demo(size: usize, index: usize) {
    let mut rng = os_rng_or_exit();
    let p = group::p();
    let g = group::g();

    if size == 0 || index >= size {
        eprintln!("veilproof: need size >= 1 and 0 <= index < size");
        std::process::exit(2);
    }

    println!("ring demo: proving membership in a set of {size} public keys without revealing which one");
    println!();

    let mut secret = BigUint::from(0u32);
    let mut ys = Vec::with_capacity(size);
    for i in 0..size {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let xi = BigUint::from_bytes_be(&buf) % group::q();
        if i == index {
            secret = xi.clone();
        }
        ys.push(g.modpow(&xi, &p));
    }

    for (i, y) in ys.iter().enumerate() {
        let tag = if i == index { " (secret held here, but the proof never says so)" } else { "" };
        println!("  key {i}: {}...{tag}", &hexutil::encode(&y.to_bytes_be())[..16]);
    }
    println!();

    let (stmt, proof) = match ring::prove(&secret, index, &ys, &mut rng) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("veilproof: {e}");
            std::process::exit(1);
        }
    };

    let ok = ring::verify(&stmt, &proof).expect("well-formed ring proof");
    println!("verifier checks every branch equation and that the challenge shares sum correctly: {}",
        if ok { "ACCEPT" } else { "REJECT" });
    println!("the proof reveals membership, not the index. it is the same shape for any position.");
}

fn os_rng_or_exit() -> DeterministicRng {
    match DeterministicRng::from_os() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("veilproof: {e}");
            std::process::exit(1);
        }
    }
}

fn parse_biguint_decimal(s: &str) -> BigUint {
    match BigUint::parse_bytes(s.as_bytes(), 10) {
        Some(v) => v,
        None => {
            eprintln!("veilproof: could not parse \"{s}\" as a non-negative decimal integer");
            std::process::exit(2);
        }
    }
}

fn cmd_prove_dlog(secret: &str, trace: bool) {
    let x = parse_biguint_decimal(secret);
    let mut rng = os_rng_or_exit();
    let (stmt, proof, tr) = schnorr::prove_traced(&x, &mut rng);

    println!("statement (y = g^x mod p):");
    println!("  {}", stmt.to_hex());
    println!("proof (t, z):");
    println!("  {}", proof.to_hex());

    if trace {
        let buf = tr.transcript_bytes;
        println!();
        println!("--- Fiat-Shamir trace (schnorr-dlog-v1) ---");
        println!(
            "the {} bytes below are hashed to derive the challenge. every field is",
            buf.len()
        );
        println!("length-prefixed, so the boundaries between g, y, and t cannot slide.");
        println!("transcript input bytes (hex):");
        println!("  {}", hexutil::encode(&buf));
        let mut b0 = buf.clone();
        b0.push(0u8);
        let mut b1 = buf.clone();
        b1.push(1u8);
        println!("block 0 = SHA256(transcript || 0x00): {}", hexutil::encode(&veilproof::sha256::sha256(&b0)));
        println!("block 1 = SHA256(transcript || 0x01): {}", hexutil::encode(&veilproof::sha256::sha256(&b1)));
        println!("challenge c = (block0 || block1) mod q, then z = k + c*x mod q.");
    }
    println!();
    println!("share the statement and proof, never the secret.");
}

fn cmd_prove_range(value: &str, bits: u32) {
    let m = parse_biguint_decimal(value);
    let mut rng = os_rng_or_exit();
    match range_proof::prove(&m, bits, &mut rng) {
        Ok((stmt, proof, _blinding)) => {
            println!("statement (commitment C and bit width n):");
            println!("  {}", stmt.to_hex());
            println!("proof (bit commitments and OR-proofs):");
            println!("  {}", proof.to_hex());
            println!();
            println!("the value and its blinding are withheld. the proof shows only that C opens to a value in [0, 2^{bits}).");
        }
        Err(e) => {
            eprintln!("veilproof: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_verify_range(statement_hex: &str, proof_hex: &str) {
    let stmt = match range_proof::RangeStatement::from_hex(statement_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("reject: could not decode statement: {e}");
            std::process::exit(1);
        }
    };
    let proof = match range_proof::RangeProof::from_hex(proof_hex) {
        Ok(p) => p,
        Err(e) => {
            println!("reject: could not decode proof: {e}");
            std::process::exit(1);
        }
    };
    match range_proof::verify(&stmt, &proof) {
        Ok(true) => println!("accept"),
        Ok(false) => {
            println!("reject");
            std::process::exit(1);
        }
        Err(e) => {
            println!("reject: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_prove_ring(size: usize, index: usize) {
    if size == 0 || index >= size {
        eprintln!("veilproof: need size >= 1 and 0 <= index < size");
        std::process::exit(2);
    }
    let mut rng = os_rng_or_exit();
    let p = group::p();
    let g = group::g();

    let mut secret = BigUint::from(0u32);
    let mut ys = Vec::with_capacity(size);
    for i in 0..size {
        let mut buf = [0u8; 32];
        rng.fill_bytes(&mut buf);
        let xi = BigUint::from_bytes_be(&buf) % group::q();
        if i == index {
            secret = xi.clone();
        }
        ys.push(g.modpow(&xi, &p));
    }

    match ring::prove(&secret, index, &ys, &mut rng) {
        Ok((stmt, proof)) => {
            println!("statement (the public ring of {size} keys):");
            println!("  {}", stmt.to_hex());
            println!("proof (per-branch commitments, challenge shares, responses):");
            println!("  {}", proof.to_hex());
            println!();
            println!("the proof shows membership in the ring. it does not reveal which key was yours.");
        }
        Err(e) => {
            eprintln!("veilproof: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_verify_ring(statement_hex: &str, proof_hex: &str) {
    let stmt = match ring::RingStatement::from_hex(statement_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("reject: could not decode statement: {e}");
            std::process::exit(1);
        }
    };
    let proof = match ring::RingProof::from_hex(proof_hex) {
        Ok(p) => p,
        Err(e) => {
            println!("reject: could not decode proof: {e}");
            std::process::exit(1);
        }
    };
    match ring::verify(&stmt, &proof) {
        Ok(true) => println!("accept"),
        Ok(false) => {
            println!("reject");
            std::process::exit(1);
        }
        Err(e) => {
            println!("reject: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_verify_dlog(statement_hex: &str, proof_hex: &str) {
    let stmt = match schnorr::DlogStatement::from_hex(statement_hex) {
        Ok(s) => s,
        Err(e) => {
            println!("reject: could not decode statement: {e}");
            std::process::exit(1);
        }
    };
    let proof = match schnorr::DlogProof::from_hex(proof_hex) {
        Ok(p) => p,
        Err(e) => {
            println!("reject: could not decode proof: {e}");
            std::process::exit(1);
        }
    };

    match schnorr::verify(&stmt, &proof) {
        Ok(true) => println!("accept"),
        Ok(false) => {
            println!("reject");
            std::process::exit(1);
        }
        Err(e) => {
            println!("reject: {e}");
            std::process::exit(1);
        }
    }
}

fn cmd_demo() {
    println!("veilproof demo: proving a committed value lies in a range, without revealing it");
    println!();

    let mut rng = os_rng_or_exit();
    let secret_value = BigUint::from(2026u32);
    let n_bits = 16u32;

    println!("secret value: withheld (that is the point)");
    println!("public claim: the committed value fits in {n_bits} bits, i.e. [0, 2^{n_bits})");
    println!();

    let (range_stmt, range_proof_val, blinding) =
        range_proof::prove(&secret_value, n_bits, &mut rng)
            .expect("demo value is within range by construction");

    println!("commitment C = g^m * h^r mod p:");
    println!("  {}", hexutil::encode(&range_stmt.c.to_bytes_be()));
    println!("blinding factor r: withheld (not printed, this is what makes C hiding)");
    let _ = &blinding; // proves we hold it without printing it
    println!();

    println!("range proof: {} bit commitments, each with an OR-proof of being 0 or 1", n_bits);
    for (i, c) in range_proof_val.bit_commitments.iter().enumerate() {
        println!("  bit {i:>2} commitment: {}", hexutil::encode(&c.to_bytes_be())[..16].to_string() + "...");
    }
    println!();

    let ok = range_proof::verify(&range_stmt, &range_proof_val).expect("well-formed proof");
    println!("verifier recomputes the weighted product of bit commitments,");
    println!("checks it equals C, and checks every bit OR-proof: {}", if ok { "ACCEPT" } else { "REJECT" });
    println!();

    println!("for comparison, an OR-proof that a single bit is honest:");
    let bit_r = BigUint::from(11u32);
    let (bit_stmt, bit_proof_val) = bit_proof::prove(true, &bit_r, &mut rng);
    let bit_ok = bit_proof::verify(&bit_stmt, &bit_proof_val).expect("well-formed proof");
    println!("  bit commitment: {}", hexutil::encode(&bit_stmt.c.to_bytes_be()));
    println!("  verifies as a valid 0-or-1 commitment: {}", if bit_ok { "ACCEPT" } else { "REJECT" });
}
