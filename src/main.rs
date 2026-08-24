use clap::{Parser, Subcommand};
use num_bigint::BigUint;
use veilproof::rng::OsRng;
use veilproof::serialize::ProofBytes;
use veilproof::rng::RngCore;
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
    },
    /// Verify a Schnorr discrete-log proof.
    VerifyDlog {
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
        Command::ProveDlog { secret } => cmd_prove_dlog(&secret),
        Command::VerifyDlog { statement, proof } => cmd_verify_dlog(&statement, &proof),
        Command::ProveDleq { secret } => cmd_prove_dleq(&secret),
        Command::VerifyDleq { statement, proof } => cmd_verify_dleq(&statement, &proof),
        Command::RingDemo { size, index } => cmd_ring_demo(size, index),
        Command::Demo => cmd_demo(),
    }
}

fn cmd_prove_dleq(secret: &str) {
    let x = parse_biguint_decimal(secret);
    let mut rng = OsRng;
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
    let mut rng = OsRng;
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

fn parse_biguint_decimal(s: &str) -> BigUint {
    match BigUint::parse_bytes(s.as_bytes(), 10) {
        Some(v) => v,
        None => {
            eprintln!("veilproof: could not parse \"{s}\" as a non-negative decimal integer");
            std::process::exit(2);
        }
    }
}

fn cmd_prove_dlog(secret: &str) {
    let x = parse_biguint_decimal(secret);
    let mut rng = OsRng;
    let (stmt, proof) = schnorr::prove(&x, &mut rng);

    println!("statement (y = g^x mod p):");
    println!("  {}", stmt.to_hex());
    println!("proof (t, z):");
    println!("  {}", proof.to_hex());
    println!();
    println!("share the statement and proof, never the secret.");
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

    let mut rng = OsRng;
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
