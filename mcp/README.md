# Veilproof MCP server

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent verify zero-knowledge proofs with Veilproof. An agent can produce a Schnorr, range, equality, or ring proof and then mathematically check its own output through these tools.

Every tool shells out to the real `veilproof` binary, so verification has one source of truth: the audited Rust code, never a reimplementation.

## Tools

- **verify_dlog** verify a Schnorr discrete-log proof (`knowledge of x with y = g^x`).
- **verify_dleq** verify a Chaum-Pedersen equality proof (`one x with y1 = g^x and y2 = h^x`).
- **verify_range** verify a range proof (`a committed value is in [0, 2^n)`).
- **verify_ring** verify a 1-of-n ring membership proof.

Each tool takes a hex `statement` and a hex `proof`, exactly as printed by the matching `veilproof prove-*` command, and returns `{"verified": true|false, "detail": "..."}`.

## Install

Build and install the binary so the server can call it:

```
cargo install --path ..
```

Install the server dependencies:

```
npm install
```

## Configure your client

Point your MCP client at `index.js`. For Claude Code:

```
claude mcp add veilproof -- node /absolute/path/to/veilproof/mcp/index.js
```

If the `veilproof` binary is not on `PATH`, set `VEILPROOF_BIN` to its full path in the server environment.

## Example flow for an agent

1. Produce a proof: `veilproof prove-range --value 42 --bits 8` prints a hex statement and proof.
2. Call `verify_range` with that statement and proof.
3. Read back `{"verified": true, ...}`.

By Pavan Nallamothu.
