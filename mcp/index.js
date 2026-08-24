#!/usr/bin/env node
// Veilproof MCP server. Exposes the library's proof verifiers as tools so an
// agent can check a zero-knowledge proof it (or someone else) produced. Every
// tool shells out to the real `veilproof` binary, so verification has exactly
// one source of truth: the audited Rust code, not a reimplementation here.

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { execFile } from "node:child_process";

const BIN = process.env.VEILPROOF_BIN || "veilproof";

// A statement and a proof are always lowercase or uppercase hex. Reject
// anything else before it reaches the binary, so a tool call cannot smuggle
// flags or shell metacharacters into the argument list.
function assertHex(name, value) {
  if (typeof value !== "string" || value.length === 0 || !/^[0-9a-fA-F]+$/.test(value)) {
    throw new Error(`${name} must be a non-empty hex string`);
  }
}

function runVerify(subcommand, statement, proof) {
  return new Promise((resolve) => {
    execFile(
      BIN,
      [subcommand, "--statement", statement, "--proof", proof],
      { timeout: 20000 },
      (err, stdout) => {
        const out = (stdout || "").trim();
        if (out.startsWith("accept")) {
          resolve({ verified: true, detail: out });
        } else {
          // A non-zero exit is how the CLI signals a rejected proof, so an
          // error here is a normal reject, not a server fault.
          resolve({ verified: false, detail: out || (err ? String(err.message) : "reject") });
        }
      }
    );
  });
}

const TOOLS = [
  {
    name: "verify_dlog",
    description:
      "Verify a Veilproof Schnorr discrete-log proof (knowledge of x with y = g^x). Inputs are the hex-encoded statement and proof from `veilproof prove-dlog`.",
    subcommand: "verify-dlog",
  },
  {
    name: "verify_dleq",
    description:
      "Verify a Veilproof Chaum-Pedersen equality proof (one secret x with y1 = g^x and y2 = h^x). Inputs are the hex statement and proof from `veilproof prove-dleq`.",
    subcommand: "verify-dleq",
  },
  {
    name: "verify_range",
    description:
      "Verify a Veilproof range proof that a committed value lies in [0, 2^n). Inputs are the hex statement and proof from `veilproof prove-range`.",
    subcommand: "verify-range",
  },
  {
    name: "verify_ring",
    description:
      "Verify a Veilproof 1-of-n ring membership proof. Inputs are the hex statement and proof from `veilproof prove-ring`.",
    subcommand: "verify-ring",
  },
];

const inputSchema = {
  type: "object",
  properties: {
    statement: { type: "string", description: "hex-encoded statement" },
    proof: { type: "string", description: "hex-encoded proof" },
  },
  required: ["statement", "proof"],
};

const server = new Server(
  { name: "veilproof", version: "0.1.0" },
  { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools: TOOLS.map((t) => ({
    name: t.name,
    description: t.description,
    inputSchema,
  })),
}));

server.setRequestHandler(CallToolRequestSchema, async (req) => {
  const tool = TOOLS.find((t) => t.name === req.params.name);
  if (!tool) {
    return { isError: true, content: [{ type: "text", text: `unknown tool: ${req.params.name}` }] };
  }
  const { statement, proof } = req.params.arguments || {};
  try {
    assertHex("statement", statement);
    assertHex("proof", proof);
  } catch (e) {
    return { isError: true, content: [{ type: "text", text: e.message }] };
  }
  const result = await runVerify(tool.subcommand, statement, proof);
  return {
    content: [{ type: "text", text: JSON.stringify(result) }],
  };
});

const transport = new StdioServerTransport();
await server.connect(transport);
