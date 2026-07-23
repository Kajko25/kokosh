#!/usr/bin/env node
// Converts a base58 Solana secret key (env var only, never a CLI arg or stdout echo) into
// the standard solana-keygen JSON-array keyfile format. Prints only the public key.
//
// Run this yourself, in your own terminal — not through the chat — so the secret never
// appears in any conversation transcript:
//   SOLANA_SECRET_B58='...' node scripts/convert-solana-key.mjs ~/.config/solana/kokosh-id.json

import { writeFileSync } from "node:fs";
import { createKeyPairSignerFromBytes } from "@solana/kit";

const b58 = process.env.SOLANA_SECRET_B58;
if (!b58) {
  console.error("set SOLANA_SECRET_B58 in your own shell first, don't pass it as an argument");
  process.exit(1);
}

const outPath = process.argv[2];
if (!outPath) {
  console.error("usage: SOLANA_SECRET_B58='...' node convert-solana-key.mjs <output-path>");
  process.exit(1);
}

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Decode(str) {
  let bytes = [0];
  for (const char of str) {
    const value = ALPHABET.indexOf(char);
    if (value === -1) throw new Error(`invalid base58 character: ${char}`);
    let carry = value;
    for (let i = 0; i < bytes.length; i++) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const char of str) {
    if (char !== "1") break;
    bytes.push(0);
  }
  return new Uint8Array(bytes.reverse());
}

const secretBytes = base58Decode(b58.trim());
if (secretBytes.length !== 64) {
  console.error(`decoded ${secretBytes.length} bytes, expected 64 (32-byte seed + 32-byte public key) — wrong key format`);
  process.exit(1);
}

const signer = await createKeyPairSignerFromBytes(secretBytes);
writeFileSync(outPath, JSON.stringify(Array.from(secretBytes)));
console.log("wrote keyfile:", outPath);
console.log("public key:", signer.address);
