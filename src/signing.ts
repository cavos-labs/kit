/**
 * Off-chain message signing + sign-without-submit types, shared across chains.
 *
 * `signMessage` signs an arbitrary message off-chain (no transaction, no gas,
 * no state change) so a third party can verify the wallet owner endorsed it —
 * the canonical primitive for Sign-In-with-X, off-chain auth, and attestations.
 *
 * `signTransaction` signs a chain-native transaction WITHOUT submitting it,
 * returning the signed artifact a relayer/backend can broadcast later.
 */

import { utf8ToBytes } from "./crypto/encoding";

/** Curve a signature was produced with. Determines how a verifier checks it. */
export type SignatureCurve = "secp256r1" | "ed25519";

/**
 * Result of `wallet.signMessage(message)`. The signature is over
 * `sha256(prefixedMessage)` for secp256r1 chains (Starknet, Solana) and over
 * the raw message bytes for the ed25519 control key (Stellar). `publicKey` is
 * the string a verifier needs to confirm ownership:
 *  - Starknet: uncompressed hex `04‖x‖y` of the device P-256 key.
 *  - Solana: compressed hex (33 bytes) of the device P-256 key.
 *  - Stellar: the `G…` control address (ed25519).
 *
 * Check `curve` to know which verification path to use.
 */
export interface MessageSignature {
  /** Chain-native signature bytes (64 bytes for both secp256r1 r‖s and ed25519). */
  signature: Uint8Array;
  /** Verifier input: the key/address that owns this wallet's signing authority. */
  publicKey: string;
  /** Curve used to produce the signature. */
  curve: SignatureCurve;
}

/**
 * A transaction signed but NOT submitted. The concrete shape is chain-specific
 * — narrow on `chain` to read the fields.
 *
 * <Callout-minded note>: every variant is **single-use and binds to on-chain
 * state** (Starknet nonce + resourceBounds, Stellar sequence number, Solana
 * on-chain nonce). If any other transaction from the same account is submitted
 * first, this signature becomes invalid. Broadcast promptly.
 */
export type SignedTransaction =
  | StarknetSignedTransaction
  | StellarSignedTransaction
  | SolanaSignedTransaction;

/** Starknet invoke, signed by the device key (5-felt signature), not broadcast. */
export interface StarknetSignedTransaction {
  chain: "starknet";
  /** Hex-encoded calldata felts of the built invoke. */
  calldata: string[];
  /** The 5-felt device signature as hex strings: `[r_low, r_high, s_low, s_high, y_parity]`. */
  signature: string[];
  /** Account nonce the signature binds to. */
  nonce: string;
  /** Resource bounds the signature binds to (L1/L2 gas). */
  resourceBounds: {
    l1Gas: { maxAmount: string; maxPricePerUnit: string };
    l2Gas: { maxAmount: string; maxPricePerUnit: string };
  };
  /** Transaction version (hex). */
  version: string;
}

/** Stellar classic transaction, signed by the ed25519 control key, as base64 XDR. */
export interface StellarSignedTransaction {
  chain: "stellar";
  /** Base64-encoded signed inner Transaction envelope (fee-bumpable by a relayer). */
  xdr: string;
}

/**
 * Solana device signature over the secp256r1-precompile message. **This is NOT
 * a signed Solana transaction** — the device P-256 key never signs the Solana
 * transaction itself (it signs a domain-tagged message verified on-chain by the
 * native secp256r1 precompile). A relayer/feePayer must assemble the full
 * transaction (adding the feePayer signature + a recent blockhash) and submit
 * it; this triple is what the device contributes.
 */
export interface SolanaSignedTransaction {
  chain: "solana";
  /** The domain-tagged message bytes the device signed. */
  message: Uint8Array;
  /** 64-byte low-S `r‖s` P-256 signature over `sha256(message)`. */
  signature: Uint8Array;
  /** 33-byte compressed P-256 public key of the device signer. */
  publicKey: Uint8Array;
}

/** Prefix scheme for off-chain messages, mirroring EIP-191 / Solana's convention. */
export const CAVOS_MESSAGE_PREFIX = "Cavos Signed Message:\n";

/** Build the prefixed message bytes a secp256r1 chain signs for `signMessage`.
 *  Format: `CAVOS_MESSAGE_PREFIX` + ASCII decimal length + `\n` + message. */
export function prefixedMessageBytes(message: Uint8Array): Uint8Array {
  const len = String(message.length);
  const parts = [
    utf8ToBytes(CAVOS_MESSAGE_PREFIX),
    utf8ToBytes(len),
    utf8ToBytes("\n"),
    message,
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}
