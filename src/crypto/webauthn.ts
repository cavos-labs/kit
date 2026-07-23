import { Buffer } from "buffer";

/**
 * WebAuthn (passkey) helpers for the passkey-approval flow.
 *
 * A passkey is a synced secp256r1 credential (iCloud Keychain / Google Password
 * Manager). We use it as an on-chain "approver" that can authorize `add_signer`
 * from ANY browser — so a user never has to return to an already-authorized
 * device to onboard a new one.
 *
 * Unlike a silent device key (which signs `sha256(txHash)`), a passkey signs
 * `sha256(authenticatorData || sha256(clientDataJSON))`, with the challenge
 * embedded (base64url) in `clientDataJSON`. These helpers parse an assertion and
 * reproduce exactly what the on-chain contracts recompute.
 */
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import type { DevicePublicKey } from "../signer/DeviceSigner";
import { bytesToBigInt, bytesToUtf8 } from "./encoding";

/** A parsed passkey assertion, chain-agnostic. */
export interface PasskeyAssertion {
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  /** ECDSA signature components (raw, as returned by the authenticator). */
  r: bigint;
  s: bigint;
  /** Byte index where the base64url challenge starts inside clientDataJSON. */
  challengeOffset: number;
}

/** base64url (no padding) of a byte array. */
export function base64urlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = typeof btoa !== "undefined" ? btoa(bin) : Buffer.from(bytes).toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Parse a DER (ASN.1) ECDSA signature into its `{ r, s }` components. */
export function derToRs(der: Uint8Array): { r: bigint; s: bigint } {
  // SEQUENCE(0x30) len INTEGER(0x02) rlen r INTEGER(0x02) slen s
  let i = 0;
  if (der[i++] !== 0x30) throw new Error("kit/webauthn: bad DER (no SEQUENCE)");
  if (der[i] & 0x80) i += 1 + (der[i] & 0x7f); // skip long-form length
  else i += 1;
  if (der[i++] !== 0x02) throw new Error("kit/webauthn: bad DER (no r INTEGER)");
  const rlen = der[i++];
  const r = bytesToBigInt(der.subarray(i, i + rlen));
  i += rlen;
  if (der[i++] !== 0x02) throw new Error("kit/webauthn: bad DER (no s INTEGER)");
  const slen = der[i++];
  const s = bytesToBigInt(der.subarray(i, i + slen));
  return { r, s };
}

/** Extract the P-256 public key `{ x, y }` from a DER SPKI blob (as returned by
 * `AuthenticatorAttestationResponse.getPublicKey()`). The uncompressed EC point
 * is the trailing 65 bytes (`0x04 || X || Y`). */
export function spkiToPublicKey(spki: Uint8Array): DevicePublicKey {
  const idx = spki.lastIndexOf(0x04, spki.length - 65);
  const start = spki.length - 65;
  const prefix = spki[start];
  if (prefix !== 0x04) {
    // Fall back to scanning for the 0x04 uncompressed marker.
    if (idx < 0) throw new Error("kit/webauthn: no uncompressed EC point in SPKI");
    return { x: bytesToBigInt(spki.subarray(idx + 1, idx + 33)), y: bytesToBigInt(spki.subarray(idx + 33, idx + 65)) };
  }
  return {
    x: bytesToBigInt(spki.subarray(start + 1, start + 33)),
    y: bytesToBigInt(spki.subarray(start + 33, start + 65)),
  };
}

/**
 * Batch challenge over ordered per-chain leaves: `sha256(leaf_0 ‖ … ‖ leaf_n)`.
 * A single passkey assertion over this challenge authorizes `add_signer` on every
 * chain in the batch (each chain verifies only its own leaf sits at its index).
 * For a single chain the batch is one leaf, so the challenge is `sha256(leaf)`.
 */
export function batchChallenge(leaves: Uint8Array[]): Uint8Array {
  const total = leaves.reduce((n, l) => n + l.length, 0);
  const cat = new Uint8Array(total);
  let o = 0;
  for (const l of leaves) {
    cat.set(l, o);
    o += l.length;
  }
  return sha256(cat);
}

/** The WebAuthn signed digest: `sha256(authenticatorData || sha256(clientDataJSON))`. */
export function webauthnDigest(authenticatorData: Uint8Array, clientDataJSON: Uint8Array): Uint8Array {
  const clientHash = sha256(clientDataJSON);
  const msg = new Uint8Array(authenticatorData.length + clientHash.length);
  msg.set(authenticatorData, 0);
  msg.set(clientHash, authenticatorData.length);
  return sha256(msg);
}

/** Both candidate public keys recoverable from `(r, s)` over `digest`, tagged
 * with their y-parity. On a fresh browser the assertion does not carry the
 * pubkey, so the caller identifies the real one via the on-chain `is_approver`
 * view. */
export function recoverCandidatePublicKeys(
  r: bigint,
  s: bigint,
  digest: Uint8Array,
): { publicKey: DevicePublicKey; yParity: boolean }[] {
  const out: { publicKey: DevicePublicKey; yParity: boolean }[] = [];
  for (const bit of [0, 1] as const) {
    try {
      const point = new p256.Signature(r, s).addRecoveryBit(bit).recoverPublicKey(digest).toAffine();
      out.push({ publicKey: { x: point.x, y: point.y }, yParity: bit === 1 });
    } catch {
      // not recoverable for this bit
    }
  }
  return out;
}

/** Normalize `s` to the low half of the curve order (required by the Stellar
 * and Solana verifiers, which do not normalize on-chain). */
export function lowS(s: bigint): bigint {
  const n = p256.CURVE.n;
  return s > n / 2n ? n - s : s;
}

/** Byte offset of the base64url `challenge` string inside `clientDataJSON`. */
export function challengeOffsetOf(clientDataJSON: Uint8Array, challengeB64: string): number {
  const text = bytesToUtf8(clientDataJSON);
  const idx = text.indexOf(challengeB64);
  if (idx < 0) throw new Error("kit/webauthn: challenge not found in clientDataJSON");
  // clientDataJSON is ASCII, so the char index equals the byte index.
  return idx;
}
