import { gcm } from "@noble/ciphers/aes";
import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";

/**
 * Envelope encryption for the classic-G control key.
 *
 * The control key's 32-byte seed is the one secret that authorizes the account.
 * It is never stored in the clear. Instead:
 *
 *   1. A random 256-bit **DEK** (data-encryption key) encrypts the control seed
 *      once → `ciphertext` (stored on-chain in a `cv:ct` data entry).
 *   2. The DEK itself is **wrapped** independently by each unlock factor's KEK
 *      (key-encryption key), producing one small blob per factor:
 *        - device P-256 (ECIES)  → silent daily unlock, per-device, non-syncable
 *        - passkey PRF           → recovery / new-device anchor (synced, portable)
 *        - recovery code         → offline backup (optional in v1)
 *
 * Adding a factor (e.g. approving a new device) only re-wraps the DEK for that
 * factor; the control ciphertext never changes. Losing a factor is just dropping
 * its wrap. This is the classic-multisig analogue of `add_signer`, done in the
 * account's own on-chain data entries with no backend and no registry.
 *
 * All primitives are AES-256-GCM (authenticated) + HKDF-SHA256, pure `@noble/*`.
 */

/** AES-GCM nonce length (96-bit, the standard). */
const NONCE_LEN = 12;

/** HKDF `info` strings, one per factor, so the same underlying secret can never
 *  produce the same KEK across factors. Never change (breaks existing wraps). */
const RECOVERY_INFO = "cavos-stellar-dek-recovery";
const PASSKEY_INFO = "cavos-stellar-dek-passkey";
const ECIES_INFO = "cavos-stellar-dek-ecies";

/** PBKDF2 iterations for the recovery-code KEK — matches the recovery signer's
 *  brute-force brake so a stolen envelope can't be attacked cheaply offline. */
const RECOVERY_PBKDF2_ITERATIONS = 210_000;
const RECOVERY_KDF_SALT = "cavos-stellar-recovery-v1";

/** A DEK-wrap blob: `nonce || AES-GCM(kek, dek)`. Self-contained (nonce inline). */
export type WrappedDEK = Uint8Array;

/** Fresh 256-bit data-encryption key. One per account, generated at creation. */
export function generateDEK(): Uint8Array {
  return randomBytes(32);
}

/** Encrypt the control seed under the DEK → `nonce || ct`. */
export function sealControlSeed(controlSeed: Uint8Array, dek: Uint8Array): Uint8Array {
  const nonce = randomBytes(NONCE_LEN);
  const ct = gcm(dek, nonce).encrypt(controlSeed);
  return concat(nonce, ct);
}

/** Decrypt the control seed (`nonce || ct`) under the DEK. Throws on tamper. */
export function openControlSeed(sealed: Uint8Array, dek: Uint8Array): Uint8Array {
  const { nonce, ct } = splitNonce(sealed);
  return gcm(dek, nonce).decrypt(ct);
}

/** Wrap the DEK under a raw 32-byte KEK → `nonce || AES-GCM(kek, dek)`. */
export function wrapDEK(dek: Uint8Array, kek: Uint8Array): WrappedDEK {
  const nonce = randomBytes(NONCE_LEN);
  return concat(nonce, gcm(kek, nonce).encrypt(dek));
}

/** Unwrap the DEK from a `nonce || ct` blob under a raw 32-byte KEK. */
export function unwrapDEK(wrapped: WrappedDEK, kek: Uint8Array): Uint8Array {
  const { nonce, ct } = splitNonce(wrapped);
  return gcm(kek, nonce).decrypt(ct);
}

// ---------------------------------------------------------------------------
// Factor KEK derivations
// ---------------------------------------------------------------------------

/** KEK from a human recovery code (PBKDF2-stretched, then HKDF-scoped). The same
 *  normalised code yields the same KEK on any device. */
export function deriveRecoveryKEK(code: string): Uint8Array {
  const normalised = code.trim().replace(/\s+/g, " ").toLowerCase();
  if (!normalised) throw new Error("kit/stellar: recovery code is empty");
  const stretched = pbkdf2(sha256, new TextEncoder().encode(normalised), new TextEncoder().encode(RECOVERY_KDF_SALT), {
    c: RECOVERY_PBKDF2_ITERATIONS,
    dkLen: 32,
  });
  return hkdf(sha256, stretched, undefined, RECOVERY_INFO, 32);
}

/** KEK from a WebAuthn PRF output (32 bytes the authenticator returns for our
 *  fixed PRF salt). HKDF-scoped so the raw PRF secret is never used directly. */
export function derivePasskeyKEK(prfOutput: Uint8Array): Uint8Array {
  if (prfOutput.length < 32) throw new Error("kit/stellar: passkey PRF output too short");
  return hkdf(sha256, prfOutput, undefined, PASSKEY_INFO, 32);
}

// ---------------------------------------------------------------------------
// Device factor: ECIES over P-256
// ---------------------------------------------------------------------------

/**
 * ECIES-wrap the DEK to a device's P-256 public key (SEC1 uncompressed, 65
 * bytes). Returns `ephPubCompressed(33) || nonce(12) || ct` — self-contained.
 * An ephemeral keypair makes each wrap use a fresh shared secret; the device
 * unwraps with its private scalar. The ephemeral public key is bound into the
 * KEK via the HKDF salt so it can't be swapped.
 */
export function eciesWrapDEK(dek: Uint8Array, recipientPubSec1: Uint8Array): Uint8Array {
  const ephPriv = p256.utils.randomPrivateKey();
  const ephPubCompressed = p256.getPublicKey(ephPriv, true); // 33 bytes
  const kek = eciesKEK(p256.getSharedSecret(ephPriv, recipientPubSec1, false), ephPubCompressed);
  const wrapped = wrapDEK(dek, kek);
  return concat(ephPubCompressed, wrapped);
}

/** ECIES-unwrap the DEK with the device's private scalar (32 bytes). */
export function eciesUnwrapDEK(blob: Uint8Array, recipientPrivScalar: Uint8Array): Uint8Array {
  const ephPubCompressed = blob.subarray(0, 33);
  const wrapped = blob.subarray(33);
  const kek = eciesKEK(p256.getSharedSecret(recipientPrivScalar, ephPubCompressed, false), ephPubCompressed);
  return unwrapDEK(wrapped, kek);
}

/**
 * Derive the ECIES KEK from a raw ECDH result. We hash ONLY the shared secret's
 * X coordinate (bytes 1..33 of the uncompressed `04||X||Y` point), because that
 * is exactly what WebCrypto's `deriveBits({name:"ECDH"}, …)` returns — so a
 * browser `WebCryptoDeviceUnwrapKey` and a raw-scalar `LocalDeviceUnwrapKey`
 * derive the identical KEK for the same wrap. The ephemeral public key is bound
 * in as the HKDF salt so it can't be swapped.
 */
export function eciesKEK(sharedUncompressed: Uint8Array, ephPubCompressed: Uint8Array): Uint8Array {
  return eciesKEKFromX(sharedUncompressed.subarray(1, 33), ephPubCompressed);
}

/** ECIES KEK straight from the 32-byte ECDH X coordinate — the form WebCrypto's
 *  `deriveBits` returns, so the browser unwrap path derives the identical KEK. */
export function eciesKEKFromX(sharedX: Uint8Array, ephPubCompressed: Uint8Array): Uint8Array {
  return hkdf(sha256, sharedX, ephPubCompressed, ECIES_INFO, 32);
}

// ---------------------------------------------------------------------------
// 64-byte chunking (Stellar MANAGE_DATA value limit)
// ---------------------------------------------------------------------------

/** Stellar data-entry values are capped at 64 bytes; blobs larger than that
 *  (e.g. an ECIES device wrap) are split across ordered `<key>:<i>` entries. */
export const DATA_ENTRY_MAX = 64;

/** Split a blob into ≤64-byte chunks, in order. A blob that already fits
 *  returns a single chunk. */
export function chunkTo64(blob: Uint8Array): Uint8Array[] {
  if (blob.length <= DATA_ENTRY_MAX) return [blob];
  const chunks: Uint8Array[] = [];
  for (let i = 0; i < blob.length; i += DATA_ENTRY_MAX) {
    chunks.push(blob.subarray(i, i + DATA_ENTRY_MAX));
  }
  return chunks;
}

/** Reassemble an ordered list of chunks back into the original blob. */
export function unchunk(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function splitNonce(blob: Uint8Array): { nonce: Uint8Array; ct: Uint8Array } {
  return { nonce: blob.subarray(0, NONCE_LEN), ct: blob.subarray(NONCE_LEN) };
}
