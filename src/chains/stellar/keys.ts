import { Keypair } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import { deriveAddressSeedStellar } from "../../identity";
import type { IdentityInput } from "../../identity";

/**
 * Key derivation for the classic Stellar (`G…`) multisig account.
 *
 * A partner integration requires classic ed25519 `G…` addresses, which the
 * Soroban device-account (`C…`) model cannot provide. Instead of a smart
 * contract, we use a *classic multisig* account whose UX still matches the rest
 * of Cavos (social login → deterministic address, silent signing, gasless,
 * self-custodial, NO backend, NO registry):
 *
 *   - The **master key** is derived deterministically from the user identity, so
 *     the same user always resolves to the same `G…` address on any device with
 *     nothing but their login. It is set to **weight 0** at account creation:
 *     public and address-defining, but powerless to sign anything.
 *   - The **control key** is a random ed25519 key (weight 1, threshold 1) — the
 *     real signer. Its 32-byte seed is never stored in the clear; it lives
 *     envelope-encrypted in the account's own on-chain data entries (see
 *     `envelope.ts`), unlocked per-device by a P-256 device factor.
 *
 * This module is pure `@noble/*` + stellar-sdk keypair math (no WebCrypto/DOM),
 * so the identical derivation runs in the browser and React Native.
 */

/** HKDF info that scopes the master-key derivation. Bumping it re-derives a new
 *  master-key space (and therefore new addresses) — never change per-user. */
const MASTER_HKDF_INFO = "cavos-stellar-master";

/**
 * Deterministically derive the 32-byte ed25519 seed of the account's master key
 * from the user identity. Folds the shared cross-chain address seed
 * (`userId + appSalt`) through HKDF with a Stellar-master-scoped `info`, so this
 * seed is independent of the seeds used by the Soroban path or other chains.
 */
export function deriveStellarMasterSeed(identity: IdentityInput): Uint8Array {
  const ikm = deriveAddressSeedStellar(identity);
  return hkdf(sha256, ikm, undefined, MASTER_HKDF_INFO, 32);
}

/**
 * The account's master `Keypair`. Its public key IS the classic `G…` address of
 * the account. Deterministic: same identity → same keypair on every device.
 * Set to weight 0 at creation, so this keypair can never actually authorize a
 * transaction — it only names the account.
 */
export function deriveStellarMasterKeypair(identity: IdentityInput): Keypair {
  return Keypair.fromRawEd25519Seed(Buffer.from(deriveStellarMasterSeed(identity)));
}

/**
 * The deterministic `G…` address for an identity, derivable offline from login
 * alone — no chain read, no registry. This is what makes the account
 * self-custodial and backend-free: the address is a pure function of identity.
 */
export function deriveStellarAddress(identity: IdentityInput): string {
  return deriveStellarMasterKeypair(identity).publicKey();
}

/** A freshly generated control key: the real (weight-1) signer of the account.
 *  Returns both the `Keypair` and its raw 32-byte seed (the secret that the
 *  envelope encrypts). Generated once at account creation, then only ever
 *  recovered by decrypting the on-chain envelope. */
export function generateControlKey(): { keypair: Keypair; seed: Uint8Array } {
  const seed = randomBytes(32);
  return { keypair: Keypair.fromRawEd25519Seed(Buffer.from(seed)), seed };
}

/** Rebuild the control `Keypair` from a decrypted 32-byte seed. */
export function controlKeypairFromSeed(seed: Uint8Array): Keypair {
  if (seed.length !== 32) throw new Error("kit/stellar: control seed must be 32 bytes");
  return Keypair.fromRawEd25519Seed(Buffer.from(seed));
}
