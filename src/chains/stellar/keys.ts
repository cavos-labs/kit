import { Keypair } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { randomBytes } from "@noble/hashes/utils";

/**
 * Key derivation for the classic Stellar (`G…`) multisig account.
 *
 * A partner integration requires classic ed25519 `G…` addresses, which the
 * Soroban device-account (`C…`) model cannot provide. Instead of a smart
 * contract we use a classic account whose UX matches the rest of Cavos (social
 * login → one address per app, silent signing, gasless, self-custodial):
 *
 *   - The **control key** is a random ed25519 key generated on the first device.
 *     Its public key IS the account's `G…` address, and it is the account's
 *     master key (weight 1) — the address is therefore named by the first
 *     device, exactly as the Starknet constructor and the Solana PDA seeds do.
 *   - Its 32-byte seed is never stored in the clear: it lives envelope-encrypted
 *     in the account's own on-chain data entries (see `envelope.ts`), unlocked
 *     per-device by a P-256 device factor, a passkey, or recovery.
 *
 * The address is not derivable from identity. A returning device looks it up in
 * the Cavos registry and then unlocks the control key from the envelope; it
 * never mints a second `G…`.
 *
 * This module is pure `@noble/*` + stellar-sdk keypair math (no WebCrypto/DOM),
 * so the identical derivation runs in the browser and React Native.
 */

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
