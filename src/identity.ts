import { hash } from "starknet";
import { sha256 } from "@noble/hashes/sha256";

/**
 * The address seed binds a wallet to a stable, backend-managed user identity.
 * The deterministic account address is derived from this seed + salt ONLY — never
 * from a device pubkey — so the same user resolves to the same wallet on any
 * device. The backend owns the user_id <-> address mapping off-chain.
 */
export interface IdentityInput {
  /** Stable, backend-managed user identifier (e.g. from email / magic link). */
  userId: string;
  /** Per-app salt, so the same user has distinct wallets across apps. */
  appSalt: string;
}

/** Derive the felt `address_seed` passed to the contract constructor. */
export function deriveAddressSeed({ userId, appSalt }: IdentityInput): bigint {
  // Poseidon over the identity components; stable and collision-resistant.
  const h = hash.computePoseidonHashOnElements([feltFromString(userId), feltFromString(appSalt)]);
  return BigInt(h);
}

/**
 * Solana variant: a 32-byte `address_seed` for the Cavos device-account PDA.
 * Uses the SAME identity input as Starknet (`userId + appSalt`) but hashes with
 * SHA-256 instead of Poseidon, since Solana has no native Poseidon and the PDA
 * seed is raw bytes. The same user therefore maps to a stable, app-scoped
 * address on each chain (different address spaces, one identity).
 */
export function deriveAddressSeedSolana({ userId, appSalt }: IdentityInput): Uint8Array {
  return sha256(new TextEncoder().encode(`cavos:solana:v1:${userId}:${appSalt}`));
}

/**
 * Stellar variant: a 32-byte `address_seed` used as the Soroban account's seed
 * and folded (with the initial device signer) into the factory deploy salt.
 * Same identity input as the other chains, SHA-256 hashed, with a Stellar-scoped
 * domain so the same user maps to a distinct address per chain.
 */
export function deriveAddressSeedStellar({ userId, appSalt }: IdentityInput): Uint8Array {
  return sha256(new TextEncoder().encode(`cavos:stellar:v1:${userId}:${appSalt}`));
}

/** Map an arbitrary UTF-8 string into a felt via Poseidon over its byte chunks. */
function feltFromString(s: string): bigint {
  const bytes = new TextEncoder().encode(s);
  const chunks: bigint[] = [];
  for (let i = 0; i < bytes.length; i += 31) {
    let w = 0n;
    for (const b of bytes.subarray(i, i + 31)) w = (w << 8n) | BigInt(b);
    chunks.push(w);
  }
  if (chunks.length === 0) return 0n;
  if (chunks.length === 1) return chunks[0];
  return BigInt(hash.computePoseidonHashOnElements(chunks));
}
