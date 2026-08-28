import { hash } from "starknet";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "./crypto/encoding";

/**
 * The account address is named by the FIRST device signer: its pubkey goes into
 * the constructor calldata (Starknet) or the PDA seeds (Solana), so nobody who
 * lacks that key can land on the address. The app namespace below is the second
 * half of the derivation — it keeps two apps from sharing an address when the
 * same device key is used in both.
 *
 * The namespace is not a secret and is NOT the user's identity. "Same user ->
 * same wallet" is a lookup in the Cavos registry (`/api/wallets`), not a
 * derivation. A device that has never seen the registry cannot find the
 * address; that is the point.
 */
export interface AppNamespaceInput {
  /** Cavos App ID (public). */
  appId: string;
  /** Console environment id, or the kind ("production" / "development"). */
  environmentId?: string;
}

/** 32-byte app namespace, shared by every chain. */
export function appNamespace({ appId, environmentId }: AppNamespaceInput): Uint8Array {
  return sha256(utf8ToBytes(`cavos:app:v2:${appId}:${environmentId ?? "production"}`));
}

/**
 * A 32-byte namespace as a felt, for Starknet constructor calldata. Every
 * 251-bit value is below the Starknet prime, so truncating to 251 bits is exact
 * and needs no modular reduction.
 */
export function namespaceToFelt(namespace: Uint8Array): bigint {
  let v = 0n;
  for (const b of namespace) v = (v << 8n) | BigInt(b);
  return v >> 5n;
}

/** The app namespace as a felt. */
export function appNamespaceFelt(input: AppNamespaceInput): bigint {
  return namespaceToFelt(appNamespace(input));
}

/** Convert a bigint to a fixed-width big-endian byte array. */
export function toBytesBE(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  let v = value;
  for (let i = length - 1; i >= 0; i--) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

/** Poseidon hash of felts, as a bigint. Used for the Starknet deploy salt. */
export function poseidon(felts: bigint[]): bigint {
  return BigInt(hash.computePoseidonHashOnElements(felts.map((f) => "0x" + f.toString(16))));
}
