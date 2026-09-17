import { ed25519 } from "@noble/curves/ed25519";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";
import { PublicKey } from "@solana/web3.js";
import { StrKey } from "@stellar/stellar-sdk";
import { utf8ToBytes } from "../crypto/encoding";
import { parseMasterDEK, parseEd25519Seed, type MasterDEK, type Ed25519Seed } from "./dek";

export type Ed25519Chain = "solana" | "stellar";

declare const appSaltBrand: unique symbol;
export type AppSalt = Uint8Array & { readonly [appSaltBrand]: "AppSalt" };

export const HKDF_SOLANA = "cavos-ed25519-solana-v1";
export const HKDF_STELLAR = "cavos-ed25519-stellar-v1";

export function parseAppSalt(salt: string | Uint8Array): AppSalt {
  if (typeof salt === "string") {
    if (!salt) throw new Error("kit/secret: appSalt is empty");
    return sha256(utf8ToBytes(salt)) as AppSalt;
  }
  if (salt.length !== 32) throw new Error("kit/secret: appSalt must be 32 bytes");
  return salt.slice() as AppSalt;
}

function infoFor(chain: Ed25519Chain): string {
  return chain === "solana" ? HKDF_SOLANA : HKDF_STELLAR;
}

export function deriveSeed(dek: MasterDEK, chain: Ed25519Chain, appSalt: AppSalt): Ed25519Seed {
  return parseEd25519Seed(hkdf(sha256, dek, appSalt, infoFor(chain), 32));
}

/** MasterDEK from a synced passkey PRF. Same credential + app → same DEK, no server wrap. */
export const HKDF_PASSKEY_DEK = "cavos-master-dek-passkey-v1";

export function masterDekFromPasskey(prf: Uint8Array, appSalt: AppSalt): MasterDEK {
  if (prf.length < 32) throw new Error("kit/secret: passkey PRF output too short");
  return parseMasterDEK(hkdf(sha256, prf, appSalt, HKDF_PASSKEY_DEK, 32));
}

export function solanaAddressFromSeed(seed: Ed25519Seed): string {
  return new PublicKey(ed25519.getPublicKey(seed)).toBase58();
}

export function stellarAddressFromSeed(seed: Ed25519Seed): string {
  return StrKey.encodeEd25519PublicKey(Buffer.from(ed25519.getPublicKey(seed)));
}

export function nativeAddress(dek: MasterDEK, chain: Ed25519Chain, appSalt: AppSalt): string {
  const seed = deriveSeed(dek, chain, appSalt);
  try {
    return chain === "solana" ? solanaAddressFromSeed(seed) : stellarAddressFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}
