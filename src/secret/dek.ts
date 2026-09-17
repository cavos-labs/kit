import { randomBytes } from "@noble/hashes/utils";

declare const masterDekBrand: unique symbol;
declare const ed25519SeedBrand: unique symbol;

/** 32-byte account secret. Lives in the sealed record. Never a spend key by itself. */
export type MasterDEK = Uint8Array & { readonly [masterDekBrand]: "MasterDEK" };

/** 32-byte Ed25519 seed for one chain. HKDF of a MasterDEK. Import then zeroize. */
export type Ed25519Seed = Uint8Array & { readonly [ed25519SeedBrand]: "Ed25519Seed" };

export function parseMasterDEK(bytes: Uint8Array): MasterDEK {
  if (bytes.length !== 32) {
    throw new Error("kit/secret: MasterDEK must be 32 bytes");
  }
  return bytes.slice() as MasterDEK;
}

export function parseEd25519Seed(bytes: Uint8Array): Ed25519Seed {
  if (bytes.length !== 32) {
    throw new Error("kit/secret: Ed25519Seed must be 32 bytes");
  }
  return bytes.slice() as Ed25519Seed;
}

export function generateMasterDEK(): MasterDEK {
  return parseMasterDEK(randomBytes(32));
}

export function zeroize(secret: Uint8Array): void {
  secret.fill(0);
}
