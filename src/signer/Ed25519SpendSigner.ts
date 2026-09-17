import { ed25519 } from "@noble/curves/ed25519";
import { PublicKey } from "@solana/web3.js";
import { parseEd25519Seed, type Ed25519Seed } from "../secret/dek";

export interface Ed25519SpendSigner {
  address(): string;
  publicKeyRaw(): Uint8Array;
  sign(message: Uint8Array): Promise<Uint8Array>;
}

export function solanaSpendFromSeed(seed: Ed25519Seed): Ed25519SpendSigner {
  const secret = parseEd25519Seed(seed);
  const publicRaw = ed25519.getPublicKey(secret);
  return {
    address: () => new PublicKey(publicRaw).toBase58(),
    publicKeyRaw: () => publicRaw,
    async sign(message) {
      return ed25519.sign(message, secret);
    },
  };
}
