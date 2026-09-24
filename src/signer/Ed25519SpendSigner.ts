import { ed25519 } from "@noble/curves/ed25519";
import { PublicKey } from "@solana/web3.js";
import { parseEd25519Seed, type Ed25519Seed } from "../secret/dek";
import { prefixedMessageBytes } from "../signing";

/**
 * Signs whole Solana messages and prefixed off-chain messages, never raw
 * bytes, so a signer behind a policy can see what it is signing.
 */
export interface Ed25519SpendSigner {
  address(): string;
  publicKeyRaw(): Uint8Array;
  signTransaction(message: Uint8Array): Promise<Uint8Array>;
  /** Signs `prefixedMessageBytes(message)`. */
  signMessage(message: Uint8Array): Promise<Uint8Array>;
}

export function spendSignerFrom(
  publicRaw: Uint8Array,
  sign: (data: Uint8Array) => Promise<Uint8Array>,
): Ed25519SpendSigner {
  return {
    address: () => new PublicKey(publicRaw).toBase58(),
    publicKeyRaw: () => publicRaw,
    signTransaction: (message) => sign(message),
    signMessage: (message) => sign(prefixedMessageBytes(message)),
  };
}

export function solanaSpendFromSeed(seed: Ed25519Seed): Ed25519SpendSigner {
  const secret = parseEd25519Seed(seed);
  return spendSignerFrom(ed25519.getPublicKey(secret), async (data) => ed25519.sign(data, secret));
}
