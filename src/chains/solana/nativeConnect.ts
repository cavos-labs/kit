import { PublicKey } from "@solana/web3.js";
import { WebCryptoControlKey } from "../stellar/WebCryptoControlKey";
import {
  resolveNativeEd25519,
  type ResolveNativeEd25519Input,
} from "../../secret/nativeAccount";
import { solanaSpendFromSeed, type Ed25519SpendSigner } from "../../signer/Ed25519SpendSigner";
import type { Ed25519Seed } from "../../secret/dek";

export type ResolveNativeSolanaInput = Omit<ResolveNativeEd25519Input, "chain">;

export async function resolveNativeSolana(
  input: ResolveNativeSolanaInput,
): Promise<{ address: string; spend: Ed25519SpendSigner | null; isNewAccount: boolean }> {
  return resolveNativeEd25519({
    ...input,
    chain: "solana",
    loadPersisted: input.loadPersisted ?? loadPersistedSolana,
    importSpend: input.importSpend ?? importSolanaSpend,
  });
}

async function loadPersistedSolana(keyId: string): Promise<Ed25519SpendSigner | null> {
  const key = await WebCryptoControlKey.load({ keyId });
  if (!key) return null;
  return spendFromControl(key);
}

async function importSolanaSpend(seed: Ed25519Seed, keyId: string): Promise<Ed25519SpendSigner> {
  try {
    return spendFromControl(await WebCryptoControlKey.importFromSeed(seed, { keyId }));
  } catch {
    return solanaSpendFromSeed(seed);
  }
}

function spendFromControl(key: WebCryptoControlKey): Ed25519SpendSigner {
  return {
    address: () => new PublicKey(key.publicKeyRaw()).toBase58(),
    publicKeyRaw: () => key.publicKeyRaw(),
    sign: (message) => key.sign(message),
  };
}
