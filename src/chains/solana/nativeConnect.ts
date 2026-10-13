import { WebCryptoControlKey } from "../stellar/WebCryptoControlKey";
import {
  resolveNative,
  type ResolveNativeInput,
} from "../../secret/nativeAccount";
import { solanaSpendFromSeed, spendSignerFrom, type Ed25519SpendSigner } from "../../signer/Ed25519SpendSigner";
import type { Ed25519Seed } from "../../secret/dek";

export type ResolveNativeSolanaInput = Omit<ResolveNativeInput, "chain">;

export async function resolveNativeSolana(
  input: ResolveNativeSolanaInput,
): Promise<{ address: string; spend: Ed25519SpendSigner | null; isNewAccount: boolean }> {
  return resolveNative({
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
  return spendSignerFrom(key.publicKeyRaw(), (data) => key.sign(data));
}
