import { resolveNative, type ResolveNativeInput } from "../../secret/nativeAccount";
import { zeroize, type Ed25519Seed } from "../../secret/dek";
import { deriveSeed, parseAppSalt } from "../../secret/derive";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import { idbWrapStore } from "../../secret/idbWrapStore";
import { WebCryptoDeviceUnwrapKey } from "../stellar/WebCryptoDeviceUnwrapKey";
import { starkKeyFromSeed, starkPublicKey, starknetAddressFromPublicKey } from "./keys";

/** The in-memory Stark key. WebCrypto cannot hold one, so it is re-derived from the DEK whenever it is needed. */
export interface StarknetSpend {
  address(): string;
  publicKey(): string;
  privateKey(): string;
}

export type ResolveNativeStarknetInput = Omit<ResolveNativeInput<StarknetSpend>, "chain">;

export async function resolveNativeStarknet(
  input: ResolveNativeStarknetInput,
): Promise<{ address: string; spend: StarknetSpend | null; isNewAccount: boolean }> {
  return resolveNative<StarknetSpend>({
    ...input,
    chain: "starknet",
    loadPersisted: input.loadPersisted ?? (() => loadPersistedStarknet(input)),
    importSpend: input.importSpend ?? (async (seed) => starknetSpendFromSeed(seed)),
  });
}

export function starknetSpendFromSeed(seed: Ed25519Seed): StarknetSpend {
  const privateKey = starkKeyFromSeed(seed);
  const publicKey = starkPublicKey(privateKey);
  const address = starknetAddressFromPublicKey(publicKey);
  return { address: () => address, publicKey: () => publicKey, privateKey: () => privateKey };
}

async function loadPersistedStarknet(input: ResolveNativeStarknetInput): Promise<StarknetSpend | null> {
  const scoped = (id: string) => (input.keyScope ? `${input.keyScope}|${id}` : id);
  const wrap = await (input.store ?? idbWrapStore(input.keyScope)).get(input.identity.userId);
  if (!wrap) return null;
  try {
    const factor =
      input.factor ??
      (await WebCryptoDeviceUnwrapKey.load({ keyId: scoped(`${input.identity.userId}:${input.appSalt}`) }).then(
        (key) => (key ? deviceFactorFromUnwrapKey(key) : null),
      ));
    if (!factor) return null;
    const dek = await factor.unwrap(wrap);
    const seed = deriveSeed(dek, "starknet", parseAppSalt(input.appSalt));
    zeroize(dek);
    try {
      return starknetSpendFromSeed(seed);
    } finally {
      zeroize(seed);
    }
  } catch {
    return null;
  }
}
