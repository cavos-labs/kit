import { WebCryptoControlKey, type ControlKey } from "./WebCryptoControlKey";
import {
  resolveNativeEd25519,
  type ResolveNativeEd25519Input,
} from "../../secret/nativeAccount";
import type { Ed25519SpendSigner } from "../../signer/Ed25519SpendSigner";
import type { Ed25519Seed } from "../../secret/dek";

export type ResolveNativeStellarInput = Omit<ResolveNativeEd25519Input, "chain" | "importSpend" | "loadPersisted">;

export async function resolveNativeStellar(
  input: ResolveNativeStellarInput,
): Promise<{ address: string; control?: ControlKey; isNewAccount: boolean }> {
  let control: ControlKey | undefined;
  const native = await resolveNativeEd25519({
    ...input,
    chain: "stellar",
    loadPersisted: async (keyId) => {
      const key = await WebCryptoControlKey.load({ keyId });
      if (!key) return null;
      control = key;
      return stellarSpend(key);
    },
    importSpend: async (seed: Ed25519Seed, keyId: string) => {
      control = await WebCryptoControlKey.importFromSeed(seed, { keyId });
      return stellarSpend(control);
    },
  });
  return { address: native.address, control, isNewAccount: native.isNewAccount };
}

function stellarSpend(key: ControlKey): Ed25519SpendSigner {
  return {
    address: () => key.publicAddress(),
    publicKeyRaw: () => key.publicKeyRaw(),
    sign: (message) => key.sign(message),
  };
}
