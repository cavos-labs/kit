import { WebCryptoControlKey, type ControlKey } from "./WebCryptoControlKey";
import {
  resolveNativeEd25519,
  type ResolveNativeEd25519Input,
} from "../../secret/nativeAccount";
import type { Ed25519Seed } from "../../secret/dek";

export type ResolveNativeStellarInput = Omit<ResolveNativeEd25519Input, "chain" | "importSpend" | "loadPersisted">;

type StellarSpend = { address(): string; control: ControlKey };

export async function resolveNativeStellar(
  input: ResolveNativeStellarInput,
): Promise<{ address: string; control?: ControlKey; isNewAccount: boolean }> {
  const native = await resolveNativeEd25519<StellarSpend>({
    ...input,
    chain: "stellar",
    loadPersisted: async (keyId) => {
      const key = await WebCryptoControlKey.load({ keyId });
      return key ? stellarSpend(key) : null;
    },
    importSpend: async (seed: Ed25519Seed, keyId: string) =>
      stellarSpend(await WebCryptoControlKey.importFromSeed(seed, { keyId })),
  });
  return { address: native.address, control: native.spend?.control, isNewAccount: native.isNewAccount };
}

function stellarSpend(control: ControlKey): StellarSpend {
  return { address: () => control.publicAddress(), control };
}
