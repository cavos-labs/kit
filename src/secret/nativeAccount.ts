import type { Identity } from "../auth/AuthProvider";
import { toEnclaveDekPort } from "../recovery/EnclaveDekPort";
import type { SocialRecoveryClient } from "../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import type { WalletRegistry } from "../registry/WalletRegistry";
import { WebCryptoDeviceUnwrapKey } from "../chains/stellar/WebCryptoDeviceUnwrapKey";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { addressIndexFromRegistry } from "./addressIndex";
import { deriveSeed, parseAppSalt, type Ed25519Chain } from "./derive";
import { ensureEnclave } from "./DeviceSecret";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "./DeviceSecret";
import { deviceFactorFromUnwrapKey } from "./factor";
import { idbWrapStore } from "./idbWrapStore";
import { toPasskeyDekPort } from "./PasskeyDekPort";
import { zeroize, type Ed25519Seed } from "./dek";
import type { Ed25519SpendSigner } from "../signer/Ed25519SpendSigner";

export interface ResolveNativeEd25519Input {
  chain: Ed25519Chain;
  identity: Identity;
  appSalt: string;
  registry: WalletRegistry;
  credential?: SocialRecoveryCredential;
  socialRecovery?: SocialRecoveryClient;
  recovery?: EnclaveDekPort;
  passkey?: PasskeyPrfProvider;
  factor?: DeviceFactor;
  store?: WrapStore;
  importSpend?: (seed: Ed25519Seed, keyId: string) => Promise<Ed25519SpendSigner>;
  loadPersisted?: (keyId: string) => Promise<Ed25519SpendSigner | null>;
}

const PASSKEY_CREDENTIAL: SocialRecoveryCredential = {
  idToken: "a.b.c",
  tokenFingerprint: "passkey",
  provider: "google",
};

/** New device, no local wrap, and connect was not given a passkey or enclave. */
export const NO_WRAP_SOURCE = "kit/secret: this device has no local key and no recovery wrap";

function localOnlyDekPort(): EnclaveDekPort {
  return {
    async lookupDek() {
      return null;
    },
    async enrollDek() {
      return { kind: "enrolled" };
    },
    async mintDek() {
      return null;
    },
    async wrapDekToFactor() {
      throw new Error(NO_WRAP_SOURCE);
    },
  };
}

export async function resolveNativeEd25519(
  input: ResolveNativeEd25519Input,
): Promise<{ address: string; spend: Ed25519SpendSigner | null; isNewAccount: boolean }> {
  const appSalt = parseAppSalt(input.appSalt);
  const keyId = `${input.chain}:${input.identity.userId}:${input.appSalt}`;
  const loaded = input.loadPersisted ? await input.loadPersisted(keyId) : null;
  if (loaded) {
    return { address: loaded.address(), spend: loaded, isNewAccount: false };
  }

  const factor =
    input.factor ??
    deviceFactorFromUnwrapKey(
      await WebCryptoDeviceUnwrapKey.loadOrCreate({
        keyId: `${input.identity.userId}:${input.appSalt}`,
      }),
    );
  const store = input.store ?? idbWrapStore();
  const recovery = input.recovery ?? dekPort(input);
  let existing = false;
  try {
    existing = Boolean(await input.registry.lookup(input.identity.userId));
  } catch {
    existing = false;
  }
  let ready;
  try {
    ready = await ensureEnclave({
      userId: input.identity.userId,
      appSalt,
      chains: [input.chain],
      factor,
      recovery,
      registry: addressIndexFromRegistry(input.registry),
      store,
      credential: recoveryCredential(input),
    });
  } catch (error) {
    const registered = await input.registry.lookup(input.identity.userId);
    if (
      registered &&
      error instanceof Error &&
      error.message === NO_WRAP_SOURCE
    ) {
      return { address: registered.address, spend: null, isNewAccount: false };
    }
    throw error;
  }
  const address = ready.addresses[input.chain];
  if (!address) throw new Error(`kit/${input.chain}: native connect derived no address`);
  const dek = await factor.unwrap(ready.wrap);
  const seed = deriveSeed(dek, input.chain, appSalt);
  zeroize(dek);
  try {
    if (!input.importSpend) {
      throw new Error(`kit/${input.chain}: native connect needs importSpend`);
    }
    const spend = await input.importSpend(seed, keyId);
    if (spend.address() !== address) {
      throw new Error(`kit/${input.chain}: spend key does not match the derived address`);
    }
    return { address, spend, isNewAccount: !existing };
  } finally {
    zeroize(seed);
  }
}

function recoveryCredential(input: ResolveNativeEd25519Input): SocialRecoveryCredential {
  if (input.credential) return input.credential;
  if (input.passkey && !input.socialRecovery && !input.recovery) return PASSKEY_CREDENTIAL;
  if (!input.socialRecovery && !input.recovery) return PASSKEY_CREDENTIAL;
  throw new Error(`kit/${input.chain}: sign in again to restore this device`);
}

function dekPort(input: ResolveNativeEd25519Input): EnclaveDekPort {
  if (input.recovery) return input.recovery;
  if (input.socialRecovery) return toEnclaveDekPort(input.socialRecovery);
  if (input.passkey) {
    return toPasskeyDekPort({
      passkey: input.passkey,
      userId: input.identity.userId,
      appSalt: parseAppSalt(input.appSalt),
      userName: input.identity.email ?? input.identity.userId,
    });
  }
  return localOnlyDekPort();
}
