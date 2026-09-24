import type { Identity } from "../auth/AuthProvider";
import { toEnclaveDekPort } from "../recovery/EnclaveDekPort";
import type { SocialRecoveryClient } from "../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import type { WalletRegistry } from "../registry/WalletRegistry";
import { WebCryptoDeviceUnwrapKey } from "../chains/stellar/WebCryptoDeviceUnwrapKey";
import { HttpPasskeyWrapStore, type PasskeyWrapStore } from "../registry/PasskeyWrapStore";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { addressIndexFromRegistry } from "./addressIndex";
import { deriveSeed, parseAppSalt, type Ed25519Chain } from "./derive";
import { ensureEnclave, NO_WRAP_SOURCE } from "./DeviceSecret";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "./DeviceSecret";
import { deviceFactorFromUnwrapKey } from "./factor";
import { idbWrapStore } from "./idbWrapStore";
import { toPasskeyDekPort } from "./PasskeyDekPort";
import { zeroize, type Ed25519Seed } from "./dek";
import type { Ed25519SpendSigner } from "../signer/Ed25519SpendSigner";

export interface ResolveNativeEd25519Input<S extends { address(): string } = Ed25519SpendSigner> {
  chain: Ed25519Chain;
  identity: Identity;
  appSalt: string;
  registry: WalletRegistry;
  credential?: SocialRecoveryCredential;
  socialRecovery?: SocialRecoveryClient;
  recovery?: EnclaveDekPort;
  /** Restores a registered account on a new device, from a passkey the user added. Needs `passkeyWraps` and `appId`. */
  passkey?: PasskeyPrfProvider;
  passkeyWraps?: PasskeyWrapStore;
  appId?: string;
  factor?: DeviceFactor;
  store?: WrapStore;
  importSpend?: (seed: Ed25519Seed, keyId: string) => Promise<S>;
  loadPersisted?: (keyId: string) => Promise<S | null>;
  /**
   * Prefixes every stored key. The vault passes the app id, so one app can
   * never load another app's keys from the same browser storage.
   */
  keyScope?: string;
}

const PASSKEY_CREDENTIAL: SocialRecoveryCredential = {
  idToken: "a.b.c",
  tokenFingerprint: "passkey",
  provider: "google",
};

export { NO_WRAP_SOURCE };

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

export async function resolveNativeEd25519<S extends { address(): string } = Ed25519SpendSigner>(
  input: ResolveNativeEd25519Input<S>,
): Promise<{ address: string; spend: S | null; isNewAccount: boolean }> {
  const appSalt = parseAppSalt(input.appSalt);
  const scoped = (id: string) => (input.keyScope ? `${input.keyScope}|${id}` : id);
  const keyId = scoped(`${input.chain}:${input.identity.userId}:${input.appSalt}`);
  const factor = async (): Promise<DeviceFactor> =>
    input.factor ??
    deviceFactorFromUnwrapKey(
      await WebCryptoDeviceUnwrapKey.loadOrCreate({
        keyId: scoped(`${input.identity.userId}:${input.appSalt}`),
      }),
    );
  const ensure = async (deviceFactor: DeviceFactor) =>
    ensureEnclave({
      userId: input.identity.userId,
      appSalt,
      chains: [input.chain],
      factor: deviceFactor,
      recovery: input.recovery ?? dekPort(input),
      registry: addressIndexFromRegistry(input.registry),
      store: input.store ?? idbWrapStore(input.keyScope),
      credential: recoveryCredential(input),
    });

  const loaded = input.loadPersisted ? await input.loadPersisted(keyId) : null;
  if (loaded) {
    // A wallet created before this app used the enclave (on passkeys, or with
    // the host off) was never sealed, so a new device would find nothing to
    // recover. Seal it while this login's proof is fresh. Enroll is idempotent,
    // and hardening must never break a wallet that already signs here.
    //
    // Not awaited: on a wallet that is already sealed this is an enclave
    // session, a job and a registry claim per chain — about 3.5s of a login
    // that needs none of it to sign.
    if (input.credential && (input.socialRecovery || input.recovery)) {
      void factor().then(ensure).catch((error: unknown) =>
        console.warn(`[cavos] could not seal this wallet for recovery: ${error instanceof Error ? error.message : error}`),
      );
    }
    return { address: loaded.address(), spend: loaded, isNewAccount: false };
  }

  const deviceFactor = await factor();
  let existing = false;
  try {
    existing = Boolean(await input.registry.lookup(input.identity.userId));
  } catch {
    existing = false;
  }
  let ready;
  try {
    ready = await ensure(deviceFactor);
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
  const dek = await deviceFactor.unwrap(ready.wrap);
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

/** The passkey fields of a native connect, with the Cavos backend's wrap store. Empty without a passkey or app. */
export function passkeyRestoreInput(opts: {
  passkey?: PasskeyPrfProvider;
  appId?: string;
  backendUrl: string;
  environment?: "development" | "production";
  authToken: () => string | null;
}): Pick<ResolveNativeEd25519Input, "passkey" | "passkeyWraps" | "appId"> {
  if (!opts.passkey || !opts.appId) return {};
  return {
    passkey: opts.passkey,
    appId: opts.appId,
    passkeyWraps: new HttpPasskeyWrapStore({
      baseUrl: opts.backendUrl,
      appId: opts.appId,
      ...(opts.environment ? { environment: opts.environment } : {}),
      authToken: opts.authToken,
    }),
  };
}

function recoveryCredential(input: ResolveNativeEd25519Input<{ address(): string }>): SocialRecoveryCredential {
  if (input.credential) return input.credential;
  if (input.passkey && !input.socialRecovery && !input.recovery) return PASSKEY_CREDENTIAL;
  if (!input.socialRecovery && !input.recovery) return PASSKEY_CREDENTIAL;
  // Reached on a new account as much as on a new device, and most often after
  // an email code, which carries no token the enclave verifies.
  throw new Error(
    `kit/${input.chain}: this wallet is protected by recovery. Sign in with Google, Apple or an email link to continue.`,
  );
}

function dekPort(input: ResolveNativeEd25519Input<{ address(): string }>): EnclaveDekPort {
  if (input.recovery) return input.recovery;
  if (input.socialRecovery) return toEnclaveDekPort(input.socialRecovery);
  if (input.passkey) {
    if (!input.passkeyWraps || !input.appId) {
      throw new Error(`kit/${input.chain}: passkey restore needs an appId`);
    }
    return toPasskeyDekPort({
      passkey: input.passkey,
      wraps: input.passkeyWraps,
      owner: { appId: input.appId, userId: input.identity.userId },
    });
  }
  return localOnlyDekPort();
}
