import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import { generateMasterDEK, zeroize, type MasterDEK } from "./dek";
import {
  nativeAddress,
  type AppSalt,
  type Ed25519Chain,
} from "./derive";
import { parseWrappedDEK, type WrappedDEK } from "./wrap";

export interface DeviceFactor {
  publicKeySec1(): Uint8Array;
  unwrap(blob: WrappedDEK): Promise<MasterDEK>;
  wrap(dek: MasterDEK): WrappedDEK;
}

export interface WrapStore {
  get(userId: string): Promise<WrappedDEK | null>;
  put(userId: string, wrap: WrappedDEK): Promise<void>;
  clear(userId: string): Promise<void>;
}

export interface AddressIndex {
  lookup(userId: string, chain: Ed25519Chain): Promise<string | null>;
  claim(
    userId: string,
    chain: Ed25519Chain,
    address: string,
  ): Promise<{ address: string; existing: boolean }>;
}

export interface EnclaveDekPort {
  lookupDek(params: {
    credential: SocialRecoveryCredential;
  }): Promise<{ address: string } | null>;
  enrollDek(params: {
    address: string;
    credential: SocialRecoveryCredential;
    dek: MasterDEK;
  }): Promise<{ kind: "enrolled" } | { kind: "already-enrolled"; address: string }>;
  wrapDekToFactor(params: {
    address: string;
    credential: SocialRecoveryCredential;
    recipientSec1: Uint8Array;
  }): Promise<WrappedDEK>;
  /**
   * Passkey path: the DEK is HKDF of the PRF, not a random secret stored on
   * the server. When this returns a DEK, ensure derives the address from it.
   */
  mintDek?(params: {
    credential: SocialRecoveryCredential;
  }): Promise<MasterDEK | null>;
}

export type ReadySecret = {
  kind: "ready";
  wrap: WrappedDEK;
  addresses: Partial<Record<Ed25519Chain, string>>;
};

export type EnclaveEnsureInput = {
  userId: string;
  appSalt: AppSalt;
  chains: readonly Ed25519Chain[];
  factor: DeviceFactor;
  recovery: EnclaveDekPort;
  registry: AddressIndex;
  store: WrapStore;
  credential: SocialRecoveryCredential;
};

const inFlight = new Map<string, Promise<ReadySecret>>();

function isMissingEnrollment(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return (
    message.includes("not_enrolled") ||
    message.includes("nothing to recover")
  );
}

export async function ensureEnclave(input: EnclaveEnsureInput): Promise<ReadySecret> {
  if (input.chains.length === 0) throw new Error("kit/secret: ensure needs a chain");
  const key = `${input.userId}:${input.chains.join(",")}`;
  const pending = inFlight.get(key);
  if (pending) return pending;
  const work = runEnsure(input).finally(() => inFlight.delete(key));
  inFlight.set(key, work);
  return work;
}

async function runEnsure(input: EnclaveEnsureInput): Promise<ReadySecret> {
  const { userId, appSalt, chains, factor, recovery, registry, store, credential } = input;
  const primary = chains[0];

  let wrap = await store.get(userId);
  let dek: MasterDEK | null = null;
  if (wrap) {
    try {
      dek = await factor.unwrap(wrap);
    } catch {
      // Salt change or a wrap from another factor: this device cannot open it.
      wrap = null;
      await store.clear(userId);
    }
  }
  const registered = await lookupAny(registry, userId, chains);

  if (dek && registered) {
    const derived = nativeAddress(dek, registered.chain, appSalt);
    if (derived !== registered.address) {
      zeroize(dek);
      dek = null;
      wrap = null;
      await store.clear(userId);
    }
  }

  if (dek && registered) {
    // A previous connect may have claimed the address and then failed to
    // seal. This device still spends from IndexedDB; a new phone cannot,
    // because recover finds nothing in the enclave. Seal every time we have
    // the DEK — enroll is idempotent once the wrap is there.
    return sealLocalDek(dek);
  }

  if (!dek && registered) {
    const minted = await recovery.mintDek?.({ credential });
    if (minted) {
      const derived = nativeAddress(minted, registered.chain, appSalt);
      if (derived === registered.address) {
        wrap = factor.wrap(minted);
        await store.put(userId, wrap);
        return sealLocalDek(minted);
      }
      zeroize(minted);
    }
    try {
      return await recoverAt(registered.address, false);
    } catch (error) {
      if (isMissingEnrollment(error)) {
        throw new Error(
          "kit/secret: this wallet has no sealed recovery. Open it once on the device that created it.",
        );
      }
      throw error;
    }
  }

  if (!dek) {
    const found = await recovery.lookupDek({ credential });
    if (found) return recoverAt(found.address, true);
    dek = (await recovery.mintDek?.({ credential })) ?? generateMasterDEK();
    wrap = factor.wrap(dek);
    await store.put(userId, wrap);
  }

  const address = nativeAddress(dek, primary, appSalt);
  const claimed = await registry.claim(userId, primary, address);
  if (claimed.address !== address) {
    zeroize(dek);
    return recoverAt(claimed.address, false);
  }

  const enrolled = await recovery.enrollDek({ address, credential, dek });
  if (enrolled.kind === "already-enrolled") {
    if (enrolled.address !== address) {
      zeroize(dek);
      return recoverAt(enrolled.address, true);
    }
    await claimAll(registry, userId, chains, dek, appSalt);
    return finish(store, userId, wrap ?? factor.wrap(dek), dek, chains, appSalt);
  }

  await claimAll(registry, userId, chains, dek, appSalt);
  return finish(store, userId, wrap ?? factor.wrap(dek), dek, chains, appSalt);

  async function sealLocalDek(current: MasterDEK): Promise<ReadySecret> {
    const local = nativeAddress(current, primary, appSalt);
    const sealed = await recovery.enrollDek({
      address: local,
      credential,
      dek: current,
    });
    if (sealed.kind === "already-enrolled" && sealed.address !== local) {
      zeroize(current);
      return recoverAt(sealed.address, true);
    }
    await claimAll(registry, userId, chains, current, appSalt);
    return finish(store, userId, wrap ?? factor.wrap(current), current, chains, appSalt);
  }

  async function recoverAt(target: string, sealThisChain: boolean): Promise<ReadySecret> {
    wrap = await recovery.wrapDekToFactor({
      address: target,
      credential,
      recipientSec1: factor.publicKeySec1(),
    });
    await store.put(userId, wrap);
    dek = await factor.unwrap(wrap);
    await claimAll(registry, userId, chains, dek, appSalt);
    if (sealThisChain) {
      const local = nativeAddress(dek, primary, appSalt);
      await recovery.enrollDek({ address: local, credential, dek });
    }
    return finish(store, userId, wrap, dek, chains, appSalt);
  }
}

async function lookupAny(
  registry: AddressIndex,
  userId: string,
  chains: readonly Ed25519Chain[],
): Promise<{ chain: Ed25519Chain; address: string } | null> {
  for (const chain of chains) {
    const address = await registry.lookup(userId, chain);
    if (address) return { chain, address };
  }
  return null;
}

async function claimAll(
  registry: AddressIndex,
  userId: string,
  chains: readonly Ed25519Chain[],
  dek: MasterDEK,
  appSalt: AppSalt,
): Promise<void> {
  for (const chain of chains) {
    const address = nativeAddress(dek, chain, appSalt);
    const claimed = await registry.claim(userId, chain, address);
    if (claimed.address !== address) {
      throw new Error("kit/secret: registry already holds a different address");
    }
  }
}

async function finish(
  store: WrapStore,
  userId: string,
  wrap: WrappedDEK,
  dek: MasterDEK,
  chains: readonly Ed25519Chain[],
  appSalt: AppSalt,
): Promise<ReadySecret> {
  const addresses: ReadySecret["addresses"] = {};
  for (const chain of chains) {
    addresses[chain] = nativeAddress(dek, chain, appSalt);
  }
  zeroize(dek);
  await store.put(userId, wrap);
  return { kind: "ready", wrap: parseWrappedDEK(wrap), addresses };
}
