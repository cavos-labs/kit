import { LocalDeviceUnwrapKey } from "../../chains/stellar/DeviceUnwrapKey";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import { parseMasterDEK, type MasterDEK } from "../../secret/dek";
import type { EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import { readLocalDek } from "../../secret/localDek";
import { addPasskey } from "../../secret/PasskeyDekPort";
import type { StoredPasskeyWrap } from "../../registry/PasskeyWrapStore";
import { wrapDekToSec1, type WrappedDEK } from "../../secret/wrap";
import { solanaSpendFromSeed } from "../../signer/Ed25519SpendSigner";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { resolveNativeSolana } from "./nativeConnect";

const credential: SocialRecoveryCredential = {
  idToken: "a.b.c",
  tokenFingerprint: "fp",
  provider: "google",
};

class MemoryStore implements WrapStore {
  private rows = new Map<string, WrappedDEK>();
  async get(userId: string) {
    return this.rows.get(userId) ?? null;
  }
  async put(userId: string, wrap: WrappedDEK) {
    this.rows.set(userId, wrap);
  }
  async clear(userId: string) {
    this.rows.delete(userId);
  }
}

class MemoryEnclave implements EnclaveDekPort {
  dek: MasterDEK | null = null;
  address: string | null = null;
  async lookupDek() {
    if (!this.dek || !this.address) return null;
    return { address: this.address };
  }
  async enrollDek(params: { address: string; dek: MasterDEK }) {
    if (this.dek) return { kind: "already-enrolled" as const, address: this.address! };
    this.dek = parseMasterDEK(params.dek);
    this.address = params.address;
    return { kind: "enrolled" as const };
  }
  async wrapDekToFactor(params: { recipientSec1: Uint8Array }) {
    if (!this.dek) throw new Error("no dek");
    return wrapDekToSec1(this.dek, params.recipientSec1);
  }
}

async function until(done: () => boolean): Promise<void> {
  for (let i = 0; i < 100 && !done(); i++) await new Promise((r) => setTimeout(r, 0));
}

describe("resolveNativeSolana", () => {
  const appSalt = "app-salt";

  it("first device derives a system-account address and can sign", async () => {
    const native = await resolveNativeSolana({
      identity: { userId: "user-n1" },
      appSalt,
      registry: new InMemoryWalletRegistry(),
      credential,
      recovery: new MemoryEnclave(),
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    expect(native.address).toBe(native.spend!.address());
    expect(native.isNewAccount).toBe(true);
    const sig = await native.spend!.signMessage(new Uint8Array(32));
    expect(sig).toHaveLength(64);
  });

  it("second device recovers the same address without a phrase", async () => {
    const recovery = new MemoryEnclave();
    const registry = new InMemoryWalletRegistry();
    const first = await resolveNativeSolana({
      identity: { userId: "user-n2" },
      appSalt,
      registry,
      credential,
      recovery,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    const second = await resolveNativeSolana({
      identity: { userId: "user-n2" },
      appSalt,
      registry,
      credential,
      recovery,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    expect(second.address).toBe(first.address);
    expect(second.spend!.address()).toBe(first.address);
    expect(second.isNewAccount).toBe(false);
  });

  it("a passkey added after sign-up opens the wallet on a second device", async () => {
    const registry = new InMemoryWalletRegistry();
    const key = LocalDeviceUnwrapKey.generate();
    const store = new MemoryStore();
    // Sign-up asks for no passkey: the DEK is random.
    const first = await resolveNativeSolana({
      identity: { userId: "user-pk" },
      appSalt,
      registry,
      factor: deviceFactorFromUnwrapKey(key),
      store,
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    const prf = new Uint8Array(32).fill(9);
    const passkey = {
      enroll: async () => ({ credentialId: new Uint8Array(16), secret: prf.slice() }),
      getSecret: async () => prf.slice(),
    };
    const saved: StoredPasskeyWrap[] = [];
    const passkeyWraps = {
      list: async () => saved,
      save: async (_userId: string, entry: StoredPasskeyWrap) => {
        saved.push(entry);
      },
    };
    await addPasskey({
      passkey,
      wraps: passkeyWraps,
      owner: { appId: "app", userId: "user-pk" },
      dek: await readLocalDek({ chain: "solana", userId: "user-pk", appSalt, address: first.address, store, unwrapKey: key }),
      user: { userId: "user-pk", userName: "u" },
    });

    const second = await resolveNativeSolana({
      identity: { userId: "user-pk" },
      appSalt,
      registry,
      passkey,
      passkeyWraps,
      appId: "app",
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    expect(second.address).toBe(first.address);
    expect(second.spend!.address()).toBe(first.address);
    expect(second.isNewAccount).toBe(false);
  });

  it("seals a wallet created without the enclave when its device signs in with one", async () => {
    const registry = new InMemoryWalletRegistry();
    const factor = deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate());
    const store = new MemoryStore();
    // Created on passkeys: nothing sealed anywhere.
    const created = await resolveNativeSolana({
      identity: { userId: "user-late" },
      appSalt,
      registry,
      factor,
      store,
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });

    // Same device, now on the enclave: the persisted key answers first.
    const enclave = new MemoryEnclave();
    await resolveNativeSolana({
      identity: { userId: "user-late" },
      appSalt,
      registry,
      credential,
      recovery: enclave,
      factor,
      store,
      loadPersisted: async () => created.spend!,
    });
    // Sealing runs behind the connect; let it finish.
    await until(() => enclave.address !== null);
    expect(enclave.address).toBe(created.address);

    const restored = await resolveNativeSolana({
      identity: { userId: "user-late" },
      appSalt,
      registry,
      credential,
      recovery: enclave,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    expect(restored.spend!.address()).toBe(created.address);
  });

  it("returns a device-held wallet without waiting for the enclave", async () => {
    const registry = new InMemoryWalletRegistry();
    const factor = deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate());
    const store = new MemoryStore();
    const created = await resolveNativeSolana({
      identity: { userId: "user-fast" },
      appSalt,
      registry,
      factor,
      store,
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });

    // An enclave that never answers: the login must not hang on it.
    const stalled = new MemoryEnclave();
    stalled.enrollDek = () => new Promise(() => undefined);
    const native = await resolveNativeSolana({
      identity: { userId: "user-fast" },
      appSalt,
      registry,
      credential,
      recovery: stalled,
      factor,
      store,
      loadPersisted: async () => created.spend!,
    });
    expect(native.address).toBe(created.address);
    expect(native.spend).toBe(created.spend);
  });

  it("first device does not prompt a passkey", async () => {
    const native = await resolveNativeSolana({
      identity: { userId: "user-local" },
      appSalt,
      registry: new InMemoryWalletRegistry(),
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
      importSpend: async (seed) => solanaSpendFromSeed(seed),
    });
    expect(native.spend).not.toBeNull();
    expect(native.spend!.address()).toBe(native.address);
    expect(native.isNewAccount).toBe(true);
  });
});
