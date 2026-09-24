import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import { parseMasterDEK, type MasterDEK } from "../../secret/dek";
import type { EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import { readLocalDek } from "../../secret/localDek";
import { addPasskey } from "../../secret/PasskeyDekPort";
import type { StoredPasskeyWrap } from "../../registry/PasskeyWrapStore";
import { wrapDekToSec1, type WrappedDEK } from "../../secret/wrap";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { resolveNativeStellar } from "./nativeConnect";

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

describe("resolveNativeStellar", () => {
  const appSalt = "app-salt";

  it("first device derives a classic G and can sign", async () => {
    const native = await resolveNativeStellar({
      identity: { userId: "user-s1" },
      appSalt,
      registry: new InMemoryWalletRegistry(),
      credential,
      recovery: new MemoryEnclave(),
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(native.address.startsWith("G")).toBe(true);
    expect(native.control!.publicAddress()).toBe(native.address);
    expect(native.isNewAccount).toBe(true);
    const sig = await native.control!.signMessage(new Uint8Array(32));
    expect(sig).toHaveLength(64);
  });

  it("second device recovers the same G without a phrase", async () => {
    const recovery = new MemoryEnclave();
    const registry = new InMemoryWalletRegistry();
    const first = await resolveNativeStellar({
      identity: { userId: "user-s2" },
      appSalt,
      registry,
      credential,
      recovery,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    const second = await resolveNativeStellar({
      identity: { userId: "user-s2" },
      appSalt,
      registry,
      credential,
      recovery,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(second.address).toBe(first.address);
    expect(second.control!.publicAddress()).toBe(first.address);
    expect(second.isNewAccount).toBe(false);
  });

  it("a passkey added after sign-up opens the wallet on a second device", async () => {
    const registry = new InMemoryWalletRegistry();
    const key = LocalDeviceUnwrapKey.generate();
    const store = new MemoryStore();
    // Sign-up asks for no passkey: the DEK is random.
    const first = await resolveNativeStellar({
      identity: { userId: "user-spk" },
      appSalt,
      registry,
      factor: deviceFactorFromUnwrapKey(key),
      store,
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
      owner: { appId: "app", userId: "user-spk" },
      dek: await readLocalDek({ chain: "stellar", userId: "user-spk", appSalt, address: first.address, store, unwrapKey: key }),
      user: { userId: "user-spk", userName: "u" },
    });

    const second = await resolveNativeStellar({
      identity: { userId: "user-spk" },
      appSalt,
      registry,
      passkey,
      passkeyWraps,
      appId: "app",
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(second.address).toBe(first.address);
    expect(second.control!.publicAddress()).toBe(first.address);
    expect(second.isNewAccount).toBe(false);
  });
});
