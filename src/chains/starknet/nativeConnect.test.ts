import { LocalDeviceUnwrapKey } from "../stellar/DeviceUnwrapKey";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import { parseMasterDEK, type MasterDEK } from "../../secret/dek";
import type { EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import { deviceFactorFromUnwrapKey } from "../../secret/factor";
import { nativeAddress, parseAppSalt } from "../../secret/derive";
import { wrapDekToSec1, type WrappedDEK } from "../../secret/wrap";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { resolveNativeStarknet } from "./nativeConnect";

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

describe("resolveNativeStarknet", () => {
  const appSalt = "app-salt";

  it("first device derives the OZ account address and holds the stark key", async () => {
    const enclave = new MemoryEnclave();
    const native = await resolveNativeStarknet({
      identity: { userId: "user-s1" },
      appSalt,
      registry: new InMemoryWalletRegistry(),
      credential,
      recovery: enclave,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(native.isNewAccount).toBe(true);
    expect(native.spend!.address()).toBe(native.address);
    expect(native.address).toBe(nativeAddress(enclave.dek!, "starknet", parseAppSalt(appSalt)));
  });

  it("second device recovers the same address", async () => {
    const recovery = new MemoryEnclave();
    const registry = new InMemoryWalletRegistry();
    const connect = () =>
      resolveNativeStarknet({
        identity: { userId: "user-s2" },
        appSalt,
        registry,
        credential,
        recovery,
        factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
        store: new MemoryStore(),
      });
    const first = await connect();
    const second = await connect();
    expect(second.address).toBe(first.address);
    expect(second.spend!.publicKey()).toBe(first.spend!.publicKey());
    expect(second.isNewAccount).toBe(false);
  });

  it("reloads the same key from this device's wrap without asking the enclave", async () => {
    const registry = new InMemoryWalletRegistry();
    const factor = deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate());
    const store = new MemoryStore();
    const first = await resolveNativeStarknet({
      identity: { userId: "user-s3" },
      appSalt,
      registry,
      credential,
      recovery: new MemoryEnclave(),
      factor,
      store,
    });
    const reload = await resolveNativeStarknet({
      identity: { userId: "user-s3" },
      appSalt,
      registry,
      recovery: {
        lookupDek: async () => {
          throw new Error("enclave must not be asked");
        },
      } as unknown as EnclaveDekPort,
      factor,
      store,
    });
    expect(reload.address).toBe(first.address);
    expect(reload.spend!.privateKey()).toBe(first.spend!.privateKey());
    expect(reload.isNewAccount).toBe(false);
  });

  it("has no spend key on a device with neither a local wrap nor a recovery factor", async () => {
    const registry = new InMemoryWalletRegistry();
    const registered = await registry.register({
      userId: "user-s4",
      address: "0x123",
      initialSigner: { x: 0n, y: 0n },
    });
    const native = await resolveNativeStarknet({
      identity: { userId: "user-s4" },
      appSalt,
      registry,
      factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(native.spend).toBeNull();
    expect(native.address).toBe(registered.address);
  });
});
