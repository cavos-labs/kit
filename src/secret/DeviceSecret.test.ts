import { LocalDeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import { generateMasterDEK, parseMasterDEK, type MasterDEK } from "./dek";
import { parseAppSalt, masterDekFromPasskey, type Ed25519Chain } from "./derive";
import {
  ensureEnclave,
  type AddressIndex,
  type DeviceFactor,
  type EnclaveDekPort,
  type WrapStore,
} from "./DeviceSecret";
import { wrapDekToSec1, type WrappedDEK } from "./wrap";

const credential: SocialRecoveryCredential = {
  idToken: "a.b.c",
  tokenFingerprint: "fp",
  provider: "google",
};

function factor(key: LocalDeviceUnwrapKey): DeviceFactor {
  return {
    publicKeySec1: () => key.publicKeySec1(),
    unwrap: async (blob) => parseMasterDEK(await key.unwrap(blob)),
    wrap: (dek) => wrapDekToSec1(dek, key.publicKeySec1()),
  };
}

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

class MemoryIndex implements AddressIndex {
  private rows = new Map<string, string>();
  private k(userId: string, chain: Ed25519Chain) {
    return `${userId}:${chain}`;
  }
  async lookup(userId: string, chain: Ed25519Chain) {
    return this.rows.get(this.k(userId, chain)) ?? null;
  }
  async claim(userId: string, chain: Ed25519Chain, address: string) {
    const key = this.k(userId, chain);
    const existing = this.rows.get(key);
    if (existing) return { address: existing, existing: true };
    this.rows.set(key, address);
    return { address, existing: false };
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

const salt = parseAppSalt("app-salt");
const chains = ["solana", "stellar"] as const;

describe("ensureEnclave", () => {
  it("first device enrolls and claims both chain addresses", async () => {
    const ready = await ensureEnclave({
      userId: "user-1",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery: new MemoryEnclave(),
      registry: new MemoryIndex(),
      store: new MemoryStore(),
      credential,
    });
    expect(ready.kind).toBe("ready");
    expect(ready.addresses.solana).toBeTruthy();
    expect(ready.addresses.stellar).toBeTruthy();
    expect(ready.addresses.solana).not.toBe(ready.addresses.stellar);
  });

  it("reseals when the first connect claimed but did not enroll", async () => {
    let attempts = 0;
    const inner = new MemoryEnclave();
    const recovery: EnclaveDekPort = {
      lookupDek: () => inner.lookupDek(),
      enrollDek: async (params) => {
        attempts += 1;
        if (attempts === 1) throw new Error("enclave down");
        return inner.enrollDek(params);
      },
      wrapDekToFactor: (params) => inner.wrapDekToFactor(params),
    };
    const registry = new MemoryIndex();
    const store = new MemoryStore();
    const key = LocalDeviceUnwrapKey.generate();
    const input = {
      userId: "user-seal",
      appSalt: salt,
      chains,
      factor: factor(key),
      recovery,
      registry,
      store,
      credential,
    };
    await expect(ensureEnclave(input)).rejects.toThrow("enclave down");
    const ready = await ensureEnclave(input);
    expect(ready.kind).toBe("ready");
    expect(attempts).toBe(2);
    const phone = await ensureEnclave({
      ...input,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      store: new MemoryStore(),
    });
    expect(phone.addresses).toEqual(ready.addresses);
  });

  it("second device recovers the same addresses without a phrase", async () => {
    const recovery = new MemoryEnclave();
    const registry = new MemoryIndex();
    const first = await ensureEnclave({
      userId: "user-2",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    const second = await ensureEnclave({
      userId: "user-2",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    expect(second.addresses).toEqual(first.addresses);
  });

  it("identity lookup recovers the sealed DEK without a local wrap", async () => {
    const recovery = new MemoryEnclave();
    const registry = new MemoryIndex();
    const first = await ensureEnclave({
      userId: "user-3",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    const store = new MemoryStore();
    const lost = await ensureEnclave({
      userId: "user-3-other",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry: new MemoryIndex(),
      store,
      credential,
    });
    expect(lost.addresses).toEqual(first.addresses);
  });

  it("registry claim conflict recovers the winner address", async () => {
    const recovery = new MemoryEnclave();
    const registry = new MemoryIndex();
    const first = await ensureEnclave({
      userId: "user-6",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    const blind: AddressIndex = {
      lookup: async () => null,
      claim: (userId, chain, address) => registry.claim(userId, chain, address),
    };
    const second = await ensureEnclave({
      userId: "user-6",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry: blind,
      store: new MemoryStore(),
      credential,
    });
    expect(second.addresses).toEqual(first.addresses);
  });

  it("discards a stale local wrap that does not match the registry", async () => {
    const recovery = new MemoryEnclave();
    const registry = new MemoryIndex();
    const store = new MemoryStore();
    const key = LocalDeviceUnwrapKey.generate();
    const first = await ensureEnclave({
      userId: "user-4",
      appSalt: salt,
      chains,
      factor: factor(key),
      recovery,
      registry,
      store,
      credential,
    });
    await store.put("user-4", factor(key).wrap(generateMasterDEK()));
    const recovered = await ensureEnclave({
      userId: "user-4",
      appSalt: salt,
      chains,
      factor: factor(key),
      recovery,
      registry,
      store,
      credential,
    });
    expect(recovered.addresses).toEqual(first.addresses);
  });

  it("serializes two first-device ensures for the same user", async () => {
    const recovery = new MemoryEnclave();
    const registry = new MemoryIndex();
    const store = new MemoryStore();
    const key = LocalDeviceUnwrapKey.generate();
    const input = {
      userId: "user-5",
      appSalt: salt,
      chains,
      factor: factor(key),
      recovery,
      registry,
      store,
      credential,
    };
    const [a, b] = await Promise.all([ensureEnclave(input), ensureEnclave(input)]);
    expect(a.addresses).toEqual(b.addresses);
  });

  it("mints the same addresses from a passkey without a server wrap", async () => {
    const prf = new Uint8Array(32).fill(9);
    const recovery: EnclaveDekPort = {
      lookupDek: async () => null,
      enrollDek: async () => ({ kind: "enrolled" }),
      wrapDekToFactor: async () => {
        throw new Error("passkey path must not fetch a wrap");
      },
      mintDek: async () => masterDekFromPasskey(prf, salt),
    };
    const registry = new MemoryIndex();
    const first = await ensureEnclave({
      userId: "user-pk",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    const second = await ensureEnclave({
      userId: "user-pk",
      appSalt: salt,
      chains,
      factor: factor(LocalDeviceUnwrapKey.generate()),
      recovery,
      registry,
      store: new MemoryStore(),
      credential,
    });
    expect(second.addresses).toEqual(first.addresses);
  });
});
