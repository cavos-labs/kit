import { LocalDeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import type { PasskeyWrapStore, StoredPasskeyWrap } from "../registry/PasskeyWrapStore";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { generateMasterDEK, type MasterDEK } from "./dek";
import { parseAppSalt, type Ed25519Chain } from "./derive";
import {
  ensureEnclave,
  NO_WRAP_SOURCE,
  type AddressIndex,
  type EnclaveDekPort,
  type WrapStore,
} from "./DeviceSecret";
import { deviceFactorFromUnwrapKey } from "./factor";
import { readLocalDek } from "./localDek";
import { addPasskey, PASSKEY_DOES_NOT_OPEN, toPasskeyDekPort } from "./PasskeyDekPort";
import type { WrappedDEK } from "./wrap";

const appSaltString = "app-salt";
const appSalt = parseAppSalt(appSaltString);
const credential = { idToken: "a.b.c", tokenFingerprint: "passkey", provider: "google" as const };
const chains = ["solana"] as const;

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
  async lookup(userId: string, chain: Ed25519Chain) {
    return this.rows.get(`${userId}:${chain}`) ?? null;
  }
  async claim(userId: string, chain: Ed25519Chain, address: string) {
    const existing = this.rows.get(`${userId}:${chain}`);
    if (existing) return { address: existing, existing: true };
    this.rows.set(`${userId}:${chain}`, address);
    return { address, existing: false };
  }
}

class MemoryWraps implements PasskeyWrapStore {
  rows: StoredPasskeyWrap[] = [];
  async list() {
    return this.rows;
  }
  async save(_userId: string, entry: StoredPasskeyWrap) {
    this.rows.push(entry);
  }
}

/** A synced passkey: same PRF on every device. Counts the prompts it shows. */
function fakePasskey(prf: Uint8Array, id = new Uint8Array(16).fill(prf[0])) {
  const passkey = {
    prompts: 0,
    asked: [] as (Uint8Array | undefined)[],
    enroll: async () => ({ credentialId: id }),
    getSecret: async (credentialId?: Uint8Array) => {
      passkey.prompts++;
      passkey.asked.push(credentialId);
      return prf.slice();
    },
  };
  return passkey satisfies PasskeyPrfProvider;
}

/** What an app uses to create: nothing restores, nothing is minted. */
const localOnly: EnclaveDekPort = {
  lookupDek: async () => null,
  enrollDek: async () => ({ kind: "enrolled" }),
  wrapDekToFactor: async () => {
    throw new Error(NO_WRAP_SOURCE);
  },
};

const owner = { appId: "app", userId: "user" };

async function signUp(registry: MemoryIndex) {
  const key = LocalDeviceUnwrapKey.generate();
  const store = new MemoryStore();
  const ready = await ensureEnclave({
    userId: owner.userId,
    appSalt,
    chains,
    factor: deviceFactorFromUnwrapKey(key),
    recovery: localOnly,
    registry,
    store,
    credential,
  });
  const address = ready.addresses.solana!;
  const localDek = () =>
    readLocalDek({ chain: "solana", userId: owner.userId, appSalt: appSaltString, address, store, unwrapKey: key });
  return { address, localDek };
}

async function addPasskeyFrom(device: { localDek(): Promise<MasterDEK> }, passkey: PasskeyPrfProvider, wraps: MemoryWraps) {
  await addPasskey({ passkey, wraps, owner, dek: await device.localDek(), user: { userId: owner.userId, userName: "u" } });
}

function openOnNewDevice(registry: MemoryIndex, passkey: PasskeyPrfProvider, wraps: PasskeyWrapStore) {
  return ensureEnclave({
    userId: owner.userId,
    appSalt,
    chains,
    factor: deviceFactorFromUnwrapKey(LocalDeviceUnwrapKey.generate()),
    recovery: toPasskeyDekPort({ passkey, wraps, owner }),
    registry,
    store: new MemoryStore(),
    credential,
  });
}

describe("passkey restore", () => {
  it("opens the same wallet on a new device with a passkey added after sign-up", async () => {
    const registry = new MemoryIndex();
    const wraps = new MemoryWraps();
    const device1 = await signUp(registry);
    const passkey = fakePasskey(new Uint8Array(32).fill(1));
    await addPasskeyFrom(device1, passkey, wraps);

    const device2 = await openOnNewDevice(registry, passkey, wraps);
    expect(device2.addresses.solana).toBe(device1.address);
    // One wrap: the prompt is pinned to its passkey.
    expect(passkey.asked.at(-1)).toEqual(wraps.rows[0].credentialId);
  });

  it("opens with whichever of several passkeys the user picks", async () => {
    const registry = new MemoryIndex();
    const wraps = new MemoryWraps();
    const device1 = await signUp(registry);
    const apple = fakePasskey(new Uint8Array(32).fill(1));
    const google = fakePasskey(new Uint8Array(32).fill(2));
    await addPasskeyFrom(device1, apple, wraps);
    await addPasskeyFrom(device1, google, wraps);

    const device2 = await openOnNewDevice(registry, google, wraps);
    expect(device2.addresses.solana).toBe(device1.address);
    expect(google.asked.at(-1)).toBeUndefined();
  });

  it("does not ask for a passkey when none was added", async () => {
    const registry = new MemoryIndex();
    await signUp(registry);
    const passkey = fakePasskey(new Uint8Array(32).fill(1));
    await expect(openOnNewDevice(registry, passkey, new MemoryWraps())).rejects.toThrow(NO_WRAP_SOURCE);
    expect(passkey.prompts).toBe(0);
  });

  it("refuses a passkey that was not added to this wallet", async () => {
    const registry = new MemoryIndex();
    const wraps = new MemoryWraps();
    await addPasskeyFrom(await signUp(registry), fakePasskey(new Uint8Array(32).fill(1)), wraps);
    await expect(openOnNewDevice(registry, fakePasskey(new Uint8Array(32).fill(9)), wraps)).rejects.toThrow(
      PASSKEY_DOES_NOT_OPEN,
    );
  });

  it("treats a declined passkey as a device without the key", async () => {
    const registry = new MemoryIndex();
    const wraps = new MemoryWraps();
    await addPasskeyFrom(await signUp(registry), fakePasskey(new Uint8Array(32).fill(1)), wraps);
    const declined: PasskeyPrfProvider = {
      enroll: async () => ({ credentialId: new Uint8Array(16) }),
      getSecret: async () => {
        throw new Error("kit/vault: cancelled");
      },
    };
    await expect(openOnNewDevice(registry, declined, wraps)).rejects.toThrow(NO_WRAP_SOURCE);
  });

  it("creates a new account without asking for a passkey", async () => {
    const passkey = fakePasskey(new Uint8Array(32).fill(1));
    const ready = await openOnNewDevice(new MemoryIndex(), passkey, new MemoryWraps());
    expect(ready.addresses.solana).toBeTruthy();
    expect(passkey.prompts).toBe(0);
  });
});

describe("addPasskey", () => {
  it("asks the new passkey for its PRF when creation did not return it", async () => {
    const wraps = new MemoryWraps();
    const passkey = fakePasskey(new Uint8Array(32).fill(3));
    await addPasskey({ passkey, wraps, owner, dek: generateMasterDEK(), user: { userId: "user", userName: "u" } });
    expect(passkey.asked).toEqual([new Uint8Array(16).fill(3)]);
    expect(wraps.rows).toHaveLength(1);
  });
});
