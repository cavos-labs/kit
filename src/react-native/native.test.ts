import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { NativeDeviceSigner } from "./NativeDeviceSigner";
import { NativeDeviceUnwrapKey } from "./NativeDeviceUnwrapKey";
import { NativeCavosAuth } from "./NativeCavosAuth";
import { eciesWrapDEK } from "../chains/stellar/envelope";
import { fromBase64, toBase64 } from "./encoding";

const signingPrivate = new Uint8Array(32).fill(7);
const unwrapPrivate = new Uint8Array(32).fill(9);
const signingPublic = p256.getPublicKey(signingPrivate, false);
const unwrapPublic = p256.getPublicKey(unwrapPrivate, false);
const storage = new Map<string, string>();

const bridge = {
  getOrCreateSigningKey: jest.fn(async () => ({ publicKey: toBase64(signingPublic), securityLevel: "tee" })),
  sign: jest.fn(async (_alias: string, payload: string) =>
    toBase64(p256.sign(sha256(fromBase64(payload)), signingPrivate).toDERRawBytes())),
  getOrCreateUnwrapKey: jest.fn(async () => ({ publicKey: toBase64(unwrapPublic), securityLevel: "tee" })),
  deriveSharedSecret: jest.fn(async (_alias: string, peer: string) => {
    const shared = p256.getSharedSecret(unwrapPrivate, fromBase64(peer), false);
    return toBase64(shared.subarray(1, 33));
  }),
  randomBytes: jest.fn(async (length: number) => toBase64(new Uint8Array(length).fill(13))),
  getStoredValue: jest.fn(async (key: string) => storage.get(key) ?? null),
  setStoredValue: jest.fn(async (key: string, value: string | null) => {
    if (value === null) storage.delete(key);
    else storage.set(key, value);
  }),
  deleteKeys: jest.fn(async () => undefined),
};

jest.mock("expo-modules-core", () => ({ requireNativeModule: () => bridge }), { virtual: true });
jest.mock("expo-web-browser", () => ({ openAuthSessionAsync: jest.fn() }), { virtual: true });

describe("React Native key adapters", () => {
  test("native ECDSA output satisfies the DeviceSigner contract", async () => {
    const signer = await NativeDeviceSigner.loadOrCreate({ keyId: "user:app", minimumKeySecurity: "hardware" });
    const message = new Uint8Array(32).fill(3);
    const signature = await signer.sign(message);
    const publicKey = await signer.getPublicKey();
    expect(p256.verify({ r: signature.r, s: signature.s }, sha256(message), signingPublic)).toBe(true);
    expect(publicKey.x).toBeGreaterThan(0n);
    expect(typeof signature.yParity).toBe("boolean");
  });

  test("native ECDH opens the same Stellar ECIES envelope", async () => {
    const key = await NativeDeviceUnwrapKey.loadOrCreate({ keyId: "user:app:stellar" });
    const dek = new Uint8Array(32).fill(11);
    const wrapped = eciesWrapDEK(dek, key.publicKeySec1());
    await expect(key.unwrap(wrapped)).resolves.toEqual(dek);
  });

  test("hardware-only policy rejects an OS-protected fallback", async () => {
    bridge.getOrCreateSigningKey.mockResolvedValueOnce({ publicKey: toBase64(signingPublic), securityLevel: "os-protected" });
    await expect(NativeDeviceSigner.loadOrCreate({ keyId: "fallback", minimumKeySecurity: "hardware" }))
      .rejects.toThrow("hardware-backed key required");
  });
});

describe("NativeCavosAuth", () => {
  beforeEach(() => storage.clear());

  test("persists callback identity, restores it, and logout keeps device keys", async () => {
    const auth = new NativeCavosAuth({ appId: "app", redirectUri: "cavos://auth" });
    const payload = toBase64(new TextEncoder().encode(JSON.stringify({ sub: "user-1", email: "a@b.test" })))
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const identity = await auth.handleCallback(`cavos://auth?auth_data=x.${payload}.x`);
    expect(identity).toMatchObject({ userId: "user-1", email: "a@b.test" });

    const restored = await new NativeCavosAuth({ appId: "app", redirectUri: "cavos://auth" }).restoreIdentity();
    expect(restored).toEqual(identity);
    await auth.clearStoredIdentity();
    expect(await auth.restoreIdentity()).toBeNull();
    expect(bridge.deleteKeys).not.toHaveBeenCalled();
  });
});
