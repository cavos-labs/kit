import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { NativeDeviceUnwrapKey } from "./NativeDeviceUnwrapKey";
import { NativeCavosAuth } from "./NativeCavosAuth";
import { eciesWrapDEK } from "../chains/stellar/envelope";
import { fromBase64, toBase64 } from "./encoding";
import { loginNonce, loginSecretFrom } from "../auth/loginBinding";
import * as WebBrowser from "expo-web-browser";

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
  test("native ECDH opens the same Stellar ECIES envelope", async () => {
    const key = await NativeDeviceUnwrapKey.loadOrCreate({ keyId: "user:app:stellar" });
    const dek = new Uint8Array(32).fill(11);
    const wrapped = eciesWrapDEK(dek, key.publicKeySec1());
    await expect(key.unwrap(wrapped)).resolves.toEqual(dek);
  });

  test("hardware-only policy rejects an OS-protected fallback", async () => {
    bridge.getOrCreateUnwrapKey.mockResolvedValueOnce({ publicKey: toBase64(unwrapPublic), securityLevel: "os-protected" });
    await expect(NativeDeviceUnwrapKey.loadOrCreate({ keyId: "fallback", minimumKeySecurity: "hardware" }))
      .rejects.toThrow("hardware-backed key required");
  });
});

describe("NativeCavosAuth", () => {
  beforeEach(() => storage.clear());

  test("persists callback identity, restores it, and logout keeps device keys", async () => {
    const auth = new NativeCavosAuth({ appId: "app", redirectUri: "cavos://auth" });
    // The bridge's randomness is fixed above, so the secret this login keeps
    // is known, and with it the nonce the provider would sign.
    const secret = loginSecretFrom(new Uint8Array(32).fill(13));
    const payload = toBase64(new TextEncoder().encode(JSON.stringify({
      iss: "https://accounts.google.com",
      sub: "user-1",
      email: "a@b.test",
      nonce: `0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f.${loginNonce(secret)}`,
      iat: 1_700_000_000,
    })))
      .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    const callback = `cavos://auth?auth_data=x.${payload}.x`;

    // A callback this app did not ask for is refused before anything is kept.
    await expect(auth.handleCallback(callback)).rejects.toThrow("did not start here");
    expect(() => auth.getSocialRecoveryCredential()).toThrow("fresh social login");

    const fetchMock = jest.spyOn(globalThis, "fetch").mockResolvedValue({
      ok: true,
      json: async () => ({ url: "https://provider.test/authorize" }),
    } as Response);
    (WebBrowser.openAuthSessionAsync as jest.Mock).mockResolvedValue({ type: "success", url: callback });
    const identity = await auth.login("google");
    expect(String(fetchMock.mock.calls[0][0])).toContain(`nonce=${loginNonce(secret)}`);
    fetchMock.mockRestore();

    expect(identity).toMatchObject({ userId: "user-1", email: "a@b.test" });
    expect(auth.getSocialRecoveryCredential()).toMatchObject({
      idToken: `x.${payload}.x`,
      tokenFingerprint: expect.stringMatching(/^[A-Za-z0-9_-]{43}$/),
      noncePreimage: secret,
    });

    const restored = await new NativeCavosAuth({ appId: "app", redirectUri: "cavos://auth" }).restoreIdentity();
    expect(restored).toEqual(identity);
    await auth.clearStoredIdentity();
    expect(await auth.restoreIdentity()).toBeNull();
    expect(() => auth.getSocialRecoveryCredential()).toThrow("fresh social login");
    expect(bridge.deleteKeys).not.toHaveBeenCalled();
  });

  test("email sign-in refuses rather than skip enclave attestation", async () => {
    const auth = new NativeCavosAuth({ appId: "app", redirectUri: "myapp://cb" });
    await expect(auth.sendOtp("a@b.test")).rejects.toMatchObject({ code: "unsupported" });
    await expect(auth.verifyOtp("a@b.test", "qpzry9x8g")).rejects.toMatchObject({ code: "unsupported" });
  });
});
