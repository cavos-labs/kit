import "fake-indexeddb/auto";
import { WebCryptoLoginKey } from "./loginKey";
import { loginNonceOf, pkceChallenge } from "./loginBinding";
import { createLoginHost } from "./LoginHost";

describe("the login key", () => {
  afterEach(() => WebCryptoLoginKey.remove("app"));

  it("is a P-256 key whose nonce is the 43-character hash of its public key", async () => {
    const key = await WebCryptoLoginKey.create("app");
    expect(key.publicKeyRaw()).toHaveLength(65);
    expect(key.publicKeyRaw()[0]).toBe(4);
    expect(loginNonceOf(key.publicKeyRaw())).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(key.codeVerifier).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("survives a round trip through IndexedDB and still derives the same secret", async () => {
    const created = await WebCryptoLoginKey.create("app");
    const loaded = await WebCryptoLoginKey.load("app");
    expect(loaded?.publicKeyRaw()).toEqual(created.publicKeyRaw());
    expect(loaded?.codeVerifier).toBe(created.codeVerifier);
    const peer = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const peerRaw = new Uint8Array(await crypto.subtle.exportKey("raw", peer.publicKey));
    const fromCreated = await created.deriveSharedSecret(peerRaw);
    expect(fromCreated).toHaveLength(32);
    expect(await loaded!.deriveSharedSecret(peerRaw)).toEqual(fromCreated);
  });

  it("never exposes the private key", async () => {
    await WebCryptoLoginKey.create("app");
    const stored = await new Promise<{ privateKey: CryptoKey }>((resolve, reject) => {
      const open = indexedDB.open("cavos-kit-login", 1);
      open.onsuccess = () => {
        const read = open.result.transaction("login-keys").objectStore("login-keys").get("app");
        read.onsuccess = () => resolve(read.result);
        read.onerror = () => reject(read.error);
      };
    });
    expect(stored.privateKey.extractable).toBe(false);
    await expect(crypto.subtle.exportKey("pkcs8", stored.privateKey)).rejects.toThrow();
  });

  it("replaces the record at each login and keeps scopes apart", async () => {
    const first = await WebCryptoLoginKey.create("app");
    const other = await WebCryptoLoginKey.create("other");
    const second = await WebCryptoLoginKey.create("app");
    expect((await WebCryptoLoginKey.load("app"))?.publicKeyRaw()).toEqual(second.publicKeyRaw());
    expect(second.publicKeyRaw()).not.toEqual(first.publicKeyRaw());
    expect((await WebCryptoLoginKey.load("other"))?.publicKeyRaw()).toEqual(other.publicKeyRaw());
    await WebCryptoLoginKey.remove("other");
  });

  it("runs the logins that follow on a named enclave release, until told otherwise", async () => {
    expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBeUndefined();

    await WebCryptoLoginKey.signInWith("app", 4);
    expect((await WebCryptoLoginKey.load("app"))?.enclaveRelease).toBeUndefined();
    expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBe(4);
    expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBe(4);
    expect((await WebCryptoLoginKey.load("app"))?.enclaveRelease).toBe(4);
    expect((await WebCryptoLoginKey.create("other")).enclaveRelease).toBeUndefined();
    await WebCryptoLoginKey.remove("other");

    await WebCryptoLoginKey.signInWith("app", null);
    expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBeUndefined();
  });

  it("goes back to the current release by itself after an hour", async () => {
    const now = jest.spyOn(Date, "now");
    try {
      await WebCryptoLoginKey.signInWith("app", 4);
      now.mockReturnValue(Date.now() + 59 * 60_000);
      expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBe(4);
      now.mockReturnValue(Date.now() + 2 * 60_000);
      expect((await WebCryptoLoginKey.create("app")).enclaveRelease).toBeUndefined();
    } finally {
      now.mockRestore();
      await WebCryptoLoginKey.signInWith("app", null);
    }
  });

  it("is gone after remove", async () => {
    await WebCryptoLoginKey.create("app");
    await WebCryptoLoginKey.remove("app");
    await expect(WebCryptoLoginKey.load("app")).resolves.toBeNull();
  });
});

describe("the page login host", () => {
  const host = createLoginHost({ appId: "app", backendUrl: "https://cavos.test" });
  afterEach(() => host.end());

  it("answers start with public values only", async () => {
    const started = await host.start();
    const key = await WebCryptoLoginKey.load("app");
    expect(started).toEqual({
      nonce: loginNonceOf(key!.publicKeyRaw()),
      codeChallenge: pkceChallenge(key!.codeVerifier),
    });
  });

  it("says which enclave release the login runs on when it is not the current one", async () => {
    await WebCryptoLoginKey.signInWith("app", 4);
    try {
      expect((await host.start()).enclaveRelease).toBe(4);
    } finally {
      await WebCryptoLoginKey.signInWith("app", null);
    }
  });

  it("refuses to verify when no login is in progress", async () => {
    await expect(host.verify({ provider: "github", grant: "g" })).rejects.toThrow("no sign-in in progress");
  });
});
