import { encryptForEnclave, fetchEnclaveRelease } from "./enclaveChannel";

/**
 * The enclave's side of the channel, in WebCrypto, to the same construction
 * `cavos-recovery/enclave/src/crypto.rs` implements: one ECDH exchange, HKDF
 * salted with the session id, and a different `info` per direction.
 */
async function enclaveKeys(
  enclavePrivate: CryptoKey,
  clientPublicRaw: Uint8Array,
  sessionId: string,
) {
  const clientPublic = await crypto.subtle.importKey(
    "raw", clientPublicRaw, { name: "ECDH", namedCurve: "P-256" }, false, [],
  );
  const shared = await crypto.subtle.deriveBits({ name: "ECDH", public: clientPublic }, enclavePrivate, 256);
  const hkdf = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = (info: string) =>
    crypto.subtle.deriveKey(
      { name: "HKDF", hash: "SHA-256", salt: new TextEncoder().encode(sessionId), info: new TextEncoder().encode(info) },
      hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"],
    );
  return {
    request: await key("cavos-confidential-channel-v1"),
    response: await key("cavos-confidential-channel-v1/response"),
  };
}

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString("base64url");
const unb64 = (value: string) => new Uint8Array(Buffer.from(value, "base64url"));

describe("the channel to the enclave", () => {
  const sessionId = "7ee71f25-9f59-43f6-8091-317a94074209";

  async function exchange() {
    const enclave = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const enclavePublic = new Uint8Array(await crypto.subtle.exportKey("raw", enclave.publicKey));
    const job = new TextEncoder().encode('{"action":"enroll"}');
    const { encrypted, openResult } = await encryptForEnclave(sessionId, enclavePublic, job);
    const keys = await enclaveKeys(enclave.privateKey, unb64(encrypted.client_public_key_b64), sessionId);
    const aad = new TextEncoder().encode(sessionId);
    const seal = async (key: CryptoKey, result: unknown) => {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: aad }, key, new TextEncoder().encode(JSON.stringify(result)),
      );
      return { nonce_b64: b64(iv), ciphertext_b64: b64(new Uint8Array(ciphertext)) };
    };
    return { encrypted, openResult, keys, aad, job, seal };
  }

  it("opens an answer the enclave sealed, and the enclave opens the job", async () => {
    const { encrypted, openResult, keys, aad, job, seal } = await exchange();
    const opened = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: unb64(encrypted.nonce_b64), additionalData: aad },
      keys.request, unb64(encrypted.ciphertext_b64),
    );
    expect(new Uint8Array(opened)).toEqual(job);

    const result = { result: "enrolled", recovery_x_hex: "0x01" };
    await expect(openResult(await seal(keys.response, result))).resolves.toEqual(result);
  });

  it("refuses an answer anyone on the way back could have written", async () => {
    const { openResult, keys, seal } = await exchange();
    const forged = { result: "enrolled", recovery_x_hex: "0xattacker" };

    // Sealed under the request key, which the relay never has either, but which
    // must not double as the answer's key.
    await expect(openResult(await seal(keys.request, forged))).rejects.toThrow("failed authentication");

    // A genuine answer with one byte changed.
    const genuine = await seal(keys.response, { result: "enrolled", recovery_x_hex: "0x01" });
    const bytes = unb64(genuine.ciphertext_b64);
    bytes[0] ^= 1;
    await expect(openResult({ ...genuine, ciphertext_b64: b64(bytes) })).rejects.toThrow("failed authentication");

    // An answer from another session's exchange.
    const other = await exchange();
    await expect(
      openResult(await other.seal(other.keys.response, forged)),
    ).rejects.toThrow("failed authentication");
  });
});

describe("fetchEnclaveRelease", () => {
  const realFetch = global.fetch;
  afterEach(() => {
    global.fetch = realFetch;
  });

  it("returns the bundle the API serves", async () => {
    const bundle = { mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json" };
    global.fetch = jest.fn().mockResolvedValue(new Response(JSON.stringify(bundle))) as any;
    await expect(fetchEnclaveRelease("https://cavos.xyz/api/enclave/releases/ab")).resolves.toEqual(bundle);
    expect(global.fetch).toHaveBeenCalledWith("https://cavos.xyz/api/enclave/releases/ab", expect.anything());
  });

  it("fails clearly when no release is published", async () => {
    global.fetch = jest.fn().mockResolvedValue(new Response("", { status: 404 })) as any;
    await expect(fetchEnclaveRelease("https://cavos.xyz/x")).rejects.toThrow(/no published release/);
  });

  it("fails on other errors and on a non-JSON body", async () => {
    global.fetch = jest.fn().mockResolvedValue(new Response("", { status: 500 })) as any;
    await expect(fetchEnclaveRelease("https://cavos.xyz/x")).rejects.toThrow(/lookup failed \(500\)/);
    global.fetch = jest.fn().mockResolvedValue(new Response("<html>")) as any;
    await expect(fetchEnclaveRelease("https://cavos.xyz/x")).rejects.toThrow(/not JSON/);
  });
});
