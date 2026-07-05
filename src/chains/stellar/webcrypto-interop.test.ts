import { p256 } from "@noble/curves/p256";
import { generateDEK, eciesWrapDEK, eciesUnwrapDEK, eciesKEKFromX, unwrapDEK } from "./envelope";

/**
 * Cross-implementation parity: a DEK wrapped by the pure-`@noble` path
 * (`eciesWrapDEK`, used to wrap TO a device on any runtime) must unwrap via the
 * WebCrypto `deriveBits` ECDH path (the browser `WebCryptoDeviceUnwrapKey`), and
 * vice-versa. This guards the X-coordinate reconciliation between noble's shared
 * secret and WebCrypto's — the subtle bit that lets a browser device open a wrap
 * created off-device (e.g. by a relayer or another device during approval).
 *
 * Uses Node's built-in WebCrypto (`globalThis.crypto.subtle`) to stand in for the
 * browser.
 */
const subtle = globalThis.crypto?.subtle;

// Replicates WebCryptoDeviceUnwrapKey.unwrap without the IndexedDB layer.
async function webcryptoUnwrap(blob: Uint8Array, privateKey: CryptoKey): Promise<Uint8Array> {
  const ephPubCompressed = blob.subarray(0, 33);
  const wrapped = blob.subarray(33);
  const ephUncompressed = p256.ProjectivePoint.fromHex(ephPubCompressed).toRawBytes(false);
  const ephKey = await subtle.importKey(
    "raw",
    ephUncompressed as unknown as BufferSource,
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  const sharedX = new Uint8Array(await subtle.deriveBits({ name: "ECDH", public: ephKey }, privateKey, 256));
  return unwrapDEK(wrapped, eciesKEKFromX(sharedX, ephPubCompressed));
}

const maybe = subtle ? describe : describe.skip;

maybe("ECIES noble ↔ WebCrypto interop", () => {
  it("noble-wrapped DEK unwraps through WebCrypto deriveBits", async () => {
    const pair = (await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, [
      "deriveBits",
    ])) as CryptoKeyPair;
    const pubRaw = new Uint8Array(await subtle.exportKey("raw", pair.publicKey)); // 65 bytes

    const dek = generateDEK();
    const blob = eciesWrapDEK(dek, pubRaw); // pure-noble wrap TO the WebCrypto key
    expect(await webcryptoUnwrap(blob, pair.privateKey)).toEqual(dek);
  });

  it("WebCrypto public key + noble scalar agree on the same KEK space", async () => {
    // A raw-scalar (LocalDeviceUnwrapKey) device: its public key round-trips
    // through WebCrypto import and the noble unwrap opens a noble wrap.
    const scalar = p256.utils.randomPrivateKey();
    const pubRaw = p256.getPublicKey(scalar, false);
    const dek = generateDEK();
    const blob = eciesWrapDEK(dek, pubRaw);
    expect(eciesUnwrapDEK(blob, scalar)).toEqual(dek);

    // And the same public key is importable by WebCrypto (proves encoding parity).
    const imported = await subtle.importKey(
      "raw",
      pubRaw as unknown as BufferSource,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    expect(imported.type).toBe("public");
  });
});
