import { Keypair } from "@stellar/stellar-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { randomBytes } from "@noble/hashes/utils";
import {
  WebCryptoControlKey,
  signTransactionWithControlKey,
  createSorobanSigner,
} from "./WebCryptoControlKey";

/**
 * Tests for the non-extractable WebCrypto Ed25519 control key.
 *
 * Node 22 has WebCrypto Ed25519 but NO IndexedDB, so these tests use
 * `importFromSeed` without a keyId (skips IDB) and verify the signing
 * functionality. Browser-specific IDB persistence is tested in integration.
 */

const subtle = globalThis.crypto?.subtle;
const hasEd25519 = subtle !== undefined;

const maybe = hasEd25519 ? describe : describe.skip;

maybe("WebCryptoControlKey", () => {
  it("imports a seed and produces a valid Ed25519 signature", async () => {
    const seed = randomBytes(32);
    const expectedPub = ed25519.getPublicKey(seed);

    const controlKey = await WebCryptoControlKey.importFromSeed(seed);
    expect(controlKey.publicKeyRaw()).toEqual(expectedPub);

    const message = new TextEncoder().encode("test message");
    const signature = await controlKey.sign(message);
    expect(signature).toHaveLength(64);

    expect(ed25519.verify(signature, message, expectedPub)).toBe(true);
  });

  it("signature verifies with stellar-sdk Keypair", async () => {
    const seed = randomBytes(32);
    const controlKey = await WebCryptoControlKey.importFromSeed(seed);

    const stellarKeypair = Keypair.fromRawEd25519Seed(Buffer.from(seed));
    expect(controlKey.publicAddress()).toBe(stellarKeypair.publicKey());

    const message = new TextEncoder().encode("verify with stellar-sdk");
    const signature = await controlKey.sign(message);

    expect(stellarKeypair.verify(message, Buffer.from(signature))).toBe(true);
  });

  it("private key is non-extractable", async () => {
    const seed = randomBytes(32);
    const controlKey = await WebCryptoControlKey.importFromSeed(seed);

    await expect(controlKey.tryExportPrivateKey()).rejects.toThrow();
  });

  it("wipes seed after import (caller responsibility demo)", async () => {
    const seed = randomBytes(32);
    const seedCopy = Uint8Array.from(seed);

    await WebCryptoControlKey.importFromSeed(seed);
    seed.fill(0);

    expect(seed).toEqual(new Uint8Array(32));
    expect(seedCopy).not.toEqual(new Uint8Array(32));
  });

  it("create() generates a random key that can sign", async () => {
    const controlKey = await WebCryptoControlKey.create();

    const message = new TextEncoder().encode("random key test");
    const signature = await controlKey.sign(message);
    expect(signature).toHaveLength(64);

    expect(ed25519.verify(signature, message, controlKey.publicKeyRaw())).toBe(true);
  });

  it("fromCryptoKey constructs an in-memory instance for tests", async () => {
    const seed = randomBytes(32);
    const pkcs8 = wrapEd25519SeedAsPkcs8(seed);

    const privateKey = await subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
    const publicRaw = ed25519.getPublicKey(seed);

    const controlKey = WebCryptoControlKey.fromCryptoKey(privateKey, publicRaw);

    const message = new TextEncoder().encode("fromCryptoKey test");
    const signature = await controlKey.sign(message);
    expect(ed25519.verify(signature, message, publicRaw)).toBe(true);
  });
});

maybe("signTransactionWithControlKey", () => {
  it("signs a transaction hash and calls addSignature", async () => {
    const seed = randomBytes(32);
    const controlKey = await WebCryptoControlKey.importFromSeed(seed);

    const txHash = randomBytes(32);
    const signatures: Array<{ publicKey: string; signature: string }> = [];

    const mockTx = {
      hash: () => Buffer.from(txHash),
      addSignature: (publicKey: string, signature: string) => {
        signatures.push({ publicKey, signature });
      },
    };

    await signTransactionWithControlKey(mockTx, controlKey);

    expect(signatures).toHaveLength(1);
    expect(signatures[0].publicKey).toBe(controlKey.publicAddress());

    const sigBytes = Buffer.from(signatures[0].signature, "base64");
    expect(ed25519.verify(sigBytes, txHash, controlKey.publicKeyRaw())).toBe(true);
  });
});

maybe("createSorobanSigner", () => {
  it("creates a signer callback compatible with authorizeEntry", async () => {
    const seed = randomBytes(32);
    const controlKey = await WebCryptoControlKey.importFromSeed(seed);

    const signer = createSorobanSigner(controlKey);
    const payload = randomBytes(32);

    const mockPreimage = { toXDR: () => Buffer.from(payload) };

    const result = await signer(mockPreimage, payload);

    expect(result.publicKey).toBe(controlKey.publicAddress());
    expect(ed25519.verify(result.signature, payload, controlKey.publicKeyRaw())).toBe(true);
  });

  it("hashes preimage if payload not provided", async () => {
    const seed = randomBytes(32);
    const controlKey = await WebCryptoControlKey.importFromSeed(seed);

    const signer = createSorobanSigner(controlKey);
    const preimageBytes = randomBytes(100);
    const mockPreimage = { toXDR: () => Buffer.from(preimageBytes) };

    const result = await signer(mockPreimage);

    expect(result.publicKey).toBe(controlKey.publicAddress());
    expect(result.signature).toHaveLength(64);
  });
});

function wrapEd25519SeedAsPkcs8(seed: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  return pkcs8;
}
