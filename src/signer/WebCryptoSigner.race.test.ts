import { describe, expect, it, beforeEach } from "@jest/globals";
import "fake-indexeddb/auto";
import { webcrypto } from "node:crypto";
import { WebCryptoSigner } from "./WebCryptoSigner";

/**
 * A multi-chain connect brings up every chain in parallel, and each asks for the
 * same device key. On a first login none existed, so all of them created one and
 * the last write won.
 *
 * Every chain had already derived its address from the key it made — and on
 * Starknet the address IS the key — so the account was deployed with a key the
 * browser then discarded. The device that created the wallet could not sign for
 * it, and nothing reported it: the wallet simply looked like someone else's.
 */
describe("one device key, however many chains ask at once", () => {
  beforeEach(() => {
    // WebCrypto and a secure context, as the browser would provide.
    (globalThis as { crypto?: unknown }).crypto = webcrypto;
    (globalThis as { window?: unknown }).window = { isSecureContext: true };
    indexedDB.deleteDatabase("cavos-kit");
  });

  it("hands the same key to every chain connecting together", async () => {
    const keyId = `user:${Math.random()}`;
    const signers = await Promise.all([
      WebCryptoSigner.loadOrCreate({ keyId }),
      WebCryptoSigner.loadOrCreate({ keyId }),
      WebCryptoSigner.loadOrCreate({ keyId }),
    ]);

    const pubkeys = await Promise.all(signers.map((s) => s.getPublicKey()));
    const distinct = new Set(pubkeys.map((k) => `${k.x}:${k.y}`));
    expect(distinct.size).toBe(1);
  });

  it("keeps the key it handed out", async () => {
    // The half that actually broke wallets: an address derived from the key a
    // caller was given has to still be the key in storage afterwards.
    const keyId = `user:${Math.random()}`;
    const [first] = await Promise.all([
      WebCryptoSigner.loadOrCreate({ keyId }),
      WebCryptoSigner.loadOrCreate({ keyId }),
    ]);

    const reloaded = await WebCryptoSigner.load({ keyId });
    expect(await reloaded!.getPublicKey()).toEqual(await first.getPublicKey());
  });
});
