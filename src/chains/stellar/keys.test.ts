import { StrKey } from "@stellar/stellar-sdk";
import {
  deriveStellarMasterKeypair,
  deriveStellarMasterSeed,
  deriveStellarAddress,
  generateControlKey,
  controlKeypairFromSeed,
} from "./keys";

const identity = { userId: "user-123", appSalt: "app-abc" };

describe("stellar keys", () => {
  it("derives a deterministic master keypair from identity", () => {
    const a = deriveStellarMasterKeypair(identity);
    const b = deriveStellarMasterKeypair({ ...identity });
    expect(a.publicKey()).toBe(b.publicKey());
    expect(a.secret()).toBe(b.secret());
  });

  it("derives a valid classic G address", () => {
    const addr = deriveStellarAddress(identity);
    expect(addr.startsWith("G")).toBe(true);
    expect(StrKey.isValidEd25519PublicKey(addr)).toBe(true);
    expect(addr).toBe(deriveStellarMasterKeypair(identity).publicKey());
  });

  it("gives different users different addresses", () => {
    expect(deriveStellarAddress(identity)).not.toBe(
      deriveStellarAddress({ userId: "other", appSalt: "app-abc" }),
    );
  });

  it("scopes addresses per app (appSalt)", () => {
    expect(deriveStellarAddress(identity)).not.toBe(
      deriveStellarAddress({ userId: "user-123", appSalt: "different-app" }),
    );
  });

  it("master seed is 32 bytes", () => {
    expect(deriveStellarMasterSeed(identity)).toHaveLength(32);
  });

  it("generates a random control key and rebuilds it from its seed", () => {
    const { keypair, seed } = generateControlKey();
    expect(seed).toHaveLength(32);
    expect(controlKeypairFromSeed(seed).publicKey()).toBe(keypair.publicKey());
  });

  it("control keys are random (distinct across calls)", () => {
    expect(generateControlKey().keypair.publicKey()).not.toBe(generateControlKey().keypair.publicKey());
  });

  it("rejects a control seed of the wrong length", () => {
    expect(() => controlKeypairFromSeed(new Uint8Array(16))).toThrow();
  });
});
