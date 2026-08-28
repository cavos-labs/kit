import { StrKey } from "@stellar/stellar-sdk";
import { generateControlKey, controlKeypairFromSeed } from "./keys";

describe("stellar keys", () => {
  it("names the account with the control key's public key", () => {
    const { keypair } = generateControlKey();
    const address = keypair.publicKey();
    expect(address.startsWith("G")).toBe(true);
    expect(StrKey.isValidEd25519PublicKey(address)).toBe(true);
  });

  it("generates a random control key and rebuilds it from its seed", () => {
    const { keypair, seed } = generateControlKey();
    expect(seed).toHaveLength(32);
    expect(controlKeypairFromSeed(seed).publicKey()).toBe(keypair.publicKey());
  });

  it("control keys are random, so the address is not derivable from identity", () => {
    expect(generateControlKey().keypair.publicKey()).not.toBe(generateControlKey().keypair.publicKey());
  });

  it("rejects a control seed of the wrong length", () => {
    expect(() => controlKeypairFromSeed(new Uint8Array(16))).toThrow();
  });
});
