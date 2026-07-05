import { describe, expect, it } from "@jest/globals";
import { StarknetAdapter } from "./StarknetAdapter";
import type { DevicePublicKey } from "../../signer/DeviceSigner";

/**
 * The address derivation change (Option D): the address depends ONLY on
 * `addressSeed`, never on the device pubkey. These tests pin the property that
 * makes recovery self-custodial — the user recomputes the address from
 * (userId, appSalt) alone, with no device key.
 */
describe("StarknetAdapter — seed-only address derivation (Option D)", () => {
  const CLASS_HASH = "0x25cbc5423e8ee895febb0ef2c3945b408da44d0039d915fbdd681fe6b6ba66b";

  // Two distinct, real (on-curve) P-256 pubkeys — standing in for two different
  // devices the same user might enroll over time.
  const deviceA: DevicePublicKey = {
    x: 0x9a60dea803efe2c5ac2332f021401b1d344a8381a2727c2a82a5755a207cf0ffn,
    y: 0x523f353cabeaf050e718ed1c296943ce49652d15af2c6d87cab25adf8caf210n,
  };
  const deviceB: DevicePublicKey = {
    x: 0x27dc812de9374f35b5ff02901dd3f0225bddad4dafed3f1dfcc068c9e0f5ab7bn,
    y: 0x8ed95e95d913435e93e5ac18196c1eb88df7156b3ed0f3cc7f9095857eb0ffden,
  };

  it("computeAddress ignores the device pubkey (same seed → same address)", () => {
    const adapter = new StarknetAdapter({ classHash: CLASS_HASH });
    const seed = 0xdeadbeefn;

    // Pass deviceA, then deviceB, then NO device — all three MUST resolve to
    // the same address. The device pubkey no longer enters the derivation.
    const withA = adapter.computeAddress({ addressSeed: seed, initialSigner: deviceA });
    const withB = adapter.computeAddress({ addressSeed: seed, initialSigner: deviceB });
    const withNone = adapter.computeAddress({ addressSeed: seed });

    expect(withA).toBe(withB);
    expect(withA).toBe(withNone);
  });

  it("computeAddress changes with the seed", () => {
    const adapter = new StarknetAdapter({ classHash: CLASS_HASH });
    const a = adapter.computeAddress({ addressSeed: 0xdeadbeefn });
    const b = adapter.computeAddress({ addressSeed: 0xdeadbef0n });
    expect(a).not.toBe(b);
  });

  it("constructorCalldata contains only the seed (no pubkey)", () => {
    const adapter = new StarknetAdapter({ classHash: CLASS_HASH });
    const calldata = adapter.constructorCalldata(0xdeadbeefn);
    // The address hash includes ALL constructor calldata, so for the address to
    // be seed-only the calldata must be exactly [seed] — no pubkey felts.
    expect(calldata).toHaveLength(1);
    expect(calldata[0]).toBe("0xdeadbeef");
  });

  it("buildInitialize encodes pubkey felts", () => {
    const adapter = new StarknetAdapter({ classHash: CLASS_HASH });
    const call = adapter.buildInitialize("0x123", deviceA);
    expect(call.entrypoint).toBe("initialize");
    // [x_low, x_high, y_low, y_high]
    expect(call.calldata).toHaveLength(4);
  });
});
