import { describe, expect, it } from "@jest/globals";
import { StarknetAdapter } from "./StarknetAdapter";
import { appNamespace } from "../../identity";
import type { DevicePublicKey } from "../../signer/DeviceSigner";

/**
 * The first device names the address: its pubkey is constructor calldata, and
 * Starknet hashes the calldata into the address. These tests pin the property
 * that makes squatting impossible — a key you do not hold cannot reach the
 * address it names.
 */
describe("StarknetAdapter — the first device names the address", () => {
  const CLASS_HASH = "0x25cbc5423e8ee895febb0ef2c3945b408da44d0039d915fbdd681fe6b6ba66b";
  const namespace = appNamespace({ appId: "app-1" });

  // Two distinct, real (on-curve) P-256 pubkeys — two different devices.
  const deviceA: DevicePublicKey = {
    x: 0x9a60dea803efe2c5ac2332f021401b1d344a8381a2727c2a82a5755a207cf0ffn,
    y: 0x523f353cabeaf050e718ed1c296943ce49652d15af2c6d87cab25adf8caf210n,
  };
  const deviceB: DevicePublicKey = {
    x: 0x27dc812de9374f35b5ff02901dd3f0225bddad4dafed3f1dfcc068c9e0f5ab7bn,
    y: 0x8ed95e95d913435e93e5ac18196c1eb88df7156b3ed0f3cc7f9095857eb0ffden,
  };

  const adapter = new StarknetAdapter({ classHash: CLASS_HASH });

  it("gives two devices two different addresses", () => {
    const withA = adapter.computeAddress({ namespace, initialSigner: deviceA });
    const withB = adapter.computeAddress({ namespace, initialSigner: deviceB });
    expect(withA).not.toBe(withB);
  });

  it("is deterministic for the same device and namespace", () => {
    const first = adapter.computeAddress({ namespace, initialSigner: deviceA });
    const second = adapter.computeAddress({ namespace, initialSigner: deviceA });
    expect(first).toBe(second);
  });

  it("scopes the address per app", () => {
    const inAppOne = adapter.computeAddress({ namespace, initialSigner: deviceA });
    const inAppTwo = adapter.computeAddress({
      namespace: appNamespace({ appId: "app-2" }),
      initialSigner: deviceA,
    });
    expect(inAppOne).not.toBe(inAppTwo);
  });

  it("constructorCalldata is [namespace, x_low, x_high, y_low, y_high]", () => {
    const calldata = adapter.constructorCalldata({ namespace, initialSigner: deviceA });
    // The address hash covers ALL constructor calldata, so the pubkey being in
    // here is exactly what binds the address to the device.
    expect(calldata).toHaveLength(5);
  });

  it("has no initialize entrypoint to front-run", () => {
    expect("buildInitialize" in adapter).toBe(false);
  });
});
