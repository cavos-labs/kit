import { p256 } from "@noble/curves/p256";
import { scValToNative, StrKey } from "@stellar/stellar-sdk";
import {
  StellarAdapter,
  sec1Pubkey,
  encodeLowSSignature,
  deviceSignatureScVal,
} from "./StellarAdapter";
import { bytesToBigInt } from "../../crypto/encoding";
import type { DevicePublicKey, DeviceSignature } from "../../signer/DeviceSigner";

function devicePubkey(priv: Uint8Array): DevicePublicKey {
  const uncompressed = p256.getPublicKey(priv, false); // 0x04 || x || y
  return {
    x: bytesToBigInt(uncompressed.slice(1, 33)),
    y: bytesToBigInt(uncompressed.slice(33, 65)),
  };
}

// A signer with no network access — computeAddress / encoders are pure.
const adapter = new StellarAdapter({
  network: "stellar-testnet",
  signer: {
    getPublicKey: async () => ({ x: 0n, y: 0n }),
    sign: async () => ({ r: 0n, s: 0n, yParity: false }),
  },
});

describe("StellarAdapter", () => {
  it("builds a 65-byte SEC-1 uncompressed pubkey matching noble", () => {
    const priv = p256.utils.randomPrivateKey();
    const pk = devicePubkey(priv);
    const sec1 = sec1Pubkey(pk);
    expect(sec1.length).toBe(65);
    expect(sec1[0]).toBe(0x04);
    expect(Buffer.from(sec1)).toEqual(Buffer.from(p256.getPublicKey(priv, false)));
  });

  it("normalizes signatures to low-S in the 64-byte r||s encoding", () => {
    const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
    const highS: DeviceSignature = { r: 5n, s: n - 10n, yParity: false };
    const enc = encodeLowSSignature(highS);
    expect(enc.length).toBe(64);
    // high-S (> n/2) must be flipped to n - s = 10.
    expect(bytesToBigInt(enc.slice(32, 64))).toBe(10n);
    // low-S passes through unchanged.
    expect(bytesToBigInt(encodeLowSSignature({ r: 5n, s: 10n, yParity: false }).slice(32, 64))).toBe(10n);
  });

  it("encodes Vec<DeviceSignature> as a symbol-keyed struct the contract decodes", () => {
    const priv = p256.utils.randomPrivateKey();
    const pk = devicePubkey(priv);
    const sig: DeviceSignature = { r: 123n, s: 456n, yParity: false };
    const scval = deviceSignatureScVal(pk, sig);
    const native = scValToNative(scval) as Array<{ public_key: Buffer; signature: Buffer }>;
    expect(native).toHaveLength(1);
    expect(Buffer.from(native[0].public_key)).toEqual(Buffer.from(sec1Pubkey(pk)));
    expect(Buffer.from(native[0].signature)).toEqual(Buffer.from(encodeLowSSignature(sig)));
  });

  it("computes the deterministic account address off-chain, matching the on-chain factory", () => {
    // Cross-check vector recorded in account-contracts/stellar/deployments/testnet.json:
    // seed = 0x01*32, signer = 0x04 || 0x02*64  ->  the factory's account_address.
    const seed = new Uint8Array(32).fill(0x01);
    const pk: DevicePublicKey = {
      x: bytesToBigInt(new Uint8Array(32).fill(0x02)),
      y: bytesToBigInt(new Uint8Array(32).fill(0x02)),
    };
    const address = adapter.computeAddress(seed, pk);
    expect(address).toBe("CCGXWAHSSXAFW3O7ULH6CPPYHZ5FXCCLIJFRDLH665QIZXBBG7S6THW2");
    expect(StrKey.isValidContract(address)).toBe(true);
  });

  it("is deterministic and sensitive to seed + signer", () => {
    const seed = new Uint8Array(32).fill(7);
    const pkA: DevicePublicKey = { x: 11n, y: 22n };
    const pkB: DevicePublicKey = { x: 11n, y: 24n };
    const base = adapter.computeAddress(seed, pkA);
    expect(adapter.computeAddress(seed, pkA)).toBe(base);
    expect(adapter.computeAddress(new Uint8Array(32).fill(8), pkA)).not.toBe(base);
    expect(adapter.computeAddress(seed, pkB)).not.toBe(base);
  });
});
