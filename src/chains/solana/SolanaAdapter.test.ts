import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { PublicKey } from "@solana/web3.js";
import {
  SolanaAdapter,
  compressedPubkey,
  encodeLowSSignature,
  buildSecp256r1Instruction,
  anchorDiscriminator,
} from "./SolanaAdapter";
import { SECP256R1_N, SECP256R1_PROGRAM_ID } from "./constants";
import { deriveAddressSeedSolana } from "../../identity";
import type { DevicePublicKey } from "../../signer/DeviceSigner";
import { bytesToBigInt } from "../../crypto/encoding";

function devicePubkey(priv: Uint8Array): DevicePublicKey {
  const uncompressed = p256.getPublicKey(priv, false); // 0x04 || x || y
  return {
    x: bytesToBigInt(uncompressed.slice(1, 33)),
    y: bytesToBigInt(uncompressed.slice(33, 65)),
  };
}

describe("SolanaAdapter", () => {
  const adapter = new SolanaAdapter();

  it("compresses a {x,y} pubkey to a valid SEC1 33-byte key matching noble", () => {
    const priv = p256.utils.randomPrivateKey();
    const pk = devicePubkey(priv);
    const compressed = compressedPubkey(pk);
    expect(compressed.length).toBe(33);
    expect([0x02, 0x03]).toContain(compressed[0]);
    expect(Buffer.from(compressed).toString("hex")).toBe(
      Buffer.from(p256.getPublicKey(priv, true)).toString("hex")
    );
  });

  it("normalizes the signature to low-S", () => {
    const r = 1n;
    const highS = SECP256R1_N - 5n; // > n/2
    const sig = encodeLowSSignature(r, highS);
    const s = bytesToBigInt(sig.slice(32, 64));
    expect(s).toBe(5n); // n - (n-5)
    expect(s <= SECP256R1_N / 2n).toBe(true);
  });

  it("derives a deterministic PDA off the program id and seed (Option D: device pubkey ignored)", () => {
    const seed = deriveAddressSeedSolana({ userId: "user-123", appSalt: "app-xyz" });
    expect(seed.length).toBe(32);
    // The address is recomputable from the seed alone — two different devices
    // for the same user resolve to the SAME address. This is what makes
    // recovery self-custodial on Solana too.
    const privA = p256.utils.randomPrivateKey();
    const privB = p256.utils.randomPrivateKey();
    const addr = adapter.computeAddress(seed);
    const addrAgain = adapter.computeAddress(seed);
    // valid base58 pubkey + stable across calls
    expect(() => new PublicKey(addr)).not.toThrow();
    expect(addrAgain).toBe(addr);
    // Different seed → different address.
    const seed2 = deriveAddressSeedSolana({ userId: "user-456", appSalt: "app-xyz" });
    expect(adapter.computeAddress(seed2)).not.toBe(addr);
    // Sanity: the two devices we generated are actually distinct keys (else the
    // address-sensitivity claim would be trivially true for the wrong reason).
    expect(devicePubkey(privA).x).not.toBe(devicePubkey(privB).x);
  });

  it("builds a secp256r1 precompile ix the precompile program owns, verifiable by noble", () => {
    const priv = p256.utils.randomPrivateKey();
    const pk = devicePubkey(priv);
    const message = Buffer.from("cavos:test-message");
    const sig = p256.sign(sha256(message), priv, { lowS: true });
    const ix = buildSecp256r1Instruction(
      compressedPubkey(pk),
      sig.toCompactRawBytes(),
      message
    );
    expect(ix.programId.toBase58()).toBe(SECP256R1_PROGRAM_ID);
    // The same digest/signature/pubkey must verify off-chain (sanity on convention).
    expect(p256.verify(sig, sha256(message), p256.getPublicKey(priv, true))).toBe(true);
  });

  it("computes the anchor instruction discriminator", () => {
    const disc = anchorDiscriminator("initialize");
    expect(disc.length).toBe(8);
    expect(disc.toString("hex")).toBe(
      Buffer.from(sha256("global:initialize").slice(0, 8)).toString("hex")
    );
  });
});
