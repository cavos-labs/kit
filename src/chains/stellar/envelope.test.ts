import { p256 } from "@noble/curves/p256";
import { randomBytes } from "@noble/hashes/utils";
import {
  generateDEK,
  sealControlSeed,
  openControlSeed,
  wrapDEK,
  unwrapDEK,
  deriveRecoveryKEK,
  derivePasskeyKEK,
  eciesWrapDEK,
  eciesUnwrapDEK,
  chunkTo64,
  unchunk,
  DATA_ENTRY_MAX,
} from "./envelope";

describe("stellar envelope", () => {
  it("seals and opens the control seed round-trip", () => {
    const dek = generateDEK();
    const controlSeed = randomBytes(32);
    const sealed = sealControlSeed(controlSeed, dek);
    expect(openControlSeed(sealed, dek)).toEqual(controlSeed);
  });

  it("fails to open the control seed with the wrong DEK", () => {
    const controlSeed = randomBytes(32);
    const sealed = sealControlSeed(controlSeed, generateDEK());
    expect(() => openControlSeed(sealed, generateDEK())).toThrow();
  });

  it("wraps and unwraps the DEK under a raw KEK", () => {
    const dek = generateDEK();
    const kek = randomBytes(32);
    expect(unwrapDEK(wrapDEK(dek, kek), kek)).toEqual(dek);
  });

  it("rejects a tampered DEK wrap (GCM auth)", () => {
    const dek = generateDEK();
    const kek = randomBytes(32);
    const wrapped = wrapDEK(dek, kek);
    wrapped[wrapped.length - 1] ^= 0xff;
    expect(() => unwrapDEK(wrapped, kek)).toThrow();
  });

  it("derives a stable recovery KEK from a normalised code", () => {
    const a = deriveRecoveryKEK("  Amber  Basin ARCH ");
    const b = deriveRecoveryKEK("amber basin arch");
    expect(a).toEqual(b);
    expect(a.length).toBe(32);
  });

  it("derives distinct KEKs per factor from equal secret bytes", () => {
    const secret = new Uint8Array(32).fill(7);
    expect(derivePasskeyKEK(secret)).not.toEqual(deriveRecoveryKEK("amber basin arch"));
  });

  it("end-to-end: unlock control seed via the passkey factor", () => {
    const dek = generateDEK();
    const controlSeed = randomBytes(32);
    const sealed = sealControlSeed(controlSeed, dek);

    const prf = randomBytes(32);
    const kek = derivePasskeyKEK(prf);
    const wrap = wrapDEK(dek, kek);

    // Later, from only { sealed, wrap, prf }: re-derive KEK → DEK → seed.
    const recovered = openControlSeed(sealed, unwrapDEK(wrap, derivePasskeyKEK(prf)));
    expect(recovered).toEqual(controlSeed);
  });

  it("ECIES-wraps the DEK to a device P-256 key and unwraps with its scalar", () => {
    const dek = generateDEK();
    const devPriv = p256.utils.randomPrivateKey();
    const devPub = p256.getPublicKey(devPriv, false); // 65-byte uncompressed

    const blob = eciesWrapDEK(dek, devPub);
    expect(eciesUnwrapDEK(blob, devPriv)).toEqual(dek);
  });

  it("ECIES unwrap fails with the wrong device scalar", () => {
    const dek = generateDEK();
    const devPub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const blob = eciesWrapDEK(dek, devPub);
    expect(() => eciesUnwrapDEK(blob, p256.utils.randomPrivateKey())).toThrow();
  });

  it("chunks a large blob to 64-byte data entries and reassembles", () => {
    const blob = randomBytes(200);
    const chunks = chunkTo64(blob);
    expect(chunks.length).toBe(Math.ceil(200 / DATA_ENTRY_MAX));
    expect(chunks.every((c) => c.length <= DATA_ENTRY_MAX)).toBe(true);
    expect(unchunk(chunks)).toEqual(blob);
  });

  it("keeps a small blob as a single chunk", () => {
    const blob = randomBytes(60);
    expect(chunkTo64(blob)).toHaveLength(1);
  });

  it("an ECIES device wrap exceeds one data entry (needs chunking)", () => {
    const dek = generateDEK();
    const devPub = p256.getPublicKey(p256.utils.randomPrivateKey(), false);
    const blob = eciesWrapDEK(dek, devPub);
    // 33 (eph pub) + 12 (nonce) + 32 + 16 (GCM tag) = 93 bytes.
    expect(blob.length).toBeGreaterThan(DATA_ENTRY_MAX);
    expect(unchunk(chunkTo64(blob))).toEqual(blob);
  });
});
