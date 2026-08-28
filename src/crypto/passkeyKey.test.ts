import { describe, expect, it } from "@jest/globals";
import { p256 } from "@noble/curves/p256";
import { agreedPublicKey } from "./passkeyKey";
import { recoverCandidatePublicKeys } from "./webauthn";

/**
 * Establishing the passkey's public key with no chain to ask.
 *
 * A contract that already holds the approver can tell the two recovered
 * candidates apart, but the first chain to need the passkey has none — the user
 * enrolled while on Stellar, which keeps a secret rather than a key. The
 * alternative was deploying an account on a chain they were not using, purely
 * to have somewhere to look the answer up.
 */
describe("the key two assertions agree on", () => {
  const priv = p256.utils.randomPrivateKey();
  const point = p256.ProjectivePoint.fromPrivateKey(priv).toAffine();
  const real = { x: point.x, y: point.y };

  const candidatesFor = (message: Uint8Array) => {
    const digest = p256.CURVE.hash(message);
    const sig = p256.sign(digest, priv);
    return recoverCandidatePublicKeys(sig.r, sig.s, digest).map((c) => c.publicKey);
  };

  it("is the real key", () => {
    const a = candidatesFor(new Uint8Array([1]));
    const b = candidatesFor(new Uint8Array([2]));
    expect(agreedPublicKey(a, b)).toEqual(real);
  });

  it("holds over many signatures", () => {
    // The artefact is a function of the signature, so a run of them must never
    // agree by chance: a wrong approver is a passkey nobody holds guarding the
    // account.
    for (let i = 0; i < 20; i++) {
      const agreed = agreedPublicKey(candidatesFor(new Uint8Array([i])), candidatesFor(new Uint8Array([i + 100])));
      expect(agreed).toEqual(real);
    }
  });

  it("answers nothing when the signatures come from different passkeys", () => {
    const other = p256.utils.randomPrivateKey();
    const digest = p256.CURVE.hash(new Uint8Array([9]));
    const sig = p256.sign(digest, other);
    const foreign = recoverCandidatePublicKeys(sig.r, sig.s, digest).map((c) => c.publicKey);

    expect(agreedPublicKey(candidatesFor(new Uint8Array([1])), foreign)).toBeNull();
  });

  it("answers nothing rather than guessing when both agree twice", () => {
    // Same candidates twice is the caller having reused one signature, not an
    // answer. None beats the wrong one.
    const a = candidatesFor(new Uint8Array([7]));
    expect(agreedPublicKey(a, a)).toBeNull();
  });
});
