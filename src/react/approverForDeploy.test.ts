import { describe, expect, it, jest } from "@jest/globals";
import { recoverCandidatePublicKeys, webauthnDigest } from "../crypto/webauthn";
import { p256 } from "@noble/curves/p256";

/**
 * The passkey approver is recovered, never remembered.
 *
 * It is enrolled once, on whichever chain the user was using; the other chains
 * are deployed later and each needs that same approver, or a new device could
 * never be authorized there. Holding it in between is the trap: a note in the
 * tab dies with a refresh, one on disk is a copy that goes stale.
 *
 * An assertion carries no public key, but its signature yields two candidates,
 * and a chain that already holds the approver says which is which.
 */
describe("finding the approver from an assertion", () => {
  const priv = p256.utils.randomPrivateKey();
  const point = p256.ProjectivePoint.fromPrivateKey(priv).toAffine();
  const approver = { x: point.x, y: point.y };

  const authenticatorData = new Uint8Array(37).fill(3);
  const clientDataJSON = new TextEncoder().encode('{"type":"webauthn.get"}');
  const digest = webauthnDigest(authenticatorData, clientDataJSON);
  const sig = p256.sign(digest, priv);

  /** The wallet's rule: try each candidate, keep the one the chain knows. */
  const resolve = async (isApprover: (k: { x: bigint; y: bigint }) => Promise<boolean>) => {
    for (const c of recoverCandidatePublicKeys(sig.r, sig.s, digest)) {
      if (await isApprover(c.publicKey)) return c.publicKey;
    }
    return null;
  };

  it("picks the candidate the chain already approves", async () => {
    const found = await resolve(async (k) => k.x === approver.x && k.y === approver.y);
    expect(found).toEqual(approver);
  });

  it("recovers the real key among the candidates at all", async () => {
    const candidates = recoverCandidatePublicKeys(sig.r, sig.s, digest);
    expect(candidates.some((c) => c.publicKey.x === approver.x && c.publicKey.y === approver.y)).toBe(
      true,
    );
  });

  it("finds nothing when the passkey is a stranger to the wallet", async () => {
    // Writing a wrong candidate as the approver would mean only the wrong
    // passkey could ever authorize a device on that chain.
    expect(await resolve(async () => false)).toBeNull();
  });
});
