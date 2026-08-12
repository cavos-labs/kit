import { resolveSocialRecoveryPolicy } from "../react/CavosProvider";
import {
  DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
  DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH,
} from "./attestationDefaults";
import { isAcceptedImageDigest, type AttestationPolicy } from "./SocialRecoveryClient";

const custom: AttestationPolicy = {
  audience: "https://example.test/attest",
  imageDigest: "sha256:deadbeef",
  projectNumber: "1",
  serviceAccount: "someone@example.iam.gserviceaccount.com",
};

describe("resolveSocialRecoveryPolicy", () => {
  it("is off unless the app opts in", () => {
    expect(resolveSocialRecoveryPolicy({})).toBeUndefined();
    expect(resolveSocialRecoveryPolicy({ socialRecovery: false })).toBeUndefined();
  });

  it("uses the shipped constants for socialRecovery: true", () => {
    expect(resolveSocialRecoveryPolicy({ socialRecovery: true })).toBe(
      DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
    );
  });

  it("accepts an inline policy for a self-hosted enclave", () => {
    expect(resolveSocialRecoveryPolicy({ socialRecovery: custom })).toBe(custom);
  });

  it("keeps an existing explicit pin winning over the defaults", () => {
    // Apps that pinned their own measurements before `socialRecovery` existed
    // must not be silently repointed at the Cavos enclave.
    expect(
      resolveSocialRecoveryPolicy({
        socialRecovery: true,
        socialRecoveryAttestation: custom,
      }),
    ).toBe(custom);
  });
});

describe("shipped attestation defaults", () => {
  it("pins concrete values, not placeholders", () => {
    const p = DEFAULT_SOCIAL_RECOVERY_ATTESTATION;
    expect(p.audience).toMatch(/^https:\/\//);
    expect(p.projectNumber).toMatch(/^\d+$/);
    expect(p.serviceAccount).toMatch(/^[^@]+@[^@]+\.iam\.gserviceaccount\.com$/);
    expect(DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH.testnet).toMatch(/^0x[0-9a-f]{60,64}$/);
  });

  it("pins full-length sha256 digests", () => {
    const digests = Array.isArray(p().imageDigest)
      ? (p().imageDigest as string[])
      : [p().imageDigest as string];
    expect(digests.length).toBeGreaterThan(0);
    for (const d of digests) expect(d).toMatch(/^sha256:[0-9a-f]{64}$/);
    // A rollout window needs the incoming and outgoing image to both verify.
    expect(new Set(digests).size).toBe(digests.length);
  });

  function p() {
    return DEFAULT_SOCIAL_RECOVERY_ATTESTATION;
  }
});

describe("DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH", () => {
  it("has no mainnet default", () => {
    // A class hash only exists on the network it was declared on. Defaulting
    // one for mainnet would make the SDK upgrade a real account to a class that
    // is not there — worse than asking the developer for it.
    expect(DEFAULT_SOCIAL_RECOVERY_STARKNET_CLASS_HASH.mainnet).toBeUndefined();
  });
});

describe("isAcceptedImageDigest", () => {
  const A = "sha256:" + "a".repeat(64);
  const B = "sha256:" + "b".repeat(64);

  it("accepts a digest during a rollout window", () => {
    expect(isAcceptedImageDigest(A, [A, B])).toBe(true);
    expect(isAcceptedImageDigest(B, [A, B])).toBe(true);
  });

  it("still accepts a single pinned digest", () => {
    expect(isAcceptedImageDigest(A, A)).toBe(true);
  });

  // The list widens which images are accepted; it must not stop the check from
  // being a check. These are the ways a policy could silently become a no-op.
  it("rejects an image that is not pinned", () => {
    expect(isAcceptedImageDigest("sha256:" + "c".repeat(64), [A, B])).toBe(false);
  });

  it("rejects a missing attested digest", () => {
    expect(isAcceptedImageDigest(undefined, [A, B])).toBe(false);
    expect(isAcceptedImageDigest(null, [A, B])).toBe(false);
    expect(isAcceptedImageDigest("", [A, B])).toBe(false);
  });

  it("fails closed on an empty accepted list", () => {
    expect(isAcceptedImageDigest(A, [])).toBe(false);
  });

  it("requires an exact match, not a prefix", () => {
    expect(isAcceptedImageDigest("sha256:" + "a".repeat(63), [A])).toBe(false);
    expect(isAcceptedImageDigest(A + "x", [A])).toBe(false);
    expect(isAcceptedImageDigest(A.toUpperCase(), [A])).toBe(false);
  });
});
