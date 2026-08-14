import { resolveSocialRecoveryPolicy } from "../react/CavosProvider";
import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "./attestationDefaults";
import type { AttestationPolicy } from "./SocialRecoveryClient";

/**
 * The `isAcceptedImageDigest` cases that used to live here moved to
 * `nitro/attestation.test.ts` as `isAcceptedMeasurement`, which is the same
 * check against a PCR0 measurement rather than a container image digest.
 */

const custom: AttestationPolicy = { pcr0: "ab".repeat(48) };

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
  const measurements = () => {
    const { pcr0 } = DEFAULT_SOCIAL_RECOVERY_ATTESTATION;
    return Array.isArray(pcr0) ? pcr0 : [pcr0];
  };

  // This is deliberately allowed to be empty right now: the enclave image has
  // not been published, and an empty list fails closed, so social recovery is
  // simply unavailable rather than accepting an unverified enclave. The shape
  // check below is what stops a placeholder from shipping as if it were real.
  it("pins full-length SHA-384 measurements, when it pins any", () => {
    for (const measurement of measurements()) {
      expect(measurement).toMatch(/^[0-9a-f]{96}$/);
    }
    // A rollout window needs the incoming and outgoing image to both verify.
    expect(new Set(measurements()).size).toBe(measurements().length);
  });
});
