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
  it("accepts signed releases of the public cavos-recovery repository", () => {
    expect(DEFAULT_SOCIAL_RECOVERY_ATTESTATION.release).toEqual({
      repository: "cavos-labs/cavos-recovery",
      repositoryId: "1333734222",
      ownerId: "216094156",
      workflow: ".github/workflows/release.yml",
      environment: "release",
      minVersion: 3,
    });
  });

  it("pins no image, so only signed releases are accepted", () => {
    expect(DEFAULT_SOCIAL_RECOVERY_ATTESTATION.pcr0).toBeUndefined();
  });
});
