import type { AttestationPolicy } from "./SocialRecoveryClient";

/**
 * The Nitro enclave Cavos runs for hardware-isolated recovery and sign-in.
 *
 * These values answer one question: *which enclave am I willing to talk to?*
 * They ship here, in a versioned package you install and can audit, rather than
 * arriving from the recovery API — an API that told the client which enclave
 * to trust could simply name its own, and the attestation would prove nothing.
 * The attestation itself is signed by AWS, so authenticity is already anchored
 * outside Cavos; this policy only fixes the workload's identity.
 *
 * An enclave is accepted only if its PCR0, PCR1 and PCR2 are vouched for by a
 * signed release of the public `cavos-labs/cavos-recovery` repository: a
 * Sigstore attestation made by that repository's release workflow on a `v<N>`
 * tag, running in the `release` GitHub environment, and logged in Rekor. The
 * bundle is served by the Cavos API but verified here, so a new enclave release
 * needs no new SDK. `minVersion` revokes older releases: releases before v3
 * predate a critical fix and are refused.
 *
 * Override via `socialRecoveryAttestation` when you run your own enclave, or
 * pass a `pcr0` list (the SHA-384 measurement reported by
 * `nitro-cli build-enclave`) to pin exactly the images you audited.
 */
export const DEFAULT_SOCIAL_RECOVERY_ATTESTATION: AttestationPolicy = {
  release: {
    repository: "cavos-labs/cavos-recovery",
    repositoryId: "1333734222",
    ownerId: "216094156",
    workflow: ".github/workflows/release.yml",
    environment: "release",
    minVersion: 3,
  },
};
