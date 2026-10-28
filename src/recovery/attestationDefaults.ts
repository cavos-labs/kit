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
 * An enclave is accepted on either of two paths:
 *
 * - `release`: its PCR0, PCR1 and PCR2 are vouched for by a signed release of
 *   the public `cavos-labs/cavos-recovery` repository — a Sigstore attestation
 *   made by that repository's release workflow on a `v<N>` tag, logged in
 *   Rekor. The bundle is served by the Cavos API but verified here, so a new
 *   enclave release needs no new SDK. `minVersion` revokes older releases.
 * - `pcr0`: the SHA-384 measurement of the image, as reported by
 *   `nitro-cli build-enclave`, is listed. This list is kept only for the
 *   currently deployed images, which predate signed releases; it shrinks to
 *   nothing once those are replaced.
 *
 * Override via `socialRecoveryAttestation` when you run your own enclave, or
 * pass a `pcr0` list alone to pin exactly the images you audited.
 */
export const DEFAULT_SOCIAL_RECOVERY_ATTESTATION: AttestationPolicy = {
  pcr0: [
    "7f32a8b51fabf733339db5425d31851ad2919322581fe21793db17975c44a33702fa9be0c81a391b32049a0daf220cdb",
    "f388b0bf627bdad34968ebab083688b999da2aaa369a65323a3085725de0fc79d7cf0fab6527d57e06b4b10950a150f9",
  ],
  release: {
    repository: "cavos-labs/cavos-recovery",
    repositoryId: "1333734222",
    ownerId: "216094156",
    workflow: ".github/workflows/release.yml",
    minVersion: 1,
  },
};
