import type { AttestationPolicy } from "./SocialRecoveryClient";

/**
 * The Nitro enclave image Cavos runs for hardware-isolated recovery.
 *
 * These values answer one question: *which enclave am I willing to talk to?*
 * They ship here, in a versioned package you install and can audit, rather than
 * arriving from the recovery API — an API that told the client which
 * measurement to trust could simply name its own, and the attestation would
 * prove nothing. The attestation itself is signed by AWS, so authenticity is
 * already anchored outside Cavos; this policy only fixes the workload's
 * identity.
 *
 * `pcr0` is the SHA-384 measurement of the enclave image file, as reported by
 * `nitro-cli build-enclave`. It accepts a list so a rollout can overlap:
 * publish the new measurement alongside the one still deployed, ship the
 * release, then redeploy. Apps on either version keep working through the
 * transition. Order is newest first.
 *
 * Override via `socialRecoveryAttestation` when you run your own enclave.
 */
export const DEFAULT_SOCIAL_RECOVERY_ATTESTATION: AttestationPolicy = {
  pcr0: [
    // 2026-08-13 — first Nitro deployment. Verified against the running
    // enclave, not just against a local build: a document it produced was
    // checked with this package's own verifier.
    "f2f81237afb5ecd3287e622c711bef8e5fe382f13c549794e478be3f54877d0c0c80a7bc9f97150fc28150130f373f87",
  ],
};
