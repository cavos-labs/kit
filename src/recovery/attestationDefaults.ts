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
    // 2026-10-11 — the enclave that binds a token to the app and the login,
    // and seals its answers. Deployed, and read back from the running enclave
    // on the host. It is the only measurement accepted: this release reads the
    // sealed answer, which no earlier enclave produces, so there is no older
    // image it could work with.
    "5ec163560006f105b5448c2db77ecf5ec442e00abd475f65349d6d93e837279652708770c50b3aa2e8676f553f572825",
  ],
};
