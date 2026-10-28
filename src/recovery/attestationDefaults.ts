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
    "7f32a8b51fabf733339db5425d31851ad2919322581fe21793db17975c44a33702fa9be0c81a391b32049a0daf220cdb",
    "f388b0bf627bdad34968ebab083688b999da2aaa369a65323a3085725de0fc79d7cf0fab6527d57e06b4b10950a150f9",
  ],
};
