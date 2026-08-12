import type { AttestationPolicy } from "./SocialRecoveryClient";

/**
 * The Confidential Space workload Cavos runs for hardware-isolated recovery.
 *
 * These values answer one question: *which enclave am I willing to talk to?*
 * They ship here, in a versioned package you install and can audit, rather than
 * arriving from the recovery API — an API that told the client which image to
 * trust could simply name its own, and the attestation would prove nothing.
 * The attestation itself is signed by Google, so authenticity is already
 * anchored outside Cavos; this policy only fixes the workload's identity.
 *
 * `imageDigest` accepts a list so a rollout can overlap: publish the new digest
 * alongside the one still deployed, ship the release, then redeploy. Apps on
 * either version keep working through the transition. Order is newest first.
 *
 * Override via `socialRecoveryAttestation` when you run your own enclave.
 */
export const DEFAULT_SOCIAL_RECOVERY_ATTESTATION: AttestationPolicy = {
  audience: "https://cavos.xyz/api/recovery/social/attestation",
  imageDigest: [
    // 20260811-warm-pool — adds the prewarmed one-shot worker pool.
    "sha256:c07d3dd293d7abb9baf209ad56e35b06cea222f5d0b49997cd0edc9b1f6649e4",
    // 20260810-http-client — kept for apps still pointing at the prior deploy.
    "sha256:01ade5c577768abbb926c36f594d8c882ee4d4dd4291dbd21d1586c50faa64bc",
  ],
  projectNumber: "818389533708",
  serviceAccount:
    "cavos-confidential-recovery@cavos-459123.iam.gserviceaccount.com",
};
