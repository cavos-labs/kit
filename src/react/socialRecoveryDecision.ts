import type { ConnectStatus } from "../Cavos";

/**
 * Whether this login should enrol a recovery authority, restore this device, or
 * do neither — and, critically, whether it may take the credential.
 *
 * Extracted from the effect because the ordering is the whole thing, and it was
 * wrong twice in one day in ways nothing surfaced:
 *
 *   - every non-`ready` wallet was read as one being recovered, so a brand-new
 *     wallet looked like a restore;
 *   - the skip for undeployed wallets ran *after* the credential was taken.
 *     `consumeSocialRecoveryCredential` is one-shot and every wallet starts
 *     undeployed under lazy deploy, so the enrolment that should follow the
 *     first execute found nothing left. The wallets that came out of that are
 *     unrecoverable, and the only symptom is a second device failing weeks
 *     later.
 */
export type SocialRecoveryAction = "enroll" | "recover" | "skip";

export interface SocialRecoveryDecision {
  action: SocialRecoveryAction;
  /** False means the caller must not touch the one-shot credential. */
  takesCredential: boolean;
}

export function decideSocialRecovery(
  status: ConnectStatus,
  alreadyEnrolled: boolean,
): SocialRecoveryDecision {
  // Neither case: this device made the wallet, so there is nothing to restore,
  // and there is no account on-chain yet to enrol an authority against.
  if (status === "undeployed") return { action: "skip", takesCredential: false };
  // Already enrolled: the enclave would only answer 409, and the UI would flash
  // "securing recovery" on every login to learn that.
  if (status === "ready" && alreadyEnrolled) return { action: "skip", takesCredential: false };
  return { action: status === "ready" ? "enroll" : "recover", takesCredential: true };
}
