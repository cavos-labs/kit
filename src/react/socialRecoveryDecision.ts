import type { ConnectStatus } from "../Cavos";

/**
 * Whether this login should agree a recovery authority with the enclave, write
 * one on-chain, restore this device, or do nothing — and, critically, whether
 * it may take the credential.
 *
 * Extracted from the effect because the ordering is the whole thing, and it was
 * wrong twice in one day in ways nothing surfaced:
 *
 *   - every non-`ready` wallet was read as one being recovered, so a brand-new
 *     wallet looked like a restore;
 *   - the skip for undeployed wallets ran *after* the credential was taken.
 *     `consumeSocialRecoveryCredential` is one-shot and every wallet starts
 *     undeployed under lazy deploy, so the enrolment that should follow the
 *     first execute found nothing left.
 */
export type SocialRecoveryAction =
  /** Agree the authority with the enclave now; the chain gets it at first execute. */
  | "pre-enroll"
  /** Agree it and write it on-chain, both now. */
  | "enroll"
  /** Restore this device onto a wallet that already has an authority. */
  | "recover"
  | "skip";

export interface SocialRecoveryDecision {
  action: SocialRecoveryAction;
  /** False means the caller must not touch the one-shot credential. */
  takesCredential: boolean;
}

export function decideSocialRecovery(
  status: ConnectStatus,
  alreadyEnrolled: boolean,
): SocialRecoveryDecision {
  // An undeployed wallet has no account to write an authority to, but the
  // enclave half needs no account -- only the login, which is happening right
  // now and will not be repeated. Agreeing the authority here and letting the
  // first execute carry it on-chain is what makes recovery survive a user who
  // signs in and transacts ten minutes later: the credential expires in five,
  // and under lazy deploy every wallet starts undeployed, so waiting for the
  // account meant almost nobody was ever enrolled.
  if (status === "undeployed") {
    return { action: alreadyEnrolled ? "skip" : "pre-enroll", takesCredential: !alreadyEnrolled };
  }
  // Already enrolled: the enclave would only answer 409, and the UI would flash
  // "securing recovery" on every login to learn that.
  if (status === "ready" && alreadyEnrolled) return { action: "skip", takesCredential: false };
  return { action: status === "ready" ? "enroll" : "recover", takesCredential: true };
}
