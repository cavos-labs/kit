/**
 * Which wallets a passkey enrolment writes the approver to.
 *
 * Writing to every configured chain deploys accounts the user may never touch,
 * and each deploy is gas somebody pays. Writing to none leaves the key
 * remembered in the tab, which a refresh wipes -- and then the account deploys
 * without a passkey and nothing says so.
 *
 * So: wherever the account already exists, since that costs only the approver
 * call, plus exactly one that does not, when none do. That one gives later
 * chains something to check a recovered key against, which is what lets them
 * acquire the passkey at their own deploy instead of it being held anywhere.
 *
 * Stellar is never a target: its factor is a secret derived from the passkey,
 * not a public key a chain can hold.
 */
export interface EnrolmentWallet {
  chain: string;
  status: "undeployed" | "ready" | "needs-device-approval";
}

/** A target is never Stellar, so it always has an approver to register. */
type ApproverWallet = EnrolmentWallet & {
  addApprover(pubkey: { x: bigint; y: bigint }): Promise<{ transactionHash?: string }>;
};

export function passkeyEnrolmentTargets<T extends EnrolmentWallet>(
  wallets: T[],
  selectedChain: string,
): (T & ApproverWallet)[] {
  const approvers = wallets.filter(
    (w): w is T & ApproverWallet => w.chain !== "stellar" && "addApprover" in w,
  );
  const deployed = approvers.filter((w) => w.status !== "undeployed");
  if (deployed.length > 0) return deployed;
  const onScreen = approvers.filter((w) => w.chain === selectedChain);
  return (onScreen.length > 0 ? onScreen : approvers).slice(0, 1);
}
