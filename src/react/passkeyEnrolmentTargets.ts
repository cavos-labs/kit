/**
 * Which wallets a passkey enrolment writes the approver to.
 *
 * Writing to every configured chain deploys accounts the user may never touch,
 * and each deploy is gas somebody pays. Writing to none leaves the key
 * remembered in the tab, which a refresh wipes -- and then the account deploys
 * without a passkey and nothing says so.
 *
 * So: wherever the account already exists, since that costs only the approver
 * call, plus the chain the user is actually on, whose account their next
 * transaction would create anyway. Never a chain they are not using -- one that
 * comes later works the key out for itself.
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
  // Only the chain the user is on. Falling back to "any of them" deployed
  // Starknet for someone working on Stellar -- a whole account, paid for, on a
  // chain they never asked about. A chain that comes later works the key out
  // for itself; see the two-assertion path in the provider.
  return approvers.filter((w) => w.chain === selectedChain).slice(0, 1);
}
