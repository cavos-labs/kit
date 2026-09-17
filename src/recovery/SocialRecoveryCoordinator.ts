import type { CavosWallet, NetworkEnv } from "../Cavos";
import { bigIntTo32Bytes } from "../crypto/encoding";
import { STARKNET_NETWORKS } from "../chains/starknet/constants";
import {
  SocialRecoveryClient,
  type SocialRecoveryResult,
} from "./SocialRecoveryClient";
import type { SocialRecoveryCredential } from "./SocialRecoveryCredential";

interface EnrollmentResult extends SocialRecoveryResult {
  result: "enrolled";
  policy_hash_hex: string;
  recovery_pubkey_compressed_b64: string;
  recovery_x_hex: string;
  recovery_y_hex: string;
}

interface StarknetSignedAuthorization {
  chain: "starknet";
  r_hex: string;
  s_hex: string;
  y_parity: boolean;
  recovery_nonce: string;
  expires_at: number;
}

interface RecoveryResult extends SocialRecoveryResult {
  result: "recovered";
  authorizations?: StarknetSignedAuthorization[];
}

export interface CoordinatedRecoveryResult {
  /** False means the exact signer is scheduled and must be finalized after readyAt. */
  finalized: boolean;
  readyAt: number;
  scheduleTransaction?: string;
  finalizeTransaction?: string;
}

/**
 * Enrol the TEE-generated authority in the chain-native recovery mechanism.
 * Starknet writes a P-256 recovery authority on-chain. Native Solana and
 * Stellar seal a MasterDEK at connect instead. They do not add a spend signer
 * the enclave holds.
 */
export interface AgreedRecoveryAuthority {
  sessionId: string;
  result: EnrollmentResult;
}

function refuseOnChainSocial(
  wallet: CavosWallet,
): asserts wallet is Extract<CavosWallet, { chain: "starknet" }> {
  if (wallet.chain !== "starknet") {
    throw new Error(
      "kit/social-recovery: native Ed25519 chains enroll the DEK at connect",
    );
  }
}

/**
 * Agree a recovery authority with the enclave. Needs the login proof; touches
 * no chain.
 *
 * This is the half that has to happen at login. The proof is minted by the
 * sign-in and the enclave will not accept one older than five minutes, while
 * the account it protects does not exist until the user's first transaction --
 * which under lazy deploy is whenever they feel like it. Waiting for the
 * account meant a user who signed in and transacted ten minutes later was never
 * enrolled at all, and only found out when a second device could not be
 * restored.
 *
 * Repeating it is safe: an authority already agreed and not yet on-chain is
 * returned again rather than replaced, so a browser that dies between the two
 * halves loses nothing.
 */
export async function agreeRecoveryAuthority(params: {
  client: SocialRecoveryClient;
  wallet: CavosWallet;
  credential: SocialRecoveryCredential;
}): Promise<AgreedRecoveryAuthority> {
  const { client, wallet, credential } = params;
  refuseOnChainSocial(wallet);
  const enrollment = await client.enroll({
    walletAddress: wallet.address,
    credential,
  });
  const result = enrollment.result as EnrollmentResult;
  assertEnrollmentResult(result);
  return { sessionId: enrollment.sessionId, result };
}

/**
 * Write an agreed authority on-chain. Signed by the device; needs no login
 * proof, so it can happen any time after the account exists.
 */
export async function writeRecoveryAuthority(params: {
  client: SocialRecoveryClient;
  wallet: CavosWallet;
  authority: AgreedRecoveryAuthority;
  delaySeconds: number;
}): Promise<{ sessionId: string; transactionHash?: string }> {
  const { client, wallet, delaySeconds } = params;
  refuseOnChainSocial(wallet);
  const { sessionId, result } = params.authority;
  const { transactionHash } = await wallet.enrollSocialRecovery({
    recoveryXHex: result.recovery_x_hex,
    recoveryYHex: result.recovery_y_hex,
    delaySeconds,
    policyHashHex: result.policy_hash_hex,
  });
  await client.confirmEnrollment(sessionId, transactionHash);
  return { sessionId, transactionHash };
}

/** Both halves at once, for a wallet whose account already exists. */
export async function enrollHardwareIsolatedRecovery(params: {
  client: SocialRecoveryClient;
  wallet: CavosWallet;
  credential: SocialRecoveryCredential;
  delaySeconds: number;
}): Promise<{ sessionId: string; transactionHash?: string }> {
  const authority = await agreeRecoveryAuthority(params);
  return writeRecoveryAuthority({ ...params, authority });
}

/**
 * Recover this exact new device. A non-zero timelock returns a scheduled result;
 * callers can invoke the wallet's finalize method at `readyAt`.
 */
export async function recoverHardwareIsolatedDevice(params: {
  client: SocialRecoveryClient;
  wallet: CavosWallet;
  credential: SocialRecoveryCredential;
  network: NetworkEnv;
  delaySeconds: number;
}): Promise<CoordinatedRecoveryResult> {
  const { client, wallet, credential, network, delaySeconds } = params;
  if (wallet.chain === "stellar" || wallet.chain === "solana") {
    return { finalized: true, readyAt: Math.floor(Date.now() / 1000) };
  }
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + Math.max(delaySeconds + 3600, 3600);
  const nonce = await wallet.socialRecoveryNonce();
  const recovered = await client.recover({
    walletAddress: wallet.address,
    credential,
    authorizations: [{
      chain: "starknet",
      chain_id_hex:
        STARKNET_NETWORKS[network === "mainnet" ? "mainnet" : "sepolia"].chainId,
      account_hex: wallet.address,
      new_x_hex: toHex32(wallet.publicKey.x),
      new_y_hex: toHex32(wallet.publicKey.y),
      recovery_nonce: nonce.toString(),
      expires_at: expiresAt,
    }],
  });
  const result = recovered.result as RecoveryResult;
  if (result.result !== "recovered") {
    throw new Error("kit/social-recovery: enclave returned the wrong result");
  }

  const signed = result.authorizations?.find(
    (authorization): authorization is StarknetSignedAuthorization =>
      authorization.chain === "starknet",
  );
  if (!signed) throw new Error("kit/social-recovery: Starknet authorization is missing");
  const scheduled = await wallet.scheduleSocialRecovery({
    nonce: BigInt(signed.recovery_nonce),
    expiresAt: BigInt(signed.expires_at),
    rHex: signed.r_hex,
    sHex: signed.s_hex,
    yParity: signed.y_parity,
  });
  if (delaySeconds > 0) {
    return {
      finalized: false,
      readyAt: now + delaySeconds,
      scheduleTransaction: scheduled.transactionHash,
    };
  }
  const finalized = await wallet.finalizeSocialRecovery();
  return {
    finalized: true,
    readyAt: now,
    scheduleTransaction: scheduled.transactionHash,
    finalizeTransaction: finalized.transactionHash,
  };
}

function assertEnrollmentResult(result: EnrollmentResult): void {
  if (
    result.result !== "enrolled" ||
    !result.policy_hash_hex ||
    !result.recovery_pubkey_compressed_b64 ||
    !result.recovery_x_hex ||
    !result.recovery_y_hex
  ) {
    throw new Error("kit/social-recovery: enclave enrollment result is incomplete");
  }
}

function toHex32(value: bigint): string {
  return `0x${Array.from(bigIntTo32Bytes(value), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}
