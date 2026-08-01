import { PublicKey } from "@solana/web3.js";
import type { CavosWallet, NetworkEnv } from "../Cavos";
import { bigIntTo32Bytes, hexToBytes } from "../crypto/encoding";
import { compressedPubkey } from "../chains/solana/SolanaAdapter";
import { STARKNET_NETWORKS } from "../chains/starknet/constants";
import {
  SocialRecoveryClient,
  type ChainAuthorization,
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

interface SolanaSignedAuthorization {
  chain: "solana";
  message_b64: string;
  signature_b64: string;
  recovery_pubkey_compressed_b64: string;
  recovery_nonce: string;
  expires_at: number;
}

interface RecoveryResult extends SocialRecoveryResult {
  result: "recovered";
  authorizations?: (StarknetSignedAuthorization | SolanaSignedAuthorization)[];
  stellar_device_wrap_b64?: string;
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
 * Stellar is intentionally different: the enclave seals only the DEK, while
 * Starknet/Solana enforce the recovery authority and timelock on-chain.
 */
export async function enrollHardwareIsolatedRecovery(params: {
  client: SocialRecoveryClient;
  wallet: CavosWallet;
  credential: SocialRecoveryCredential;
  delaySeconds: number;
  /** New DeviceAccount class for opt-in migration of pre-feature Starknet wallets. */
  starknetClassHash?: string;
}): Promise<{ sessionId: string; transactionHash?: string }> {
  const { client, wallet, credential, delaySeconds } = params;
  if (wallet.chain === "starknet" && params.starknetClassHash) {
    try {
      await wallet.socialRecoveryNonce();
    } catch {
      await wallet.upgrade(params.starknetClassHash);
    }
  }
  const enrollment = await client.enroll({
    walletAddress: wallet.address,
    credential,
    ...(wallet.chain === "stellar" ? { stellarDek: wallet.socialRecoveryDek() } : {}),
  });
  const result = enrollment.result as EnrollmentResult;
  assertEnrollmentResult(result);

  if (wallet.chain === "stellar") {
    // There is no restricted recovery authority on Stellar classic. The server
    // activates this KMS-sealed DEK record atomically when the enclave completes.
    return { sessionId: enrollment.sessionId };
  }

  let transactionHash: string;
  if (wallet.chain === "starknet") {
    ({ transactionHash } = await wallet.enrollSocialRecovery({
      recoveryXHex: result.recovery_x_hex,
      recoveryYHex: result.recovery_y_hex,
      delaySeconds,
      policyHashHex: result.policy_hash_hex,
    }));
  } else {
    transactionHash = await wallet.enrollSocialRecovery({
      recoveryPubkeyCompressed: fromB64(result.recovery_pubkey_compressed_b64),
      delaySeconds,
      policyHash: exactBytes(result.policy_hash_hex, 32, "policy hash"),
    });
  }
  await client.confirmEnrollment(enrollment.sessionId, transactionHash);
  return { sessionId: enrollment.sessionId, transactionHash };
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
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + Math.max(delaySeconds + 3600, 3600);
  let authorizations: ChainAuthorization[] | undefined;
  let stellarRecipientPublicKey: Uint8Array | undefined;

  if (wallet.chain === "starknet") {
    const nonce = await wallet.socialRecoveryNonce();
    authorizations = [{
      chain: "starknet",
      chain_id_hex:
        STARKNET_NETWORKS[network === "mainnet" ? "mainnet" : "sepolia"].chainId,
      account_hex: wallet.address,
      new_x_hex: toHex32(wallet.publicKey.x),
      new_y_hex: toHex32(wallet.publicKey.y),
      recovery_nonce: nonce.toString(),
      expires_at: expiresAt,
    }];
  } else if (wallet.chain === "solana") {
    const nonce = await wallet.socialRecoveryNonce();
    authorizations = [{
      chain: "solana",
      account_b58_bytes_b64: toB64(new PublicKey(wallet.address).toBytes()),
      new_pubkey_b64: toB64(compressedPubkey(wallet.publicKey)),
      recovery_nonce: nonce.toString(),
      expires_at: expiresAt,
    }];
  } else {
    stellarRecipientPublicKey = wallet.socialRecoveryRecipientPublicKey();
  }

  const recovered = await client.recover({
    walletAddress: wallet.address,
    credential,
    ...(authorizations ? { authorizations } : {}),
    ...(stellarRecipientPublicKey ? { stellarRecipientPublicKey } : {}),
  });
  const result = recovered.result as RecoveryResult;
  if (result.result !== "recovered") {
    throw new Error("kit/social-recovery: enclave returned the wrong result");
  }

  if (wallet.chain === "stellar") {
    if (!result.stellar_device_wrap_b64) {
      throw new Error("kit/social-recovery: Stellar device wrap is missing");
    }
    const transactionHash = await wallet.approveThisDeviceWithSocialWrap(
      fromB64(result.stellar_device_wrap_b64),
    );
    return {
      finalized: true,
      readyAt: now,
      finalizeTransaction: transactionHash,
    };
  }

  if (wallet.chain === "starknet") {
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

  const signed = result.authorizations?.find(
    (authorization): authorization is SolanaSignedAuthorization =>
      authorization.chain === "solana",
  );
  if (!signed) throw new Error("kit/social-recovery: Solana authorization is missing");
  const scheduleTransaction = await wallet.scheduleSocialRecovery({
    expiresAt: signed.expires_at,
    message: fromB64(signed.message_b64),
    signature: fromB64(signed.signature_b64),
    recoveryPubkeyCompressed: fromB64(signed.recovery_pubkey_compressed_b64),
  });
  if (delaySeconds > 0) {
    return {
      finalized: false,
      readyAt: now + delaySeconds,
      scheduleTransaction,
    };
  }
  const finalizeTransaction = await wallet.finalizeSocialRecovery();
  return {
    finalized: true,
    readyAt: now,
    scheduleTransaction,
    finalizeTransaction,
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

function exactBytes(value: string, length: number, label: string): Uint8Array {
  const bytes = hexToBytes(value);
  if (bytes.length !== length) {
    throw new Error(`kit/social-recovery: malformed ${label}`);
  }
  return bytes;
}

function toHex32(value: bigint): string {
  return `0x${Array.from(bigIntTo32Bytes(value), (byte) =>
    byte.toString(16).padStart(2, "0"),
  ).join("")}`;
}

function toB64(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromB64(value: string): Uint8Array {
  const normal = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normal.padEnd(Math.ceil(normal.length / 4) * 4, "="));
  return Uint8Array.from(binary, (char) => char.charCodeAt(0));
}
