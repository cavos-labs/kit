import { sha256 } from "@noble/hashes/sha256";

/**
 * Fixed PRF input salt — scopes the derived secret to the classic-G DEK factor.
 *
 * Stable forever: changing it changes every existing user's passkey secret.
 * Shared so the credential that registers as an on-chain approver and the one
 * that unwraps the Stellar DEK can be the same passkey — they were two separate
 * `credentials.create()` calls, which is two prompts and, worse, two passkeys in
 * the user's account for one wallet.
 */
export const PRF_SALT = sha256(new TextEncoder().encode("cavos-stellar-prf-v1"));
