import { sha256 } from "@noble/hashes/sha256";
import { bytesToBase64Url, utf8ToBytes } from "../crypto/encoding";
import { ENCLAVE_EMAIL_ISSUER, ENCLAVE_GITHUB_ISSUER, ENCLAVE_TELEGRAM_ISSUER } from "../recovery/SocialRecoveryCredential";

/**
 * Binding a provider token to the login that asked for it.
 *
 * Google, Apple and the enclave's email, GitHub and Telegram tokens sign one value the client
 * chooses: the `nonce`. Each login has a login key, a non-extractable P-256 key
 * pair that never leaves the vault (or, without a vault, this browser's
 * IndexedDB). The kit sends the hash of its public key; the Cavos backend
 * prefixes the app, so the token carries `<app_id>.<base64url(SHA-256(public key))>`.
 * The recovery enclave only accepts the token on a channel encrypted with that
 * same key, so a stolen token is useless without it.
 *
 * This is the nonce use OpenID Connect Core §15.5.2 describes, with PKCE's
 * S256 transform (RFC 7636 §4.2).
 */

/** The value sent as the login `nonce`: base64url(SHA-256(raw uncompressed public key)). */
export function loginNonceOf(publicKeyRaw: Uint8Array): string {
  return bytesToBase64Url(sha256(publicKeyRaw));
}

/** The PKCE S256 challenge for a code verifier. */
export function pkceChallenge(verifier: string): string {
  return bytesToBase64Url(sha256(utf8ToBytes(verifier)));
}

/** Google, Apple and enclave email, GitHub and Telegram tokens all carry a nonce this login chose. */
export function requiresLoginBinding(issuer: unknown): boolean {
  return (
    issuer === "https://accounts.google.com" ||
    issuer === "accounts.google.com" ||
    issuer === "https://appleid.apple.com" ||
    issuer === ENCLAVE_EMAIL_ISSUER ||
    issuer === ENCLAVE_GITHUB_ISSUER ||
    issuer === ENCLAVE_TELEGRAM_ISSUER
  );
}

/** The refusal for a callback or code this browser has no login for. */
export const LOGIN_NOT_STARTED =
  "kit/auth: this sign-in did not start here, or the browser could not keep its state. Sign in again.";

/**
 * Refuse a token this client did not ask for.
 *
 * OpenID Connect requires it ("Clients MUST verify that the nonce Claim Value
 * is equal to the value of the nonce parameter sent in the Authentication
 * Request"). Without it, a callback carrying someone else's one-time code
 * signs the user into that person's account.
 */
export function assertLoginBinding(tokenNonce: unknown, expectedNonce: string | null): asserts expectedNonce is string {
  if (!expectedNonce) {
    throw new Error(LOGIN_NOT_STARTED);
  }
  if (typeof tokenNonce !== "string" || !tokenNonce.endsWith(`.${expectedNonce}`)) {
    throw new Error("kit/auth: the sign-in response does not match this sign-in. Sign in again.");
  }
}
