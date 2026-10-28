import { sha256 } from "@noble/hashes/sha256";
import { bytesToBase64Url, utf8ToBytes } from "../crypto/encoding";
import { ENCLAVE_EMAIL_ISSUER, ENCLAVE_GITHUB_ISSUER } from "../recovery/SocialRecoveryCredential";

/**
 * Binding a provider token to the login that asked for it.
 *
 * Google, Apple and the enclave's email and GitHub tokens sign one value the client
 * chooses: the `nonce`. The kit
 * sends the hash of a secret it keeps; the Cavos backend prefixes the app, so
 * the token carries `<app_id>.<base64url(SHA-256(secret))>`. The recovery
 * enclave then only accepts the token together with the secret, which never
 * leaves this client except inside the job encrypted to the enclave.
 *
 * This is the nonce use OpenID Connect Core §15.5.2 describes, with PKCE's
 * S256 transform (RFC 7636 §4.2).
 */

/** A fresh login secret from 32 bytes of randomness. */
export function loginSecretFrom(random: Uint8Array): string {
  if (random.length !== 32) throw new Error("kit/auth: a login secret needs 32 random bytes");
  return bytesToBase64Url(random);
}

/** The value sent as the login `nonce`: base64url(SHA-256(secret)). */
export function loginNonce(secret: string): string {
  return bytesToBase64Url(sha256(utf8ToBytes(secret)));
}

/** Google, Apple and enclave email and GitHub tokens all carry a nonce this login chose. */
export function requiresLoginBinding(issuer: unknown): boolean {
  return (
    issuer === "https://accounts.google.com" ||
    issuer === "accounts.google.com" ||
    issuer === "https://appleid.apple.com" ||
    issuer === ENCLAVE_EMAIL_ISSUER ||
    issuer === ENCLAVE_GITHUB_ISSUER
  );
}

/**
 * Refuse a token this client did not ask for.
 *
 * OpenID Connect requires it ("Clients MUST verify that the nonce Claim Value
 * is equal to the value of the nonce parameter sent in the Authentication
 * Request"). Without it, a callback carrying someone else's one-time code
 * signs the user into that person's account.
 */
export function assertLoginBinding(tokenNonce: unknown, secret: string | null): asserts secret is string {
  if (!secret) {
    throw new Error(
      "kit/auth: this sign-in did not start here, or the browser could not keep its state. Sign in again.",
    );
  }
  if (typeof tokenNonce !== "string" || !tokenNonce.endsWith(`.${loginNonce(secret)}`)) {
    throw new Error("kit/auth: the sign-in response does not match this sign-in. Sign in again.");
  }
}
