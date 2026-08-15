import { sha256 } from "@noble/hashes/sha256";
import { Buffer } from "buffer";
import { utf8ToBytes } from "../crypto/encoding";

/**
 * A fresh provider token plus its non-secret fingerprint. The fingerprint is
 * sent to the control plane to reserve a single recovery session; the token
 * itself is sent only through the attested encrypted channel.
 */
export type SocialRecoveryProvider = "google" | "apple" | "email";

export interface SocialRecoveryCredential {
  idToken: string;
  tokenFingerprint: string;
  /**
   * Which provider signed this token, read from its `iss`.
   *
   * The control plane needs it to pick the policy the enclave verifies
   * against, and cannot read it itself: the token only reaches the enclave,
   * encrypted, after the session already exists. Reading it here is not a
   * security check — the enclave verifies the signature, issuer and audience
   * against the sealed policy, and a wrong answer here produces a policy the
   * token cannot verify against rather than one that wrongly accepts it.
   */
  provider: SocialRecoveryProvider;
}

export function createSocialRecoveryCredential(
  idToken: string,
): SocialRecoveryCredential {
  if (idToken.split(".").length !== 3) {
    throw new Error("kit/auth: malformed social recovery credential");
  }
  return {
    idToken,
    tokenFingerprint: toBase64Url(sha256(utf8ToBytes(idToken))),
    provider: socialRecoveryProvider(idToken),
  };
}

/** The provider that issued `idToken`, by its `iss` claim. */
export function socialRecoveryProvider(
  idToken: string,
): SocialRecoveryProvider {
  const issuer = readIssuer(idToken);
  if (!isSocialRecoveryIssuer(issuer)) {
    throw new Error(
      `kit/auth: no social recovery provider issues tokens for "${issuer}"`,
    );
  }
  if (issuer === "https://appleid.apple.com") return "apple";
  if (issuer.startsWith("https://securetoken.google.com/")) return "email";
  return "google";
}

/**
 * The `iss` of an unverified token.
 *
 * Deliberately no signature check. Nothing downstream trusts this value: it
 * selects which policy to ask for, and the enclave then verifies the token
 * against that policy in full.
 */
function readIssuer(idToken: string): unknown {
  const payload = idToken.split(".")[1];
  if (!payload) throw new Error("kit/auth: malformed social recovery credential");
  const padded = payload.replace(/-/g, "+").replace(/_/g, "/");
  try {
    return JSON.parse(
      Buffer.from(padded, "base64").toString("utf8"),
    )?.iss;
  } catch {
    throw new Error("kit/auth: malformed social recovery credential");
  }
}

/** Only provider-signed tokens the recovery enclave accepts. */
export function isSocialRecoveryIssuer(issuer: unknown): issuer is string {
  return (
    issuer === "https://accounts.google.com" ||
    issuer === "accounts.google.com" ||
    issuer === "https://appleid.apple.com" ||
    (typeof issuer === "string" &&
      issuer.startsWith("https://securetoken.google.com/"))
  );
}

function toBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
