import { sha256 } from "@noble/hashes/sha256";
import { Buffer } from "buffer";
import { utf8ToBytes } from "../crypto/encoding";

/**
 * A fresh provider token plus its non-secret fingerprint. The fingerprint is
 * sent to the control plane to reserve a single recovery session; the token
 * itself is sent only through the attested encrypted channel.
 */
export interface SocialRecoveryCredential {
  idToken: string;
  tokenFingerprint: string;
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
  };
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
