import { base64UrlToBytes } from "../crypto/encoding";
import { readTokenSubject } from "./SocialRecoveryCredential";
import type { EnclaveDekPort } from "../secret/DeviceSecret";
import { parseWrappedDEK } from "../secret/wrap";
import type { SocialRecoveryClient } from "./SocialRecoveryClient";

function parseAlreadyEnrolledAddress(error: unknown, fallback: string): string | null {
  if (!(error instanceof Error)) return null;
  if (!error.message.includes("already_enrolled")) return null;
  const json = error.message.match(/\{[\s\S]*\}$/);
  if (!json) return fallback;
  try {
    const body = JSON.parse(json[0]) as { wallet_address?: unknown };
    return typeof body.wallet_address === "string" && body.wallet_address
      ? body.wallet_address
      : fallback;
  } catch {
    return fallback;
  }
}

export function toEnclaveDekPort(
  client: Pick<SocialRecoveryClient, "enroll" | "recover" | "lookupDekEnrollment">,
): EnclaveDekPort {
  return {
    async lookupDek(params) {
      const subject = readTokenSubject(params.credential.idToken);
      try {
        const row = await client.lookupDekEnrollment({
          provider: params.credential.provider,
          subject,
        });
        return row ? { address: row.wallet_address } : null;
      } catch {
        // Production still answers this GET with wallet_address only. A miss
        // is not a failed login: this device mints or uses its local wrap.
        return null;
      }
    },
    async enrollDek(params) {
      try {
        const { result } = await client.enroll({
          walletAddress: params.address,
          credential: params.credential,
          dek: params.dek,
        });
        if (result.already_enrolled) {
          const address =
            typeof result.wallet_address === "string" && result.wallet_address
              ? result.wallet_address
              : params.address;
          return { kind: "already-enrolled", address };
        }
        return { kind: "enrolled" };
      } catch (error) {
        const address = parseAlreadyEnrolledAddress(error, params.address);
        if (address) return { kind: "already-enrolled", address };
        throw error;
      }
    },
    async wrapDekToFactor(params) {
      const { result } = await client.recover({
        walletAddress: params.address,
        credential: params.credential,
        authorizations: [],
        recipientPublicSec1: params.recipientSec1,
      });
      const wrapped = result.stellar_device_wrap_b64;
      if (typeof wrapped !== "string" || !wrapped) {
        throw new Error("kit/secret: enclave returned no device wrap");
      }
      return parseWrappedDEK(base64UrlToBytes(wrapped));
    },
  };
}
