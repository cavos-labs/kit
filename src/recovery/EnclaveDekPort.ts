import { base64UrlToBytes } from "../crypto/encoding";
import { readTokenSubject } from "./SocialRecoveryCredential";
import type { EnclaveDekPort } from "../secret/DeviceSecret";
import { parseWrappedDEK } from "../secret/wrap";
import type { SocialRecoveryClient } from "./SocialRecoveryClient";

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
          idToken: params.credential.idToken,
        });
        return row ? { address: row.wallet_address } : null;
      } catch {
        // Production still answers this GET with wallet_address only. A miss
        // is not a failed login: this device mints or uses its local wrap.
        return null;
      }
    },
    async enrollDek(params) {
      const { result } = await client.enroll({
        walletAddress: params.address,
        credential: params.credential,
        dek: params.dek,
      });
      if (result.result !== "confirmed") return { kind: "enrolled" };
      // The wallet already had a record, and the enclave has now said whether
      // it seals this DEK. A mismatch must not lock the user out of a wallet
      // this device can still spend from, but it must not pass silently either:
      // it means a lost device would not be recoverable.
      if (result.dek_matches !== true) {
        console.error(
          "[cavos] the recovery record for this wallet does not hold its key; recovery is not protecting it.",
        );
      }
      return { kind: "already-enrolled", address: params.address };
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
