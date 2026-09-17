import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { parseMasterDEK, zeroize } from "./dek";
import { masterDekFromPasskey, type AppSalt } from "./derive";
import type { EnclaveDekPort } from "./DeviceSecret";
import { wrapDekToSec1 } from "./wrap";

export function toPasskeyDekPort(input: {
  passkey: PasskeyPrfProvider;
  userId: string;
  appSalt: AppSalt;
  userName?: string;
}): EnclaveDekPort {
  let prf: Uint8Array | undefined;
  const getPrf = async () => {
    if (prf) return prf;
    prf = await loadPrf(input.passkey, input.userId, input.userName ?? input.userId);
    return prf;
  };
  const mint = async () => masterDekFromPasskey(await getPrf(), input.appSalt);

  return {
    async lookupDek() {
      return null;
    },
    async enrollDek() {
      return { kind: "enrolled" };
    },
    async mintDek() {
      return mint();
    },
    async wrapDekToFactor(params) {
      const dek = parseMasterDEK(await mint());
      try {
        return wrapDekToSec1(dek, params.recipientSec1);
      } finally {
        zeroize(dek);
      }
    },
  };
}

async function loadPrf(
  passkey: PasskeyPrfProvider,
  userId: string,
  userName: string,
): Promise<Uint8Array> {
  try {
    return await passkey.getSecret();
  } catch {
    const enrolled = await passkey.enroll({ userId, userName });
    if (enrolled.secret) return enrolled.secret;
    return passkey.getSecret(enrolled.credentialId);
  }
}
