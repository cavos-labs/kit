import type { PasskeyWrapStore } from "../registry/PasskeyWrapStore";
import type { PasskeyEnrollParams, PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { zeroize, type MasterDEK } from "./dek";
import { NO_WRAP_SOURCE, type EnclaveDekPort } from "./DeviceSecret";
import { unwrapDek, wrapDek, type WrapOwner } from "./passkeyWrap";

export const PASSKEY_DOES_NOT_OPEN = "kit/secret: this passkey does not hold this wallet's key";

export interface PasskeyRecovery {
  passkey: PasskeyPrfProvider;
  wraps: PasskeyWrapStore;
  owner: WrapOwner;
}

/**
 * A passkey restores an account; it never creates one. A new account gets a
 * random DEK like any other, and each passkey the user adds stores a copy of
 * it encrypted under its PRF.
 */
export function toPasskeyDekPort(input: PasskeyRecovery): EnclaveDekPort {
  return {
    async lookupDek() {
      return null;
    },
    async enrollDek() {
      return { kind: "enrolled" };
    },
    async restoreDek() {
      const stored = await input.wraps.list(input.owner.userId);
      // No passkey was ever added: do not ask for one.
      if (stored.length === 0) throw new Error(NO_WRAP_SOURCE);
      const prf = await passkeySecret(input.passkey, stored.length === 1 ? stored[0].credentialId : undefined);
      try {
        // With several passkeys, the one that opens is the one the user chose.
        for (const { wrap } of stored) {
          try {
            return unwrapDek(wrap, prf, input.owner);
          } catch {
            // Sealed under another passkey.
          }
        }
        throw new Error(PASSKEY_DOES_NOT_OPEN);
      } finally {
        zeroize(prf);
      }
    },
    async wrapDekToFactor() {
      throw new Error(PASSKEY_DOES_NOT_OPEN);
    },
  };
}

/** Create a passkey and store the DEK encrypted under it. */
export async function addPasskey(
  input: PasskeyRecovery & { dek: MasterDEK; user: PasskeyEnrollParams },
): Promise<void> {
  const enrolled = await input.passkey.enroll(input.user);
  // Many authenticators create the credential without evaluating the PRF.
  const prf = enrolled.secret ?? (await input.passkey.getSecret(enrolled.credentialId));
  try {
    await input.wraps.save(input.owner.userId, {
      credentialId: enrolled.credentialId,
      wrap: wrapDek(input.dek, prf, input.owner),
    });
  } finally {
    zeroize(prf);
  }
}

async function passkeySecret(passkey: PasskeyPrfProvider, credentialId?: Uint8Array): Promise<Uint8Array> {
  try {
    return await passkey.getSecret(credentialId);
  } catch (error) {
    // Declining leaves the device signed in without the key, like a login with no passkey.
    if (isDeclined(error)) throw new Error(NO_WRAP_SOURCE);
    throw error;
  }
}

function isDeclined(error: unknown): boolean {
  if (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "NotAllowedError") {
    return true;
  }
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("cancelled");
}
