import { ed25519 } from "@noble/curves/ed25519";
import { ec, hash } from "starknet";
import { starkKeyFromSeed } from "../chains/starknet/keys";
import { base64UrlToBytes, bytesToHex, bytesToUtf8, utf8ToBytes } from "../crypto/encoding";
import { zeroize, type MasterDEK } from "../secret/dek";
import { deriveSeed, parseAppSalt, type NativeChain } from "../secret/derive";

/** What a user can ask Cavos to do to their account, each one confirmed in the vault. */
export type ConsentAction = "delete_account" | "disable_recovery" | "enable_recovery";

/** A signature by the wallet's spend key over the consent message. */
export type ConsentProof = {
  chain: NativeChain;
  public_key: string;
  signature: string[];
};

export const CONSENT_PREFIX = "Cavos Consent:\n";

const ACTIONS: readonly ConsentAction[] = ["delete_account", "disable_recovery", "enable_recovery"];

/** The text the wallet signs for a server-issued challenge. */
export function consentMessage(challenge: string): string {
  return `${CONSENT_PREFIX}${challenge.length}\n${challenge}`;
}

/** Reads which action a challenge asks for. The signature is the server's to check, so only the shape is verified here. */
export function consentAction(challenge: string): ConsentAction {
  const parts = challenge.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") throw new Error("kit/consent: not a consent challenge");
  let payload: { kind?: unknown; action?: unknown };
  try {
    payload = JSON.parse(bytesToUtf8(base64UrlToBytes(parts[1])));
  } catch {
    throw new Error("kit/consent: not a consent challenge");
  }
  if (payload?.kind !== "end_user_consent" || !ACTIONS.includes(payload.action as ConsentAction)) {
    throw new Error("kit/consent: not a consent challenge");
  }
  return payload.action as ConsentAction;
}

const hex = (bytes: Uint8Array) => bytesToHex(bytes).slice(2);

/** Signs the consent message with the spend key of one chain. Zeroizes the DEK and the seed. */
export function signConsent(dek: MasterDEK, chain: NativeChain, appSalt: string, challenge: string): ConsentProof {
  const text = consentMessage(challenge);
  const seed = deriveSeed(dek, chain, parseAppSalt(appSalt));
  try {
    if (chain === "starknet") {
      const priv = starkKeyFromSeed(seed);
      const digest = hash.starknetKeccak(text).toString(16).padStart(64, "0");
      const { r, s } = ec.starkCurve.sign(digest, priv);
      return {
        chain,
        public_key: hex(ec.starkCurve.getPublicKey(priv, false)),
        signature: [`0x${r.toString(16)}`, `0x${s.toString(16)}`],
      };
    }
    return {
      chain,
      public_key: hex(ed25519.getPublicKey(seed)),
      signature: [hex(ed25519.sign(utf8ToBytes(text), seed))],
    };
  } finally {
    zeroize(seed);
    zeroize(dek);
  }
}
