import { hkdf } from "@noble/hashes/hkdf";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha256 } from "@noble/hashes/sha256";
import { utf8ToBytes } from "../../crypto/encoding";
import { WebCryptoControlKey } from "./WebCryptoControlKey";

const PASSKEY_INFO = "cavos-stellar-ed25519-passkey-v1";
const RECOVERY_INFO = "cavos-stellar-ed25519-recovery-v1";
const RECOVERY_SALT = "cavos-stellar-recovery-signer-v1";
const RECOVERY_PBKDF2_ITERATIONS = 210_000;

export function passkeySignerSeed(prfOutput: Uint8Array): Uint8Array {
  if (prfOutput.length < 32) throw new Error("kit/stellar: passkey PRF output too short");
  return hkdf(sha256, prfOutput, undefined, PASSKEY_INFO, 32);
}

export function recoverySignerSeed(code: string): Uint8Array {
  const normalised = code.trim().replace(/\s+/g, " ").toLowerCase();
  if (!normalised) throw new Error("kit/stellar: recovery code is empty");
  const stretched = pbkdf2(sha256, utf8ToBytes(normalised), utf8ToBytes(RECOVERY_SALT), {
    c: RECOVERY_PBKDF2_ITERATIONS,
    dkLen: 32,
  });
  return hkdf(sha256, stretched, undefined, RECOVERY_INFO, 32);
}

export async function importPasskeySigner(prfOutput: Uint8Array): Promise<WebCryptoControlKey> {
  const seed = passkeySignerSeed(prfOutput);
  try {
    return await WebCryptoControlKey.importFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}

export async function importRecoverySigner(code: string): Promise<WebCryptoControlKey> {
  const seed = recoverySignerSeed(code);
  try {
    return await WebCryptoControlKey.importFromSeed(seed);
  } finally {
    seed.fill(0);
  }
}
