import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * The one public key two assertions agree on.
 *
 * A WebAuthn assertion carries no public key, and its signature recovers two
 * candidates — the real one and an artefact of that signature. A contract that
 * already holds the approver tells them apart, but the first chain to need the
 * passkey has no such contract to ask.
 *
 * Two signatures do. The real key is recoverable from both; the artefacts
 * differ, because each is a function of its own signature. So the key both
 * agree on is the key, and nothing had to be stored to find it.
 */
export function agreedPublicKey(
  first: DevicePublicKey[],
  second: DevicePublicKey[],
): DevicePublicKey | null {
  const common = first.filter((a) => second.some((b) => a.x === b.x && a.y === b.y));
  // Two distinct keys in common would mean the same signature pair recovered
  // twice, which is not an answer — better none than the wrong one, since a
  // wrong approver is a passkey nobody holds guarding the account.
  return common.length === 1 ? common[0]! : null;
}
