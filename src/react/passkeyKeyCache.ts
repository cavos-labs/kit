import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * The enrolled passkey's public key, remembered so a chain created later needs
 * one gesture instead of two.
 *
 * An assertion carries no public key -- only a signature, from which two
 * candidates are recoverable, one real and one an artefact. Telling them apart
 * needs either a chain that already holds the approver or a second signature,
 * and a chain created before any other has neither.
 *
 * This is a cache, not a source of truth, and it cannot lie: a remembered key
 * is used only when the signature itself recovers it, and a wrong one never
 * appears among the candidates. So a stale, poisoned, or absent entry costs the
 * second gesture and nothing else. That is what makes it safe to store, unlike
 * the pending intents this replaced -- those were believed, this one is checked.
 */
const KEY = "cavos-kit:passkey-key";

function slot(userId: string): string {
  return `${KEY}:${userId}`;
}

export function rememberPasskeyKey(userId: string, pubkey: DevicePublicKey): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(
      slot(userId),
      JSON.stringify({ x: pubkey.x.toString(16), y: pubkey.y.toString(16) }),
    );
  } catch {
    /* the fallback is one more tap, not a failure */
  }
}

export function recallPasskeyKey(userId: string): DevicePublicKey | null {
  if (typeof window === "undefined") return null;
  try {
    const raw = window.localStorage.getItem(slot(userId));
    if (!raw) return null;
    const { x, y } = JSON.parse(raw) as { x?: string; y?: string };
    if (!x || !y) return null;
    return { x: BigInt(`0x${x}`), y: BigInt(`0x${y}`) };
  } catch {
    return null;
  }
}

/**
 * The remembered key, but only if this signature recovered it. Anything else --
 * a key from another passkey, a corrupted entry, nothing at all -- returns null
 * and the caller asks for the second signature.
 */
export function confirmedByCandidates(
  remembered: DevicePublicKey | null,
  candidates: DevicePublicKey[],
): DevicePublicKey | null {
  if (!remembered) return null;
  return candidates.some((c) => c.x === remembered.x && c.y === remembered.y) ? remembered : null;
}
