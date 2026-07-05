import { chunkTo64, unchunk } from "./envelope";

/**
 * On-chain layout of the control-key envelope in the account's classic
 * `MANAGE_DATA` entries. Stellar caps both the data-entry *key* and *value* at 64
 * bytes, so every logical blob is split into ≤64-byte chunks written under
 * ordered, indexed keys. Enumerating the account's data entries (returned whole
 * by Horizon) is enough to reconstruct the envelope — no separate index needed,
 * which keeps the account self-describing and backend-free.
 *
 * Keys (all under the `cv:` namespace):
 *   cv:ct/<i>        sealed control seed (DEK-encrypted)
 *   cv:wd:<slot>/<i> device ECIES DEK-wrap, one <slot> per device
 *   cv:wp/<i>        passkey-PRF DEK-wrap (recovery / new-device anchor)
 *   cv:wr/<i>        recovery-code DEK-wrap (optional)
 *   cv:v             single-byte envelope version
 */

export const CT_BASE = "cv:ct";
export const PASSKEY_BASE = "cv:wp";
export const RECOVERY_BASE = "cv:wr";
export const VERSION_KEY = "cv:v";
export const ENVELOPE_VERSION = 1;

/** `cv:wd:<slot>` base key for a device envelope slot. */
export function deviceBase(slot: string): string {
  return `cv:wd:${slot}`;
}

/** In-memory shape of the account's control-key envelope. */
export interface AccountEnvelope {
  /** Sealed control seed (`sealControlSeed` output). */
  ct: Uint8Array;
  /** Per-device ECIES DEK-wraps, keyed by device slot id. */
  deviceWraps: Record<string, Uint8Array>;
  /** Passkey-PRF DEK-wrap, if a passkey factor is enrolled. */
  passkeyWrap?: Uint8Array;
  /** Recovery-code DEK-wrap, if the user set one up. */
  recoveryWrap?: Uint8Array;
}

/** Serialize an envelope into `MANAGE_DATA` name→value entries (raw bytes). */
export function toDataEntries(env: AccountEnvelope): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  writeChunked(out, CT_BASE, env.ct);
  for (const [slot, blob] of Object.entries(env.deviceWraps)) {
    writeChunked(out, deviceBase(slot), blob);
  }
  if (env.passkeyWrap) writeChunked(out, PASSKEY_BASE, env.passkeyWrap);
  if (env.recoveryWrap) writeChunked(out, RECOVERY_BASE, env.recoveryWrap);
  out[VERSION_KEY] = Uint8Array.of(ENVELOPE_VERSION);
  return out;
}

/** Reconstruct an envelope from an account's data entries (name→bytes). */
export function fromDataEntries(entries: Record<string, Uint8Array>): AccountEnvelope {
  const ct = readChunked(entries, CT_BASE);
  if (!ct) throw new Error("kit/stellar: account has no control-seed ciphertext (cv:ct)");

  const deviceWraps: Record<string, Uint8Array> = {};
  const seenSlots = new Set<string>();
  for (const key of Object.keys(entries)) {
    const m = key.match(/^cv:wd:([^/]+)\/\d+$/);
    if (m) seenSlots.add(m[1]);
  }
  for (const slot of seenSlots) {
    const blob = readChunked(entries, deviceBase(slot));
    if (blob) deviceWraps[slot] = blob;
  }

  return {
    ct,
    deviceWraps,
    passkeyWrap: readChunked(entries, PASSKEY_BASE),
    recoveryWrap: readChunked(entries, RECOVERY_BASE),
  };
}

/** Just the `MANAGE_DATA` entries for one device slot — used when re-wrapping the
 *  DEK for a newly approved device (a single classic tx, no full re-write). */
export function deviceWrapEntries(slot: string, blob: Uint8Array): Record<string, Uint8Array> {
  const out: Record<string, Uint8Array> = {};
  writeChunked(out, deviceBase(slot), blob);
  return out;
}

function writeChunked(out: Record<string, Uint8Array>, base: string, blob: Uint8Array): void {
  const chunks = chunkTo64(blob);
  chunks.forEach((chunk, i) => {
    out[`${base}/${i}`] = chunk;
  });
}

function readChunked(entries: Record<string, Uint8Array>, base: string): Uint8Array | undefined {
  const chunks: Uint8Array[] = [];
  for (let i = 0; ; i++) {
    const chunk = entries[`${base}/${i}`];
    if (!chunk) break;
    chunks.push(chunk);
  }
  return chunks.length ? unchunk(chunks) : undefined;
}
