import { generateDEK, sealControlSeed, openControlSeed, eciesWrapDEK } from "./envelope";
import type { DeviceUnwrapKey } from "./DeviceUnwrapKey";

/**
 * The control seed of an account that has been claimed but not yet created.
 *
 * The `G…` address IS the control key, so once the registry records it this
 * device can never mint a different one — it has to still hold that exact seed
 * when the first execute finally creates the account. The account does not
 * exist yet, so there is nowhere on-chain to put the envelope; it lives here,
 * sealed the same way, until creation writes it to the account's data entries
 * and `clearPendingControl` drops the local copy.
 *
 * Stored sealed rather than raw: the seed is wrapped to this device's P-256
 * key, so a dump of IndexedDB alone does not yield a spendable key.
 */

const DB_NAME = "cavos-kit-stellar-pending";
const STORE = "pending-control";

interface PendingRecord {
  ct: Uint8Array;
  wrap: Uint8Array;
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(mode: IDBTransactionMode, run: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  return openDb().then(
    (db) =>
      new Promise<T>((resolve, reject) => {
        const req = run(db.transaction(STORE, mode).objectStore(STORE));
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      }),
  );
}

/** Seal the control seed for `address` against this device's unwrap key. */
export async function savePendingControl(
  address: string,
  seed: Uint8Array,
  deviceKey: DeviceUnwrapKey,
): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  const dek = generateDEK();
  const record: PendingRecord = {
    ct: sealControlSeed(seed, dek),
    wrap: eciesWrapDEK(dek, deviceKey.publicKeySec1()),
  };
  try {
    await tx("readwrite", (s) => s.put(record, address));
  } catch {
    // Without this the account can still be created in THIS session; only a
    // reload before the first execute would lose the claim.
  }
}

/** Recover the seed for an account this device claimed but never created. */
export async function loadPendingControl(
  address: string,
  deviceKey: DeviceUnwrapKey,
): Promise<Uint8Array | null> {
  if (typeof indexedDB === "undefined") return null;
  try {
    const record = await tx<PendingRecord | undefined>("readonly", (s) => s.get(address));
    if (!record?.ct || !record?.wrap) return null;
    const dek = await deviceKey.unwrap(record.wrap);
    return openControlSeed(record.ct, dek);
  } catch {
    return null;
  }
}

/** Drop the local copy once the envelope is on-chain. */
export async function clearPendingControl(address: string): Promise<void> {
  if (typeof indexedDB === "undefined") return;
  try {
    await tx("readwrite", (s) => s.delete(address));
  } catch {
    /* the on-chain envelope is authoritative from here on */
  }
}
