/**
 * Local cache of the address the registry returned for this user on this device.
 *
 * The address lives in the Cavos registry, but the spending key lives here. This
 * cache is what keeps those two facts independent: once a device knows its
 * address it can keep signing with Cavos unreachable. It is a convenience, never
 * an authority — a cache miss on a brand-new device means asking the registry,
 * not inventing an address.
 */

const DB_NAME = "cavos-kit-addresses";
const STORE = "addresses";

export interface AddressKey {
  userId: string;
  appId: string;
  chain: string;
  network: string;
}

function keyOf(k: AddressKey): string {
  return `${k.userId}:${k.appId}:${k.chain}:${k.network}`;
}

function idbAvailable(): boolean {
  return typeof indexedDB !== "undefined";
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

/** The cached address, or null when this device has never resolved one. */
export async function readCachedAddress(key: AddressKey): Promise<string | null> {
  if (!idbAvailable()) return null;
  try {
    const value = await tx<string | undefined>("readonly", (s) => s.get(keyOf(key)));
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
}

/** Remember the resolved address. Failures are ignored — this is a cache. */
export async function writeCachedAddress(key: AddressKey, address: string): Promise<void> {
  if (!idbAvailable()) return;
  try {
    await tx("readwrite", (s) => s.put(address, keyOf(key)));
  } catch {
    /* private mode, quota, no IDB — signing still works, lookups just repeat */
  }
}
