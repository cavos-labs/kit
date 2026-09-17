import { parseWrappedDEK, type WrappedDEK } from "./wrap";
import type { WrapStore } from "./DeviceSecret";

const IDB_NAME = "cavos-kit-dek-wrap";
const IDB_STORE = "wraps";

export function idbWrapStore(): WrapStore {
  return {
    async get(userId) {
      if (!hasIndexedDB()) return null;
      const raw = await idbGet(userId);
      return raw ? parseWrappedDEK(raw) : null;
    },
    async put(userId, wrap) {
      if (!hasIndexedDB()) return;
      await idbPut(userId, wrap);
    },
    async clear(userId) {
      if (!hasIndexedDB()) return;
      await idbDel(userId);
    },
  };
}

function hasIndexedDB(): boolean {
  return typeof indexedDB !== "undefined";
}

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function tx<T>(
  db: IDBDatabase,
  mode: IDBTransactionMode,
  run: (store: IDBObjectStore) => IDBRequest<T>,
): Promise<T> {
  return new Promise((resolve, reject) => {
    const store = db.transaction(IDB_STORE, mode).objectStore(IDB_STORE);
    const req = run(store);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbGet(userId: string): Promise<Uint8Array | null> {
  const db = await openDb();
  const result = await tx(db, "readonly", (store) => store.get(userId));
  db.close();
  return (result as Uint8Array) ?? null;
}

async function idbPut(userId: string, wrap: WrappedDEK): Promise<void> {
  const db = await openDb();
  await tx(db, "readwrite", (store) => store.put(wrap, userId));
  db.close();
}

async function idbDel(userId: string): Promise<void> {
  const db = await openDb();
  await tx(db, "readwrite", (store) => store.delete(userId));
  db.close();
}
