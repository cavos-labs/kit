import type { Spend } from "./policy";

export interface SpendLedger {
  spentToday(userId: string, asset: string): Promise<bigint>;
  record(userId: string, spends: Spend[]): Promise<void>;
}

const IDB_NAME = "cavos-vault";
const IDB_STORE = "spent";

function dayKey(userId: string, asset: string, now: Date): string {
  return `${userId}:${asset}:${now.toISOString().slice(0, 10)}`;
}

export function memoryLedger(now: () => Date = () => new Date()): SpendLedger {
  const spent = new Map<string, bigint>();
  return {
    async spentToday(userId, asset) {
      return spent.get(dayKey(userId, asset, now())) ?? 0n;
    },
    async record(userId, spends) {
      for (const { asset, amount } of spends) {
        const key = dayKey(userId, asset, now());
        spent.set(key, (spent.get(key) ?? 0n) + amount);
      }
    },
  };
}

export function idbLedger(): SpendLedger {
  if (typeof indexedDB === "undefined") return memoryLedger();
  return {
    async spentToday(userId, asset) {
      const raw = await run<string | undefined>("readonly", (s) => s.get(dayKey(userId, asset, new Date())));
      return raw ? BigInt(raw) : 0n;
    },
    async record(userId, spends) {
      for (const { asset, amount } of spends) await add(dayKey(userId, asset, new Date()), amount);
    },
  };
}

/** Read and write in one transaction, so two records cannot both start from the same total. */
function add(key: string, amount: bigint): Promise<void> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(IDB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(IDB_STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const tx = db.transaction(IDB_STORE, "readwrite");
      const store = tx.objectStore(IDB_STORE);
      const read = store.get(key);
      read.onsuccess = () => {
        const current = read.result ? BigInt(read.result as string) : 0n;
        store.put((current + amount).toString(), key);
      };
      tx.oncomplete = () => {
        db.close();
        resolve();
      };
      tx.onerror = () => {
        db.close();
        reject(tx.error);
      };
    };
  });
}

function run<T>(mode: IDBTransactionMode, op: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(IDB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(IDB_STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const req = op(db.transaction(IDB_STORE, mode).objectStore(IDB_STORE));
      req.onsuccess = () => {
        db.close();
        resolve(req.result as T);
      };
      req.onerror = () => {
        db.close();
        reject(req.error);
      };
    };
  });
}
