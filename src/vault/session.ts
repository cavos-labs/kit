/**
 * The vault's record that a user signed in. A wallet's keys only open while
 * one is live, so a user id alone opens nothing and signing out locks them.
 *
 * It lives in the vault's own storage, which the embedding page cannot read
 * or write. Each use moves `expiresAt` forward; `endsAt` never moves.
 */
export interface SessionStore {
  /** Start a session for `key`, replacing any earlier one. */
  open(key: string): Promise<void>;
  /** Whether `key` has a live session. A live one is extended. */
  renew(key: string): Promise<boolean>;
  end(key: string): Promise<void>;
}

interface StoredSession {
  expiresAt: number;
  endsAt: number;
}

const DAY_MS = 24 * 60 * 60_000;
/** A session lasts this long after it was last used. */
export const SESSION_IDLE_MS = 7 * DAY_MS;
/** However often it is used, a session ends this long after sign-in. */
export const SESSION_MAX_MS = 30 * DAY_MS;

const IDB_NAME = "cavos-vault-session";
const IDB_STORE = "sessions";

interface Records {
  get(key: string): Promise<StoredSession | undefined>;
  put(key: string, session: StoredSession): Promise<void>;
  delete(key: string): Promise<void>;
}

function sessionStore(records: Records, now: () => number): SessionStore {
  return {
    async open(key) {
      const started = now();
      await records.put(key, { expiresAt: started + SESSION_IDLE_MS, endsAt: started + SESSION_MAX_MS });
    },
    async renew(key) {
      const session = await records.get(key);
      if (!session) return false;
      const current = now();
      if (current >= session.expiresAt || current >= session.endsAt) {
        await records.delete(key);
        return false;
      }
      await records.put(key, { expiresAt: Math.min(current + SESSION_IDLE_MS, session.endsAt), endsAt: session.endsAt });
      return true;
    },
    end: (key) => records.delete(key),
  };
}

export function memorySessions(now: () => number = Date.now): SessionStore {
  const sessions = new Map<string, StoredSession>();
  return sessionStore(
    {
      get: async (key) => sessions.get(key),
      put: async (key, session) => void sessions.set(key, session),
      delete: async (key) => void sessions.delete(key),
    },
    now,
  );
}

export function idbSessions(): SessionStore {
  if (typeof indexedDB === "undefined") return memorySessions();
  return sessionStore(
    {
      get: (key) => run<StoredSession | undefined>("readonly", (store) => store.get(key)),
      put: (key, session) => run<unknown>("readwrite", (store) => store.put(session, key)).then(() => undefined),
      delete: (key) => run<unknown>("readwrite", (store) => store.delete(key)).then(() => undefined),
    },
    Date.now,
  );
}

function run<T>(mode: IDBTransactionMode, op: (store: IDBObjectStore) => IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    const open = indexedDB.open(IDB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(IDB_STORE);
    open.onerror = () => reject(open.error);
    open.onsuccess = () => {
      const db = open.result;
      const request = op(db.transaction(IDB_STORE, mode).objectStore(IDB_STORE));
      request.onsuccess = () => {
        db.close();
        resolve(request.result as T);
      };
      request.onerror = () => {
        db.close();
        reject(request.error);
      };
    };
  });
}
