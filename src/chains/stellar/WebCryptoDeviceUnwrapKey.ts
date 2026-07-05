import { p256 } from "@noble/curves/p256";
import { eciesKEKFromX, unwrapDEK } from "./envelope";
import { deviceSlotId, type DeviceUnwrapKey } from "./DeviceUnwrapKey";

// A dedicated database (not WebCryptoSigner's "cavos-kit") so the two never
// collide on IndexedDB version numbers.
const IDB_NAME = "cavos-kit-stellar";
const IDB_STORE = "unwrap-keys";

export interface WebCryptoUnwrapKeyOptions {
  /** Storage key for this device's unwrap key (e.g. `${userId}:${appSalt}`). One
   *  ECDH key per (this value, browser profile). */
  keyId: string;
}

interface StoredUnwrapKey {
  privateKey: CryptoKey; // non-extractable ECDH key; structured-cloneable
  publicRaw: Uint8Array; // SEC1 uncompressed (65 bytes)
}

/**
 * Browser `DeviceUnwrapKey`: a non-extractable P-256 **ECDH** key generated with
 * WebCrypto and persisted in IndexedDB. Distinct from `WebCryptoSigner` (an ECDSA
 * signing key) — a signing key can't do ECDH, so the classic-G envelope needs its
 * own key here. The private key never leaves WebCrypto: the account DEK is
 * unwrapped via `deriveBits` (raw ECDH), then AES-GCM in `@noble` on the derived
 * KEK. Per-device, non-syncable → losing the device loses only this convenience
 * factor, never the account (the passkey / recovery factors survive).
 */
export class WebCryptoDeviceUnwrapKey implements DeviceUnwrapKey {
  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly publicRaw: Uint8Array,
    readonly keyId: string,
  ) {}

  /** Create a fresh device unwrap key and persist it. */
  static async create(opts: WebCryptoUnwrapKeyOptions): Promise<WebCryptoDeviceUnwrapKey> {
    assertSecureContext();
    const pair = await crypto.subtle.generateKey(
      { name: "ECDH", namedCurve: "P-256" },
      false, // private key is NON-extractable
      ["deriveBits"],
    );
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)); // 65 bytes
    await idbPut(opts.keyId, { privateKey: pair.privateKey, publicRaw });
    return new WebCryptoDeviceUnwrapKey(pair.privateKey, publicRaw, opts.keyId);
  }

  /** Load an existing device unwrap key, or null if none exists yet. */
  static async load(opts: WebCryptoUnwrapKeyOptions): Promise<WebCryptoDeviceUnwrapKey | null> {
    const rec = await idbGet(opts.keyId);
    if (!rec) return null;
    return new WebCryptoDeviceUnwrapKey(rec.privateKey, rec.publicRaw, opts.keyId);
  }

  /** Load the device unwrap key, creating one on first use. */
  static async loadOrCreate(opts: WebCryptoUnwrapKeyOptions): Promise<WebCryptoDeviceUnwrapKey> {
    return (await WebCryptoDeviceUnwrapKey.load(opts)) ?? (await WebCryptoDeviceUnwrapKey.create(opts));
  }

  publicKeySec1(): Uint8Array {
    return this.publicRaw;
  }

  slotId(): string {
    return deviceSlotId(this.publicRaw);
  }

  async unwrap(blob: Uint8Array): Promise<Uint8Array> {
    const ephPubCompressed = blob.subarray(0, 33);
    const wrapped = blob.subarray(33);

    // WebCrypto only imports uncompressed points → decompress the ephemeral pubkey.
    const ephUncompressed = p256.ProjectivePoint.fromHex(ephPubCompressed).toRawBytes(false);
    const ephKey = await crypto.subtle.importKey(
      "raw",
      ephUncompressed as unknown as BufferSource,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    const sharedX = new Uint8Array(
      await crypto.subtle.deriveBits({ name: "ECDH", public: ephKey }, this.privateKey, 256),
    );
    const kek = eciesKEKFromX(sharedX, ephPubCompressed);
    return unwrapDEK(wrapped, kek);
  }
}

function assertSecureContext(): void {
  const ok =
    typeof crypto !== "undefined" &&
    typeof crypto.subtle !== "undefined" &&
    (typeof window === "undefined" || window.isSecureContext);
  if (!ok) {
    throw new Error(
      "Cavos: WebCrypto is unavailable. Device keys require a secure context — use HTTPS, or http://localhost.",
    );
  }
}

// --- minimal IndexedDB wrapper (mirrors WebCryptoSigner, separate store) ---

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(keyId: string, value: StoredUnwrapKey): Promise<void> {
  const db = await openDb();
  await tx(db, "readwrite", (store) => store.put(value, keyId));
  db.close();
}

async function idbGet(keyId: string): Promise<StoredUnwrapKey | null> {
  const db = await openDb();
  const result = await tx(db, "readonly", (store) => store.get(keyId));
  db.close();
  return (result as StoredUnwrapKey) ?? null;
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
