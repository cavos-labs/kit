import { sha256 } from "@noble/hashes/sha256";
import type { DeviceSigner, DevicePublicKey, DeviceSignature } from "./DeviceSigner";
import { bytesToBigInt } from "../crypto/encoding";
import { recoverYParity } from "../crypto/signature";

const IDB_NAME = "cavos-kit";
const IDB_STORE = "device-keys";

export interface WebCryptoSignerOptions {
  /**
   * Storage key for the device's private key (e.g. the account address). One
   * silent key per (this value, browser profile).
   */
  keyId: string;
}

interface StoredKey {
  privateKey: CryptoKey; // non-extractable; structured-cloneable
  x: bigint;
  y: bigint;
}

/**
 * Silent, device-bound signer for the browser. Generates a non-extractable
 * secp256r1 (P-256) key via WebCrypto and stores the `CryptoKey` in IndexedDB.
 * The private key is never exposed to JS and signing produces NO UI — there is
 * no passkey, no Face ID / Touch ID prompt. To the user it is invisible; they
 * only ever see the OAuth / email login used to derive their address.
 */
export class WebCryptoSigner implements DeviceSigner {
  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly publicKey: DevicePublicKey,
    readonly keyId: string,
  ) {}

  /** Create a fresh device key (first run on this device) and persist it. */
  static async create(opts: WebCryptoSignerOptions): Promise<WebCryptoSigner> {
    assertSecureContext();
    const pair = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      false, // private key is NON-extractable
      ["sign", "verify"],
    );
    const publicKey = await exportPublicKey(pair.publicKey);
    await idbPut(opts.keyId, { privateKey: pair.privateKey, x: publicKey.x, y: publicKey.y });
    return new WebCryptoSigner(pair.privateKey, publicKey, opts.keyId);
  }

  /** Load an existing device key from storage, or null if none exists yet. */
  static async load(opts: WebCryptoSignerOptions): Promise<WebCryptoSigner | null> {
    const rec = await idbGet(opts.keyId);
    if (!rec) return null;
    return new WebCryptoSigner(rec.privateKey, { x: rec.x, y: rec.y }, opts.keyId);
  }

  /** Load the device key, creating one on first use. */
  static async loadOrCreate(opts: WebCryptoSignerOptions): Promise<WebCryptoSigner> {
    return (await WebCryptoSigner.load(opts)) ?? (await WebCryptoSigner.create(opts));
  }

  async getPublicKey(): Promise<DevicePublicKey> {
    return this.publicKey;
  }

  async sign(txHash: Uint8Array): Promise<DeviceSignature> {
    // WebCrypto ECDSA hashes the message with SHA-256 internally, then signs.
    const raw = new Uint8Array(
      await crypto.subtle.sign(
        { name: "ECDSA", hash: "SHA-256" },
        this.privateKey,
        txHash as unknown as BufferSource,
      ),
    );
    // IEEE P1363 form: r || s, 32 bytes each.
    const r = bytesToBigInt(raw.subarray(0, 32));
    const s = bytesToBigInt(raw.subarray(32, 64));
    const digest = sha256(txHash);
    const yParity = recoverYParity(r, s, digest, this.publicKey);
    return { r, s, yParity };
  }
}

async function exportPublicKey(publicKey: CryptoKey): Promise<DevicePublicKey> {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", publicKey)); // 0x04 || X || Y
  return { x: bytesToBigInt(raw.subarray(1, 33)), y: bytesToBigInt(raw.subarray(33, 65)) };
}

/**
 * WebCrypto (`crypto.subtle`) is only available in secure contexts — HTTPS, or
 * `http://localhost`. Accessing the dev server over a LAN IP (e.g.
 * http://192.168.1.24:3000) is NOT secure, so `crypto.subtle` is undefined and
 * device-key generation would crash with a cryptic "undefined is not an object".
 * Fail early with an actionable message instead.
 */
function assertSecureContext(): void {
  const ok =
    typeof crypto !== "undefined" &&
    typeof crypto.subtle !== "undefined" &&
    (typeof window === "undefined" || window.isSecureContext);
  if (!ok) {
    throw new Error(
      "Cavos: WebCrypto is unavailable. Device keys require a secure context — use HTTPS, or http://localhost. " +
        "(For LAN/mobile dev testing, run `next dev --experimental-https`.)",
    );
  }
}

// --- minimal IndexedDB wrapper ---

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut(keyId: string, value: StoredKey): Promise<void> {
  const db = await openDb();
  await tx(db, "readwrite", (store) => store.put(value, keyId));
  db.close();
}

async function idbGet(keyId: string): Promise<StoredKey | null> {
  const db = await openDb();
  const result = await tx(db, "readonly", (store) => store.get(keyId));
  db.close();
  return (result as StoredKey) ?? null;
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
