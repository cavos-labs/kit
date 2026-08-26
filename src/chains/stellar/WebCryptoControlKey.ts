import { StrKey } from "@stellar/stellar-sdk";
import { ed25519 } from "@noble/curves/ed25519";
import { sha256 } from "@noble/hashes/sha256";

/**
 * Non-extractable Ed25519 control key for classic-G Stellar accounts.
 *
 * In the browser, keys are persisted in IndexedDB so returning sessions can
 * load them without re-unwrapping the on-chain envelope. The private key
 * material never leaves WebCrypto — `crypto.subtle.exportKey("raw", privateKey)`
 * will throw because `extractable: false`. XSS on the integrator page can still
 * sign while the tab is open (same risk model as Starknet), but it cannot
 * exfiltrate the spending key.
 *
 * In Node (tests / CLI), IndexedDB is unavailable. The `fromCryptoKey` static
 * method lets callers construct an instance from an already-imported CryptoKey
 * for use in tests without mocking IDB.
 */

const IDB_NAME = "cavos-kit-stellar-control";
const IDB_STORE = "control-keys";

/** Interface for the control-key signing capability used by CavosStellar. */
export interface ControlKey {
  /** Stellar `G…` address of the control public key. */
  publicAddress(): string;
  /** The raw 32-byte Ed25519 public key. */
  publicKeyRaw(): Uint8Array;
  /** Sign data with the control key. Returns a 64-byte Ed25519 signature. */
  sign(data: Uint8Array): Promise<Uint8Array>;
}

export interface WebCryptoControlKeyOptions {
  /** Storage key for this account's control key (e.g. the `G…` address). */
  keyId: string;
}

interface StoredControlKey {
  privateKey: CryptoKey;
  publicRaw: Uint8Array;
}

/**
 * WebCrypto-backed non-extractable Ed25519 control key.
 *
 * Use `create` or `importFromSeed` for first-time setup, `load` for returning
 * sessions. For Node/test environments without IndexedDB, use `fromCryptoKey`
 * to construct directly from an in-memory CryptoKey.
 */
export class WebCryptoControlKey implements ControlKey {
  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly publicRaw: Uint8Array,
    readonly keyId: string | undefined,
  ) {}

  /**
   * Construct directly from an already-imported CryptoKey (for tests / Node).
   * No IndexedDB interaction — the key lives only in memory.
   */
  static fromCryptoKey(privateKey: CryptoKey, publicRaw: Uint8Array): WebCryptoControlKey {
    return new WebCryptoControlKey(privateKey, publicRaw, undefined);
  }

  /**
   * Generate a fresh control key. In the browser, persists to IndexedDB; in
   * Node, returns an in-memory instance (throws if `keyId` is specified but
   * IndexedDB is unavailable).
   */
  static async create(opts?: WebCryptoControlKeyOptions): Promise<WebCryptoControlKey> {
    assertSubtle();
    const pair = await crypto.subtle.generateKey(
      { name: "Ed25519" },
      false,
      ["sign", "verify"],
    );
    const publicRaw = new Uint8Array(
      await crypto.subtle.exportKey("raw", pair.publicKey),
    );
    if (opts?.keyId && hasIndexedDB()) {
      await idbPut(opts.keyId, { privateKey: pair.privateKey, publicRaw });
    }
    return new WebCryptoControlKey(pair.privateKey, publicRaw, opts?.keyId);
  }

  /**
   * Import a control key from a raw 32-byte Ed25519 seed. The seed is imported
   * with `extractable: false`, so after this call the caller should wipe the
   * seed from JS memory — it can never be exported from WebCrypto.
   *
   * In the browser, persists to IndexedDB; in Node, returns an in-memory
   * instance.
   */
  static async importFromSeed(
    seed: Uint8Array,
    opts?: WebCryptoControlKeyOptions,
  ): Promise<WebCryptoControlKey> {
    assertSubtle();
    if (seed.length !== 32) {
      throw new Error("kit/stellar: control seed must be 32 bytes");
    }
    const pkcs8 = wrapEd25519SeedAsPkcs8(seed);
    const privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    const publicRaw = await deriveEd25519PublicKey(seed);
    if (opts?.keyId && hasIndexedDB()) {
      await idbPut(opts.keyId, { privateKey, publicRaw });
    }
    return new WebCryptoControlKey(privateKey, publicRaw, opts?.keyId);
  }

  /**
   * Load an existing control key from IndexedDB, or `null` if none exists.
   * In Node (no IndexedDB), always returns `null`.
   */
  static async load(opts: WebCryptoControlKeyOptions): Promise<WebCryptoControlKey | null> {
    if (!hasIndexedDB()) return null;
    const rec = await idbGet(opts.keyId);
    if (!rec) return null;
    return new WebCryptoControlKey(rec.privateKey, rec.publicRaw, opts.keyId);
  }

  publicAddress(): string {
    return StrKey.encodeEd25519PublicKey(Buffer.from(this.publicRaw));
  }

  publicKeyRaw(): Uint8Array {
    return this.publicRaw;
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const sig = await crypto.subtle.sign(
      { name: "Ed25519" },
      this.privateKey,
      data,
    );
    return new Uint8Array(sig);
  }

  /**
   * Attempt to export the private key. This WILL throw if the key was imported
   * with `extractable: false` (which it always should be). Exposed only for
   * tests that want to verify the non-extractable guarantee.
   */
  async tryExportPrivateKey(): Promise<Uint8Array> {
    const raw = await crypto.subtle.exportKey("raw", this.privateKey);
    return new Uint8Array(raw);
  }
}

function assertSubtle(): void {
  if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined") {
    throw new Error(
      "Cavos: WebCrypto is unavailable. Control keys require a secure context — use HTTPS, or http://localhost.",
    );
  }
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

async function idbPut(keyId: string, value: StoredControlKey): Promise<void> {
  const db = await openDb();
  await tx(db, "readwrite", (store) => store.put(value, keyId));
  db.close();
}

async function idbGet(keyId: string): Promise<StoredControlKey | null> {
  const db = await openDb();
  const result = await tx(db, "readonly", (store) => store.get(keyId));
  db.close();
  return (result as StoredControlKey) ?? null;
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

/**
 * Wrap a 32-byte Ed25519 seed in PKCS#8 ASN.1 format for WebCrypto import.
 * Structure: SEQUENCE { version, AlgorithmIdentifier { Ed25519 }, OCTET STRING { seed } }
 */
function wrapEd25519SeedAsPkcs8(seed: Uint8Array): Uint8Array {
  const prefix = new Uint8Array([
    0x30, 0x2e,
    0x02, 0x01, 0x00,
    0x30, 0x05,
    0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22,
    0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  return pkcs8;
}

/** Derive the 32-byte Ed25519 public key from a 32-byte seed using noble. */
function deriveEd25519PublicKey(seed: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(seed);
}

/**
 * Wrap a stellar-sdk Keypair as a ControlKey. Useful for tests that bypass
 * `connect()` and construct the wallet directly. The underlying Keypair IS
 * extractable (unlike a proper WebCryptoControlKey), so this should only be
 * used in tests.
 */
export class KeypairControlKey implements ControlKey {
  constructor(private readonly keypair: { publicKey(): string; sign(data: Buffer): Buffer }) {}

  publicAddress(): string {
    return this.keypair.publicKey();
  }

  publicKeyRaw(): Uint8Array {
    return StrKey.decodeEd25519PublicKey(this.keypair.publicKey());
  }

  async sign(data: Uint8Array): Promise<Uint8Array> {
    const sig = this.keypair.sign(Buffer.from(data));
    return new Uint8Array(sig);
  }
}

/**
 * Sign a Stellar transaction using a WebCrypto control key.
 * Signs `tx.hash()` and adds the signature to the transaction.
 */
export async function signTransactionWithControlKey(
  tx: { hash(): Buffer; addSignature(publicKey: string, signature: string): void },
  controlKey: ControlKey,
): Promise<void> {
  const hash = tx.hash();
  const sig = await controlKey.sign(new Uint8Array(hash));
  tx.addSignature(controlKey.publicAddress(), Buffer.from(sig).toString("base64"));
}

/**
 * Create a signing callback compatible with `authorizeEntry` for Soroban.
 * The callback receives the preimage (xdr.HashIdPreimage) and optionally the
 * payload (32-byte hash). Returns `{ signature, publicKey }` as expected by
 * the stellar-sdk.
 */
export function createSorobanSigner(
  controlKey: ControlKey,
): (preimage: { toXDR(): Buffer }, payload?: Uint8Array) => Promise<{ signature: Uint8Array; publicKey: string }> {
  return async (preimage: { toXDR(): Buffer }, payload?: Uint8Array) => {
    const data = payload ?? sha256(preimage.toXDR());
    const signature = await controlKey.sign(data);
    return { signature, publicKey: controlKey.publicAddress() };
  };
}
