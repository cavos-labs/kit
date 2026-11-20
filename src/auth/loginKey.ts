import { bytesToBase64Url, secureRandomBytes } from "../crypto/encoding";
import type { ChannelClientKey } from "../recovery/enclaveChannel";

const IDB_NAME = "cavos-kit-login";
const IDB_STORE = "login-keys";

interface StoredLoginKey {
  privateKey: CryptoKey;
  publicRaw: Uint8Array;
  verifier: string;
  enclaveRelease?: number;
}

interface StoredRelease {
  enclaveRelease: number;
  expiresAt: number;
}

const releaseRecord = (scope: string) => `enclave-release:${scope}`;

/**
 * How long `signInWith` holds. Long enough to sign in again and recover; short
 * enough that a browser is not left signing in with a release that has since
 * been turned off.
 */
const SIGN_IN_WITH_RELEASE_MS = 60 * 60_000;

/**
 * The login key: a non-extractable WebCrypto ECDH P-256 key pair kept in
 * IndexedDB, one record per scope (the app id). Every login replaces the
 * record, so the key never outlives the login it was made for.
 *
 * The hash of its public key is the login `nonce`, and it is the client key of
 * every enclave job for that login. The PKCE verifier of the login is stored
 * beside it, so whoever holds the key holds both and neither is ever readable
 * by a script. In the vault the record lives in the vault's origin; without a
 * vault it lives in the page's, which is weaker but still non-extractable.
 *
 * A login normally runs on the current enclave release. `signInWith` makes the
 * following logins run on an earlier one, for a user whose recovery record
 * that release sealed: the enclave signs email, GitHub and Telegram tokens
 * with a key of its release, and only the release that sealed a record can
 * open it.
 */
export class WebCryptoLoginKey implements ChannelClientKey {
  private constructor(
    private readonly privateKey: CryptoKey,
    private readonly publicRaw: Uint8Array,
    /** The PKCE verifier of this login; only the enclave job ever sends it. */
    readonly codeVerifier: string,
    /** The enclave release this login runs on, when it is not the current one. */
    readonly enclaveRelease?: number,
  ) {}

  /** Make a fresh login key and verifier, replacing any stored for `scope`. */
  static async create(scope: string): Promise<WebCryptoLoginKey> {
    assertAvailable();
    const pair = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const publicRaw = new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey));
    const verifier = bytesToBase64Url(secureRandomBytes(32));
    const asked = (await run("readonly", (store) => store.get(releaseRecord(scope)))) as StoredRelease | undefined;
    const enclaveRelease = asked && asked.expiresAt > Date.now() ? asked.enclaveRelease : undefined;
    const stored: StoredLoginKey = { privateKey: pair.privateKey, publicRaw, verifier, enclaveRelease };
    await run("readwrite", (store) => store.put(stored, scope));
    return new WebCryptoLoginKey(pair.privateKey, publicRaw, verifier, enclaveRelease);
  }

  /**
   * Run the logins of the next hour on `enclaveRelease`, or on the current
   * release again when it is null. The login in progress is not affected.
   */
  static async signInWith(scope: string, enclaveRelease: number | null): Promise<void> {
    if (typeof indexedDB === "undefined") return;
    if (enclaveRelease === null) await run("readwrite", (store) => store.delete(releaseRecord(scope)));
    else {
      const asked: StoredRelease = { enclaveRelease, expiresAt: Date.now() + SIGN_IN_WITH_RELEASE_MS };
      await run("readwrite", (store) => store.put(asked, releaseRecord(scope)));
    }
  }

  /** The stored login key for `scope`, or null when no login is in progress. */
  static async load(scope: string): Promise<WebCryptoLoginKey | null> {
    if (typeof indexedDB === "undefined") return null;
    const stored = (await run("readonly", (store) => store.get(scope))) as StoredLoginKey | undefined;
    return stored
      ? new WebCryptoLoginKey(stored.privateKey, stored.publicRaw, stored.verifier, stored.enclaveRelease)
      : null;
  }

  static async remove(scope: string): Promise<void> {
    if (typeof indexedDB === "undefined") return;
    await run("readwrite", (store) => store.delete(scope));
  }

  publicKeyRaw(): Uint8Array {
    return this.publicRaw;
  }

  async deriveSharedSecret(peerPublicRaw: Uint8Array): Promise<Uint8Array> {
    const peer = await crypto.subtle.importKey(
      "raw",
      peerPublicRaw as unknown as BufferSource,
      { name: "ECDH", namedCurve: "P-256" },
      false,
      [],
    );
    return new Uint8Array(await crypto.subtle.deriveBits({ name: "ECDH", public: peer }, this.privateKey, 256));
  }
}

function assertAvailable(): void {
  if (typeof indexedDB === "undefined") {
    throw new Error("kit/auth: sign-in needs IndexedDB, which this browser context does not provide");
  }
  if (typeof crypto === "undefined" || typeof crypto.subtle === "undefined" || (typeof window !== "undefined" && window.isSecureContext === false)) {
    throw new Error("kit/auth: sign-in needs WebCrypto, which needs HTTPS or http://localhost");
  }
}

async function run<T>(mode: IDBTransactionMode, request: (store: IDBObjectStore) => IDBRequest<T>): Promise<T> {
  const db = await new Promise<IDBDatabase>((resolve, reject) => {
    const open = indexedDB.open(IDB_NAME, 1);
    open.onupgradeneeded = () => open.result.createObjectStore(IDB_STORE);
    open.onsuccess = () => resolve(open.result);
    open.onerror = () => reject(open.error);
  });
  try {
    return await new Promise<T>((resolve, reject) => {
      const issued = request(db.transaction(IDB_STORE, mode).objectStore(IDB_STORE));
      issued.onsuccess = () => resolve(issued.result);
      issued.onerror = () => reject(issued.error);
    });
  } finally {
    db.close();
  }
}
