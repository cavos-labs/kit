import { base64UrlToBytes, bytesToBase64Url } from "../crypto/encoding";

/** One passkey's encrypted copy of the DEK, and the passkey it opens with. */
export interface StoredPasskeyWrap {
  credentialId: Uint8Array;
  wrap: Uint8Array;
}

/** Where passkey wraps live. They are ciphertext: the store never sees what they protect. */
export interface PasskeyWrapStore {
  list(userId: string): Promise<StoredPasskeyWrap[]>;
  save(userId: string, entry: StoredPasskeyWrap): Promise<void>;
}

export interface HttpPasskeyWrapStoreOptions {
  baseUrl: string;
  appId: string;
  environment?: "development" | "production";
  /** The login's id_token. Read fresh on each call; these tokens expire. */
  authToken: () => string | null;
}

/** `/api/passkey-wraps` on the Cavos backend, authenticated as the end user. */
export class HttpPasskeyWrapStore implements PasskeyWrapStore {
  constructor(private readonly opts: HttpPasskeyWrapStoreOptions) {}

  async list(userId: string): Promise<StoredPasskeyWrap[]> {
    const url = new URL("/api/passkey-wraps", this.opts.baseUrl);
    url.searchParams.set("app_id", this.opts.appId);
    url.searchParams.set("user_social_id", userId);
    if (this.opts.environment) url.searchParams.set("environment", this.opts.environment);
    const res = await fetch(url, { headers: this.headers() });
    if (!res.ok) throw new Error(`passkey wraps lookup failed: ${res.status}`);
    const { wraps } = (await res.json()) as { wraps: { credential_id: string; wrapped_dek: string }[] };
    return wraps.map((row) => ({
      credentialId: base64UrlToBytes(row.credential_id),
      wrap: base64UrlToBytes(row.wrapped_dek),
    }));
  }

  async save(userId: string, entry: StoredPasskeyWrap): Promise<void> {
    const res = await fetch(new URL("/api/passkey-wraps", this.opts.baseUrl), {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        user_social_id: userId,
        credential_id: bytesToBase64Url(entry.credentialId),
        wrapped_dek: bytesToBase64Url(entry.wrap),
      }),
    });
    if (!res.ok) throw new Error(`passkey wrap save failed: ${res.status}`);
  }

  private headers(): Record<string, string> {
    const token = this.opts.authToken();
    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }
}
