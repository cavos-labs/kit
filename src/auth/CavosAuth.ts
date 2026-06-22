import { hash, num } from "starknet";
import type { AuthProvider, Identity } from "./AuthProvider";

export interface CavosAuthOptions {
  /** Cavos backend base URL. Defaults to the hosted service (same as @cavos/react). */
  backendUrl?: string;
  /** App identifier registered with Cavos (the `appId` from the dashboard). */
  appId?: string;
}

/**
 * Hosted login (Privy-like) backed by the Cavos backend — same endpoints
 * `@cavos/react` uses (Google / Apple OAuth + Firebase email OTP). Login only
 * resolves a stable `userId` (the OAuth `sub` claim); it never touches signing.
 * Feed the returned `Identity` to `Cavos.connect`.
 *
 *   const auth = new CavosAuth({ appId });
 *   // social: open the returned URL; user returns, then:
 *   const identity = await auth.handleCallback(window.location.search);
 *   // or email OTP:
 *   await auth.sendOtp(email); const identity = await auth.verifyOtp(email, code);
 *   const cavos = await Cavos.connect({ network, appSalt, identity, paymasterApiKey });
 *
 * Device-signer model note: the backend issues a Cavos JWT (the same one react
 * uses for on-chain RSA verification). Here we only need the stable `sub` claim
 * from it — the RSA/JWKS/nonce machinery react relies on is dead weight for the
 * device model, because the device key (not the JWT) authorizes on-chain calls.
 * We still send a `nonce` (Poseidon over random bytes) since the backend expects
 * it on the request; the value itself is irrelevant to us.
 */
export class CavosAuth implements AuthProvider {
  private readonly backendUrl: string;
  /** Most recent nonce sent to the backend (for the pending OAuth/OTP request). */
  private pendingNonce: string | null = null;
  private last: Identity | null = null;

  constructor(private readonly opts: CavosAuthOptions = {}) {
    this.backendUrl = opts.backendUrl ?? "https://cavos.xyz";
  }

  /** Redirect URL for Google login (open it; user returns to your redirectUri). */
  async getGoogleOAuthUrl(redirectUri?: string): Promise<string> {
    return this.oauthUrl("google", redirectUri);
  }

  /** Redirect URL for Apple login. */
  async getAppleOAuthUrl(redirectUri?: string): Promise<string> {
    return this.oauthUrl("apple", redirectUri);
  }

  private async oauthUrl(provider: "google" | "apple", redirectUri?: string): Promise<string> {
    if (typeof window === "undefined") throw new Error("kit/auth: OAuth requires a browser");
    const params = new URLSearchParams({
      nonce: this.freshNonce(),
      redirect_uri: redirectUri ?? window.location.href,
      ...(this.opts.appId ? { app_id: this.opts.appId } : {}),
    });
    const { url } = await this.get(`/api/oauth/${provider}?${params}`);
    return url;
  }

  /**
   * Resolve the identity from an OAuth callback. The auth data is carried in the
   * `auth_data` (or `zk_auth_data`) query param on return. We only extract `sub`.
   */
  async handleCallback(authDataOrSearch: string): Promise<Identity> {
    const authData = extractAuthData(authDataOrSearch);
    return this.identityFromAuthData(authData, "oauth");
  }

  /** Send a one-time code to an email (Firebase OTP). */
  async sendOtp(email: string): Promise<void> {
    await this.post("/api/oauth/firebase/otp/request", {
      email,
      nonce: this.freshNonce(),
      ...(this.opts.appId ? { app_id: this.opts.appId } : {}),
    });
  }

  /** Send a passwordless magic-link sign-in email (Firebase). */
  async sendMagicLink(email: string): Promise<void> {
    await this.post("/api/oauth/firebase/magic-link", {
      email,
      nonce: this.freshNonce(),
      ...(this.opts.appId ? { app_id: this.opts.appId } : {}),
      ...(typeof window !== "undefined" ? { redirect_uri: window.location.href } : {}),
    });
  }

  /** Verify the OTP and resolve the identity. */
  async verifyOtp(email: string, code: string): Promise<Identity> {
    const res = await this.post("/api/oauth/firebase/otp/verify", {
      email,
      code,
      nonce: this.consumeNonce(),
      ...(this.opts.appId ? { app_id: this.opts.appId } : {}),
    });
    return this.identityFromAuthData(res.id_token ?? res.jwt ?? res.token ?? JSON.stringify(res), "otp", email);
  }

  /** AuthProvider: returns the identity resolved by the last login step. */
  async authenticate(): Promise<Identity> {
    if (!this.last) throw new Error("kit/auth: no identity yet — complete a login first");
    return this.last;
  }

  // ── internals ──────────────────────────────────────────────────────────────

  /**
   * Build an `Identity` from whatever the backend returned. The Cavos backend
   * wraps the user id in a JWT (its `sub` claim); for the device model we only
   * need that stable id — the signature is never checked on-chain.
   */
  private async identityFromAuthData(
    authData: string,
    provider: string,
    emailOverride?: string,
  ): Promise<Identity> {
    let token = authData;
    try {
      const parsed = JSON.parse(authData);
      token = parsed.id_token ?? parsed.jwt ?? parsed.token ?? authData;
    } catch {
      // raw JWT
    }
    const claims = parseJwt(token);
    return this.remember({
      userId: String(claims.sub ?? claims.user_id ?? claims.uid),
      email: claims.email ?? emailOverride,
      provider: claims.firebase?.sign_in_provider ?? claims.provider ?? provider,
    });
  }

  /** Generate (and remember) the nonce the Cavos backend expects on requests. */
  private freshNonce(): string {
    // 31-byte random felt; matches the shape the backend validates, value is
    // irrelevant to the device-signer model.
    const bytes = crypto.getRandomValues(new Uint8Array(31));
    const h = hash.computePoseidonHashOnElements([bytesToChunks(bytes)]);
    this.pendingNonce = num.toHex(h);
    return this.pendingNonce;
  }

  /** Return the pending nonce (for the verify step), clearing it. */
  private consumeNonce(): string {
    if (!this.pendingNonce) return this.freshNonce();
    const n = this.pendingNonce;
    this.pendingNonce = null;
    return n;
  }

  private remember(id: Identity): Identity {
    this.last = id;
    return id;
  }

  private async get(path: string): Promise<any> {
    const r = await fetch(`${this.backendUrl}${path}`);
    if (!r.ok) throw new Error(`kit/auth: ${path} -> ${r.status} ${await r.text()}`);
    return r.json();
  }

  private async post(path: string, body: unknown): Promise<any> {
    const r = await fetch(`${this.backendUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!r.ok) throw new Error(`kit/auth: ${path} -> ${r.status} ${await r.text()}`);
    return r.json();
  }
}

/** Pull the `auth_data` / `zk_auth_data` value out of a callback string. */
function extractAuthData(input: string): string {
  if (input.includes("auth_data=") || input.includes("zk_auth_data=")) {
    const params = new URLSearchParams(input.startsWith("?") ? input : `?${input}`);
    return params.get("auth_data") ?? params.get("zk_auth_data") ?? input;
  }
  return input;
}

/** Decode a JWT payload (no verification — the backend already validated it). */
function parseJwt(jwt: string): any {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("kit/auth: malformed JWT");
  const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(json);
}

/** Pack a byte array into the felt252 chunks Poseidon hashes over. */
function bytesToChunks(bytes: Uint8Array): bigint {
  let w = 0n;
  for (const b of bytes.subarray(0, 31)) w = (w << 8n) | BigInt(b);
  return w;
}
