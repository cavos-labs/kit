import { hash, num } from "starknet";
import type { AuthProvider, Identity } from "./AuthProvider";
import {
  createSocialRecoveryCredential,
  isSocialRecoveryIssuer,
  type SocialRecoveryCredential,
} from "../recovery/SocialRecoveryCredential";

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
 * The fresh provider token is retained only in memory. Its SHA-256 fingerprint
 * reserves exactly one Confidential Space recovery session while the token
 * itself is sent only through the attested encrypted channel.
 */
export class CavosAuth implements AuthProvider {
  private readonly backendUrl: string;
  private readonly identityStorageKey: string;
  /** Most recent nonce sent to the backend (for the pending OAuth/OTP request). */
  private pendingNonce: string | null = null;
  private last: Identity | null = null;
  /** Fresh OIDC proof retained only in memory for an immediate TEE recovery.
   * Never persisted to localStorage and never sent to the Cavos control plane
   * outside the attested encrypted channel. */
  private recoveryCredential: SocialRecoveryCredential | null = null;

  constructor(private readonly opts: CavosAuthOptions = {}) {
    this.backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    this.identityStorageKey = `cavos-kit:identity:${opts.appId ?? "default"}`;
  }

  /**
   * Restore the last confirmed identity for this app on this browser. This is
   * deliberately only public profile data — never an OAuth token or private
   * key. The device signer remains protected in IndexedDB/WebCrypto.
   */
  restoreIdentity(): Identity | null {
    if (typeof window === "undefined") return null;
    try {
      const value = window.localStorage.getItem(this.identityStorageKey);
      if (!value) return null;
      const identity = JSON.parse(value) as Identity;
      if (!identity.userId || typeof identity.userId !== "string") return null;
      this.last = identity;
      return identity;
    } catch {
      return null;
    }
  }

  /** Clear the persisted identity on an explicit user logout. */
  clearStoredIdentity(): void {
    this.last = null;
    this.recoveryCredential = null;
    if (typeof window !== "undefined") {
      window.localStorage.removeItem(this.identityStorageKey);
    }
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
    const { url } = await this.get(`/api/oauth/v2/${provider}?${params}`);
    return url;
  }

  /**
   * Resolve identity from an OAuth callback. Current callbacks carry only a
   * short-lived one-time code; legacy raw auth data remains readable so apps can
   * roll forward without losing an already-open callback.
   */
  async handleCallback(authDataOrSearch: string, redirectUri?: string): Promise<Identity> {
    const callbackCode = extractCallbackCode(authDataOrSearch);
    if (callbackCode) {
      const callbackRedirectUri = redirectUri ?? currentCleanCallbackUrl();
      if (!callbackRedirectUri) throw new Error("kit/auth: callback redirect URI is required");
      const result = await this.post("/api/oauth/callback/exchange", {
        code: callbackCode,
        app_id: this.opts.appId,
        redirect_uri: callbackRedirectUri,
      });
      return this.identityFromAuthData(JSON.stringify(result), "oauth");
    }
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
    await this.post("/api/oauth/v2/firebase/magic-link", {
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

  /**
   * Return the fresh social credential required by Confidential Space.
   * Callers should use it immediately; it is intentionally not restorable
   * after a refresh. A new social login is required for each recovery attempt.
   */
  getSocialRecoveryCredential(): SocialRecoveryCredential {
    if (!this.recoveryCredential) {
      throw new Error("kit/auth: complete a fresh social login before recovery");
    }
    return this.recoveryCredential;
  }

  /**
   * Take the fresh social credential exactly once. A provider token is bound to
   * one enclave session, so retaining it after recovery only permits accidental
   * replay attempts during the wallet's post-recovery reconnect.
   */
  consumeSocialRecoveryCredential(): SocialRecoveryCredential {
    const credential = this.getSocialRecoveryCredential();
    this.recoveryCredential = null;
    return credential;
  }

  /**
   * Accept a provider id_token obtained by the host's own authentication.
   *
   * Apps that sign users in themselves already hold a Google or Apple token;
   * this lets social recovery use it instead of sending the user through a
   * second sign-in. Nothing here grants trust: the token is checked inside the
   * enclave against the issuer and audience sealed for the app, and only Google
   * or Apple can produce a token that passes.
   *
   * Rejected up front if it was not issued by a provider the enclave accepts,
   * so a mistake surfaces here rather than as an opaque enclave failure.
   *
   * The token must be recent — the enclave requires the authentication to be
   * within five minutes — so pass one straight from a sign-in, not a stored one.
   */
  useExternalSocialRecoveryToken(idToken: string): void {
    const claims = parseJwt(idToken);
    if (!isSocialRecoveryIssuer(claims?.iss)) {
      throw new Error(
        `kit/auth: id_token issuer ${JSON.stringify(claims?.iss ?? null)} cannot be used for social recovery. ` +
          "Pass the raw Google or Apple id_token from your login, not your own session JWT.",
      );
    }
    this.recoveryCredential = createSocialRecoveryCredential(idToken);
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
    this.recoveryCredential = isSocialRecoveryIssuer(claims.iss)
      ? createSocialRecoveryCredential(token)
      : null;
    return this.remember({
      userId: String(claims.sub ?? claims.user_id ?? claims.uid),
      email: claims.email ?? emailOverride,
      // Standard OIDC `name` — present on Google's id_token, absent on the
      // Cavos-signed Firebase JWT (email/OTP/magic-link) and Apple's token.
      name: claims.name,
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
    if (typeof window !== "undefined") {
      window.localStorage.setItem(this.identityStorageKey, JSON.stringify(id));
    }
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

function extractCallbackCode(input: string): string | null {
  if (/^[A-Za-z0-9_-]{43}$/.test(input)) return input;
  try {
    const params = input.includes('://')
      ? new URL(input).searchParams
      : new URLSearchParams(input.startsWith('?') ? input : `?${input}`);
    return params.get('cavos_auth_code');
  } catch {
    return null;
  }
}

function currentCleanCallbackUrl(): string | null {
  if (typeof window === 'undefined') return null;
  const url = new URL(window.location.href);
  url.searchParams.delete('cavos_auth_code');
  url.searchParams.delete('auth_data');
  url.searchParams.delete('zk_auth_data');
  return url.toString();
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
