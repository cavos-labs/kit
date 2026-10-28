import type { AuthProvider, Identity } from "./AuthProvider";
import {
  createSocialRecoveryCredential,
  ENCLAVE_EMAIL_ISSUER,
  ENCLAVE_GITHUB_ISSUER,
  isSocialRecoveryIssuer,
  type SocialRecoveryCredential,
} from "../recovery/SocialRecoveryCredential";
import type { AttestationPolicy } from "../recovery/SocialRecoveryClient";
import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "../recovery/attestationDefaults";
import { fetchEnclaveRelease, runEnclaveJob, verifiedChannelKey } from "../recovery/enclaveChannel";
import { secureRandomBytes } from "../crypto/encoding";
import { normalizeEmailCode } from "./emailCode";
import {
  assertLoginBinding,
  loginNonce,
  loginSecretFrom,
  requiresLoginBinding,
} from "./loginBinding";

export interface CavosAuthOptions {
  /** Cavos backend base URL. Defaults to the hosted service (same as @cavos/react). */
  backendUrl?: string;
  /** App identifier registered with Cavos (the `appId` from the dashboard). */
  appId?: string;
  /**
   * `false` keeps the signed-in identity in `sessionStorage`: it survives a
   * reload and the OAuth redirect, and ends when the tab closes. Any identity
   * already in `localStorage` is removed. Defaults to `true` (`localStorage`,
   * signed in across tabs and restarts).
   */
  persistSession?: boolean;
  /**
   * The enclave measurements email login verifies before it sends a code to
   * the enclave. Defaults to the enclave shipped with this package.
   */
  attestation?: AttestationPolicy;
}

/**
 * Hosted login (Privy-like) backed by the Cavos backend — same endpoints
 * `@cavos/react` uses for Google / Apple OAuth, plus an email code the recovery
 * enclave generates and verifies itself, and GitHub, which has no id_token of
 * its own: the enclave verifies the GitHub grant and signs one. Login only
 * resolves a stable `userId` (the OAuth `sub` claim); it never touches signing.
 * Feed the returned `Identity` to `Cavos.connect`.
 *
 *   const auth = new CavosAuth({ appId });
 *   // social: open the returned URL; user returns, then:
 *   const identity = await auth.handleCallback(window.location.search);
 *   // GitHub: the same, from getGitHubOAuthUrl
 *   // or email OTP:
 *   await auth.sendOtp(email); const identity = await auth.verifyOtp(email, code);
 *   const cavos = await Cavos.connect({ network, appSalt, identity, paymasterApiKey });
 *
 * Device-signer model note: the backend issues a Cavos JWT (the same one react
 * uses for on-chain RSA verification). Here we only need the stable `sub` claim
 * from it — the RSA/JWKS/nonce machinery react relies on is dead weight for the
 * device model, because the device key (not the JWT) authorizes on-chain calls.
 * The provider token is kept in `sessionStorage` so a reconnect can still
 * authenticate to the wallet registry. The separate social-recovery credential
 * is NOT: it stays in memory, its SHA-256 fingerprint reserves exactly one
 * enclave session, and the token itself travels only through the attested
 * encrypted channel.
 */
export class CavosAuth implements AuthProvider {
  private readonly backendUrl: string;
  private readonly identityStorageKey: string;
  private readonly authTokenKey: string;
  private readonly loginSecretKey: string;
  private readonly pkceKey: string;
  /** The login secret, for a callback this same instance handles. */
  private loginSecret: string | null = null;
  /** The PKCE verifier of the GitHub login in flight, for a callback this same instance handles. */
  private pkceVerifier: string | null = null;
  private last: Identity | null = null;
  /** Fresh OIDC proof retained only in memory for an immediate TEE recovery.
   * Never persisted to localStorage and never sent to the Cavos control plane
   * outside the attested encrypted channel. */
  private recoveryCredential: SocialRecoveryCredential | null = null;
  /**
   * The raw provider token from this session's login.
   *
   * Held in `sessionStorage`, not memory alone. The wallet registry
   * authenticates with it, and `resolveAddress` fails closed rather than mint a
   * second wallet for a user who already has one — so a token that does not
   * survive a reload takes every reconnect down with it, and a device with no
   * cached address can never connect at all.
   *
   * `sessionStorage` and not `localStorage`: it dies with the tab, is not shared
   * across tabs, and never reaches another origin. The token is already inside
   * this page's JavaScript either way; what changes is that it now outlives a
   * navigation, which is exactly what the reconnect needs.
   */
  private authTokenValue: string | null = null;

  constructor(private readonly opts: CavosAuthOptions = {}) {
    this.backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    this.identityStorageKey = `cavos-kit:identity:${opts.appId ?? "default"}`;
    this.authTokenKey = `cavos-kit:token:${opts.appId ?? "default"}`;
    this.loginSecretKey = `cavos-kit:login-secret:${opts.appId ?? "default"}`;
    this.pkceKey = `cavos-kit:pkce:${opts.appId ?? "default"}`;
    if (opts.persistSession === false && typeof window !== "undefined") {
      // An identity saved before the app turned persistence off would
      // otherwise keep this browser signed in for good.
      try {
        window.localStorage.removeItem(this.identityStorageKey);
      } catch {
        /* nothing was stored if storage is unavailable */
      }
    }
  }

  /**
   * Where the identity lives. Resolved on use, not in the constructor, because
   * the provider also builds this during SSR, where there is no `window`.
   */
  private identityStorage(): Storage {
    return this.opts.persistSession === false ? window.sessionStorage : window.localStorage;
  }

  /**
   * Restore the last confirmed identity for this app on this browser. This is
   * deliberately only public profile data — never an OAuth token or private
   * key. The device signer remains protected in IndexedDB/WebCrypto.
   */
  restoreIdentity(): Identity | null {
    if (typeof window === "undefined") return null;
    try {
      const value = this.identityStorage().getItem(this.identityStorageKey);
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
    this.setAuthToken(null);
    if (typeof window !== "undefined") {
      try {
        this.identityStorage().removeItem(this.identityStorageKey);
      } catch {
        /* nothing was stored if storage is unavailable */
      }
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

  /**
   * Redirect URL for GitHub login.
   *
   * GitHub issues no id_token, so the enclave verifies the sign-in and signs
   * one itself. The URL is built by the backend, and a code issued without our
   * PKCE challenge could be redeemed without this browser, so a URL that does
   * not carry the challenge this login made is refused here.
   */
  async getGitHubOAuthUrl(redirectUri?: string): Promise<string> {
    if (typeof window === "undefined") throw new Error("kit/auth: OAuth requires a browser");
    const appId = this.requireAppId();
    this.startLogin();
    const verifier = this.startPkce();
    const challenge = loginNonce(verifier);
    const params = new URLSearchParams({
      code_challenge: challenge,
      redirect_uri: redirectUri ?? window.location.href,
      app_id: appId,
    });
    const { url } = await this.get(`/api/oauth/v2/github?${params}`);
    if (!isGitHubAuthorizeUrl(url, challenge)) {
      throw new Error("kit/auth: the GitHub sign-in URL is not the one this login asked for");
    }
    return url;
  }

  private async oauthUrl(provider: "google" | "apple", redirectUri?: string): Promise<string> {
    if (typeof window === "undefined") throw new Error("kit/auth: OAuth requires a browser");
    const params = new URLSearchParams({
      nonce: this.startLogin(),
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
      if (typeof result.github_grant === "string") {
        return this.githubIdentity(result.github_grant);
      }
      return this.identityFromAuthData(JSON.stringify(result), "oauth");
    }
    const authData = extractAuthData(authDataOrSearch);
    return this.identityFromAuthData(authData, "oauth");
  }

  /**
   * Email a 9-character sign-in code. The code is generated and mailed by the
   * recovery enclave, so the Cavos control plane never sees it.
   */
  async sendOtp(email: string): Promise<void> {
    await this.enclavePost("/api/oauth/email/code", {
      app_id: this.requireAppId(),
      email: normalizeEmail(email),
    });
  }

  /**
   * Verify the emailed code inside the attested enclave and resolve the
   * identity. The enclave answers with its own signed token, bound to a secret
   * created here, and that token is used exactly like a Google id_token.
   */
  async verifyOtp(email: string, code: string): Promise<Identity> {
    const address = normalizeEmail(email);
    const secret = loginSecretFrom(secureRandomBytes(32));
    const idToken = await this.enclaveLogin(
      {
        action: "verify_email",
        email: address,
        code: normalizeEmailCode(code),
        client_nonce: loginNonce(secret),
      },
      "/api/oauth/email/verify",
      {},
      "email_verified",
      "kit/auth: the enclave did not verify this email",
    );
    if (parseJwt(idToken).iss !== ENCLAVE_EMAIL_ISSUER) {
      throw new Error("kit/auth: the email token was not issued by the enclave");
    }
    return this.identityFromAuthData(idToken, "email", address, secret);
  }

  /**
   * Redeem a GitHub grant inside the attested enclave. The grant is only
   * useful with the PKCE verifier and login secret this browser kept, and the
   * token the enclave signs is bound to that secret exactly like a Google one.
   */
  private async githubIdentity(githubGrant: string): Promise<Identity> {
    const secret = this.takeLoginSecret();
    const verifier = this.takePkceVerifier();
    if (!secret || !verifier) {
      throw new Error(
        "kit/auth: this sign-in did not start here, or the browser could not keep its state. Sign in again.",
      );
    }
    const idToken = await this.enclaveLogin(
      { action: "verify_github", code_verifier: verifier, client_nonce: loginNonce(secret) },
      "/api/oauth/github/verify",
      { github_grant: githubGrant },
      "github_verified",
      "kit/auth: the enclave did not verify this GitHub sign-in",
    );
    if (parseJwt(idToken).iss !== ENCLAVE_GITHUB_ISSUER) {
      throw new Error("kit/auth: the GitHub token was not issued by the enclave");
    }
    return this.identityFromAuthData(idToken, "github", undefined, secret);
  }

  /**
   * Open an attested enclave session, run one encrypted login job through it
   * and return the id_token the enclave signed.
   */
  private async enclaveLogin(
    job: Record<string, unknown>,
    verifyPath: string,
    extraBody: Record<string, unknown>,
    expectedResult: string,
    failure: string,
  ): Promise<string> {
    const session = await this.enclavePost("/api/oauth/email/session", { app_id: this.requireAppId() });
    const sessionId: unknown = session?.session_id;
    if (typeof sessionId !== "string") {
      throw new Error("kit/auth: the enclave session carried no id");
    }
    const channelKey = await verifiedChannelKey(
      sessionId,
      session.attestation_document_b64,
      this.opts.attestation ?? DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
      (pcr0Hex) => fetchEnclaveRelease(`${this.backendUrl}/api/enclave/releases/${pcr0Hex}`),
    );
    const result = await runEnclaveJob<{ result?: string; id_token?: unknown }>(
      sessionId,
      channelKey,
      job,
      (sealed) => this.enclavePost(verifyPath, { session_id: sessionId, job: sealed, ...extraBody }),
    );
    if (result.result !== expectedResult || typeof result.id_token !== "string") {
      throw new Error(failure);
    }
    return result.id_token;
  }

  /** AuthProvider: returns the identity resolved by the last login step. */
  async authenticate(): Promise<Identity> {
    if (!this.last) throw new Error("kit/auth: no identity yet — complete a login first");
    return this.last;
  }

  /**
   * Return the fresh social credential the recovery enclave requires.
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
  /**
   * Whether a login proof is available without taking it.
   *
   * The UI has to choose how a device gets authorized before anything runs, and
   * that choice depends on whether the enclave can be used at all. Asking with
   * `consume` would spend the proof to find out.
   */
  hasSocialRecoveryCredential(): boolean {
    return this.recoveryCredential !== null;
  }

  consumeSocialRecoveryCredential(): SocialRecoveryCredential {
    // Kept for the session rather than dropped on first use. A session holds a
    // wallet on every configured chain and each needs its own enrolment, so
    // spending the credential on the first one left the rest unprotected —
    // with no error, because there was simply nothing left to try with.
    //
    // Replay is the control plane's to refuse, and it does: one session per
    // credential per wallet. It cannot be reused against a wallet it has
    // already enrolled.
    return this.getSocialRecoveryCredential();
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
    presentedSecret?: string,
  ): Promise<Identity> {
    let token = authData;
    try {
      const parsed = JSON.parse(authData);
      token = parsed.id_token ?? parsed.jwt ?? parsed.token ?? authData;
    } catch {
      // raw JWT
    }
    const claims = parseJwt(token);
    let loginSecret: string | undefined;
    if (requiresLoginBinding(claims.iss)) {
      const kept = presentedSecret ?? this.takeLoginSecret();
      assertLoginBinding(claims.nonce, kept);
      loginSecret = kept;
    }
    this.setAuthToken(token);
    this.recoveryCredential = isSocialRecoveryIssuer(claims.iss)
      ? createSocialRecoveryCredential(token, loginSecret)
      : null;
    return this.remember({
      userId: String(claims.sub ?? claims.user_id ?? claims.uid),
      email: claims.email ?? emailOverride,
      name: claims.name,
      provider: providerFromClaims(claims, provider),
    });
  }

  /**
   * The provider id_token from this session's login, for the wallet registry.
   * Null on a page reload that restored the identity from storage but not
   * the token — the address cache covers that device; a brand-new device has
   * just logged in and therefore has one.
   */
  getAuthToken(): string | null {
    if (this.authTokenValue) return this.authTokenValue;
    try {
      this.authTokenValue = window.sessionStorage.getItem(this.authTokenKey);
    } catch {
      // No session storage (private mode, blocked): memory only, as before.
    }
    return this.authTokenValue;
  }

  private setAuthToken(token: string | null): void {
    this.authTokenValue = token;
    if (typeof window === "undefined") return;
    try {
      if (token) window.sessionStorage.setItem(this.authTokenKey, token);
      else window.sessionStorage.removeItem(this.authTokenKey);
    } catch {
      /* memory-only fallback; a reconnect will 401 as it did before */
    }
  }

  /**
   * Begin a Google or Apple login: keep a fresh secret for the trip to the
   * provider and back, and return the nonce that commits to it.
   *
   * `sessionStorage` because the login navigates away and the secret has to be
   * here when the callback lands; it is removed as soon as it is read. Where
   * storage is unavailable only this instance remembers it, so a login that
   * reloads the page is refused at the callback — the safe outcome.
   */
  private startLogin(): string {
    const secret = loginSecretFrom(secureRandomBytes(32));
    this.loginSecret = secret;
    try {
      window.sessionStorage.setItem(this.loginSecretKey, secret);
    } catch {
      /* memory only */
    }
    return loginNonce(secret);
  }

  /** Begin the PKCE half of a GitHub login: keep a fresh verifier and return it. */
  private startPkce(): string {
    const verifier = loginSecretFrom(secureRandomBytes(32));
    try {
      window.sessionStorage.setItem(this.pkceKey, verifier);
    } catch {
      this.pkceVerifier = verifier;
    }
    return verifier;
  }

  /** The PKCE verifier of the login in flight, taken exactly once. */
  private takePkceVerifier(): string | null {
    const kept = this.pkceVerifier;
    this.pkceVerifier = null;
    try {
      const stored = window.sessionStorage.getItem(this.pkceKey);
      window.sessionStorage.removeItem(this.pkceKey);
      return stored ?? kept;
    } catch {
      return kept;
    }
  }

  /** The secret of the login in flight, taken exactly once. */
  private takeLoginSecret(): string | null {
    let secret = this.loginSecret;
    this.loginSecret = null;
    try {
      secret = window.sessionStorage.getItem(this.loginSecretKey) ?? secret;
      window.sessionStorage.removeItem(this.loginSecretKey);
    } catch {
      /* memory only */
    }
    return secret;
  }

  private remember(id: Identity): Identity {
    this.last = id;
    if (typeof window !== "undefined") {
      try {
        this.identityStorage().setItem(this.identityStorageKey, JSON.stringify(id));
      } catch {
        // Private mode and blocked site data throw here. This store only saves
        // a returning user from signing in again; an unwritable one must not
        // take down the login that just succeeded.
      }
    }
    return id;
  }

  private async get(path: string): Promise<any> {
    const r = await fetch(`${this.backendUrl}${path}`);
    if (!r.ok) throw new Error(`kit/auth: ${path} -> ${r.status} ${await r.text()}`);
    return r.json();
  }

  private requireAppId(): string {
    if (!this.opts.appId) throw new Error("kit/auth: this sign-in needs an appId");
    return this.opts.appId;
  }

  private async enclavePost(path: string, body: unknown): Promise<any> {
    const r = await fetch(`${this.backendUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (r.ok) return r.json();
    const text = await r.text().catch(() => "");
    let code: unknown;
    try {
      code = JSON.parse(text)?.error;
    } catch {
      code = undefined;
    }
    const known = typeof code === "string" ? ENCLAVE_LOGIN_ERRORS[code] : undefined;
    throw new Error(known ?? `kit/auth: ${path} -> ${r.status} ${text}`);
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

const ENCLAVE_LOGIN_ERRORS: Record<string, string> = {
  invalid_request: "Enter a valid email address.",
  app_not_found: "kit/auth: this app is not registered with Cavos.",
  email_undeliverable: "This email provider is not supported yet.",
  code_cooldown: "A code was just sent to this address. Wait a minute before requesting another.",
  rate_limited: "Too many attempts. Try again in a few minutes.",
  email_unavailable: "Email sign-in is unavailable right now. Try again later.",
  enclave_unavailable: "Sign-in is unavailable right now. Try again later.",
  code_rejected: "That code is wrong or has expired. Request a new one.",
  github_rejected: "GitHub did not accept this sign-in. Try again.",
  invalid_grant: "This GitHub sign-in expired. Sign in again.",
};

/** Whether `url` is GitHub's authorize page, asked for with exactly this PKCE challenge. */
function isGitHubAuthorizeUrl(url: unknown, challenge: string): boolean {
  if (typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      parsed.host === "github.com" &&
      parsed.pathname === "/login/oauth/authorize" &&
      parsed.searchParams.get("code_challenge") === challenge &&
      parsed.searchParams.get("code_challenge_method") === "S256"
    );
  } catch {
    return false;
  }
}

function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
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
/**
 * Which provider actually signed this token.
 *
 * A raw Google or Apple id_token carries no `provider` claim, so the OAuth
 * path would fall through to the literal "oauth" — true, and useless to
 * anything that wants to name the provider back to the user. The issuer is the
 * authoritative answer and is always there.
 */
function providerFromClaims(claims: any, fallback: string): string {
  switch (claims?.iss) {
    case "https://accounts.google.com":
      return "google";
    case "https://appleid.apple.com":
      return "apple";
    case ENCLAVE_EMAIL_ISSUER:
      return "email";
    case ENCLAVE_GITHUB_ISSUER:
      return "github";
    default:
      return claims?.provider ?? fallback;
  }
}

function parseJwt(jwt: string): any {
  const part = jwt.split(".")[1];
  if (!part) throw new Error("kit/auth: malformed JWT");
  const json = atob(part.replace(/-/g, "+").replace(/_/g, "/"));
  return JSON.parse(json);
}
