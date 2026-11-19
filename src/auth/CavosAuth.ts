import type { AuthProvider, Identity } from "./AuthProvider";
import {
  createSocialRecoveryCredential,
  ENCLAVE_EMAIL_ISSUER,
  ENCLAVE_GITHUB_ISSUER,
  ENCLAVE_TELEGRAM_ISSUER,
  isSocialRecoveryIssuer,
  type SocialRecoveryCredential,
} from "../recovery/SocialRecoveryCredential";
import type { AttestationPolicy } from "../recovery/SocialRecoveryClient";
import { enclavePost } from "./enclaveLogin";
import { createLoginHost, type LoginHost, type LoginStart } from "./LoginHost";
import { assertLoginBinding, LOGIN_NOT_STARTED, requiresLoginBinding } from "./loginBinding";

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
  /**
   * Where the login key lives and where the enclave login jobs run. Defaults to
   * this page's IndexedDB. `CavosProvider` passes the vault's, so that no
   * script on the page can hold the key or the PKCE verifier.
   */
  login?: LoginHost;
}

/**
 * Hosted login (Privy-like) backed by the Cavos backend — same endpoints
 * `@cavos/react` uses for Google / Apple OAuth, plus an email code the recovery
 * enclave generates and verifies itself, and GitHub, which has no id_token of
 * its own: the enclave verifies the GitHub grant and signs one, as it does
 * for Telegram. Login only resolves a stable `userId` (the OAuth `sub` claim);
 * it never touches signing.
 * Feed the returned `Identity` to `Cavos.connect`.
 *
 *   const auth = new CavosAuth({ appId });
 *   // social: open the returned URL; user returns, then:
 *   const identity = await auth.handleCallback(window.location.search);
 *   // GitHub: the same, from getGitHubOAuthUrl; Telegram: from getTelegramOAuthUrl
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
  private readonly loginNonceKey: string;
  private readonly login: LoginHost;
  /** The public nonce of the login in flight, for a callback this same instance handles. */
  private loginNonce: string | null = null;
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
    this.loginNonceKey = `cavos-kit:login-nonce:${opts.appId ?? "default"}`;
    this.login =
      opts.login ??
      createLoginHost({
        appId: opts.appId ?? "default",
        backendUrl: this.backendUrl,
        attestation: opts.attestation,
      });
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
    this.loginNonce = null;
    this.login.end().catch(() => undefined);
    if (typeof window !== "undefined") {
      try {
        window.sessionStorage.removeItem(this.loginNonceKey);
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
    const { codeChallenge } = await this.startLogin();
    const params = new URLSearchParams({
      code_challenge: codeChallenge,
      redirect_uri: redirectUri ?? window.location.href,
      app_id: appId,
    });
    const { url } = await this.get(`/api/oauth/v2/github?${params}`);
    if (!isGitHubAuthorizeUrl(url, codeChallenge)) {
      throw new Error("kit/auth: the GitHub sign-in URL is not the one this login asked for");
    }
    return url;
  }

  /**
   * Redirect URL for Telegram login.
   *
   * Telegram issues an id_token the enclave re-signs after verifying the
   * sign-in. The backend builds the URL, and the challenge, nonce and scope are
   * what bind the code to this browser and app, so a URL that does not carry
   * exactly what this login asked for is refused here.
   */
  async getTelegramOAuthUrl(redirectUri?: string): Promise<string> {
    if (typeof window === "undefined") throw new Error("kit/auth: OAuth requires a browser");
    const appId = this.requireAppId();
    const { nonce, codeChallenge } = await this.startLogin();
    const params = new URLSearchParams({
      code_challenge: codeChallenge,
      redirect_uri: redirectUri ?? window.location.href,
      app_id: appId,
      nonce,
    });
    const { url } = await this.get(`/api/oauth/v2/telegram?${params}`);
    if (!isTelegramAuthorizeUrl(url, codeChallenge, `${appId}.${nonce}`)) {
      throw new Error("kit/auth: the Telegram sign-in URL is not the one this login asked for");
    }
    return url;
  }

  private async oauthUrl(provider: "google" | "apple", redirectUri?: string): Promise<string> {
    if (typeof window === "undefined") throw new Error("kit/auth: OAuth requires a browser");
    const { nonce } = await this.startLogin();
    const params = new URLSearchParams({
      nonce,
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
      if (typeof result.telegram_grant === "string") {
        return this.telegramIdentity(result.telegram_grant);
      }
      return this.identityFromAuthData(JSON.stringify(result), "oauth");
    }
    const authData = extractAuthData(authDataOrSearch);
    return this.identityFromAuthData(authData, "oauth");
  }

  /**
   * Email a 9-character sign-in code. The code is generated and mailed by the
   * recovery enclave, so the Cavos control plane never sees it. It is bound to
   * a new login key: asking for another code starts another login, and only
   * the latest code can be verified.
   */
  async sendOtp(email: string): Promise<void> {
    const appId = this.requireAppId();
    const { nonce } = await this.startLogin();
    await enclavePost(this.backendUrl, "/api/oauth/email/code", {
      app_id: appId,
      email: normalizeEmail(email),
      login_binding: nonce,
    });
  }

  /**
   * Verify the emailed code inside the attested enclave and resolve the
   * identity. The enclave answers with its own signed token, bound to the login
   * key `sendOtp` started, and that token is used exactly like a Google id_token.
   */
  async verifyOtp(email: string, code: string): Promise<Identity> {
    const address = normalizeEmail(email);
    this.requirePendingLogin();
    const idToken = await this.login.verify({ provider: "email", email: address, code });
    return this.identityFromAuthData(idToken, "email", address);
  }

  /**
   * Redeem a GitHub grant inside the attested enclave. The grant is only
   * useful with the PKCE verifier and login key kept by this login's host, and
   * the token the enclave signs is bound to that key like a Google one.
   */
  private async githubIdentity(githubGrant: string): Promise<Identity> {
    this.requirePendingLogin();
    const idToken = await this.login.verify({ provider: "github", grant: githubGrant });
    return this.identityFromAuthData(idToken, "github");
  }

  /**
   * Redeem a Telegram grant inside the attested enclave, with the same PKCE
   * verifier and login key as GitHub, so a stolen code is useless without them.
   */
  private async telegramIdentity(telegramGrant: string): Promise<Identity> {
    this.requirePendingLogin();
    const idToken = await this.login.verify({ provider: "telegram", grant: telegramGrant });
    return this.identityFromAuthData(idToken, "telegram");
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
  ): Promise<Identity> {
    let token = authData;
    try {
      const parsed = JSON.parse(authData);
      token = parsed.id_token ?? parsed.jwt ?? parsed.token ?? authData;
    } catch {
      // raw JWT
    }
    const claims = parseJwt(token);
    if (requiresLoginBinding(claims.iss)) assertLoginBinding(claims.nonce, this.takeLoginNonce());
    this.setAuthToken(token);
    this.recoveryCredential = isSocialRecoveryIssuer(claims.iss) ? createSocialRecoveryCredential(token) : null;
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
   * Begin a login: ask the login host for a new key and keep its public nonce
   * for the trip to the provider and back.
   *
   * `sessionStorage` because the login navigates away and the nonce has to be
   * here when the callback lands; it is removed as soon as it is read. Where
   * storage is unavailable only this instance remembers it, so a login that
   * reloads the page is refused at the callback, the safe outcome. The key
   * itself stays with the host.
   */
  private async startLogin(): Promise<LoginStart> {
    const started = await this.login.start();
    this.loginNonce = started.nonce;
    try {
      window.sessionStorage.setItem(this.loginNonceKey, started.nonce);
    } catch {
      return started;
    }
    return started;
  }

  private pendingLoginNonce(): string | null {
    try {
      return window.sessionStorage.getItem(this.loginNonceKey) ?? this.loginNonce;
    } catch {
      return this.loginNonce;
    }
  }

  /** Refuse to spend an enclave call on a sign-in this page did not start. */
  private requirePendingLogin(): void {
    if (!this.pendingLoginNonce()) throw new Error(LOGIN_NOT_STARTED);
  }

  /** The nonce of the login in flight, taken exactly once. */
  private takeLoginNonce(): string | null {
    const nonce = this.pendingLoginNonce();
    this.loginNonce = null;
    try {
      window.sessionStorage.removeItem(this.loginNonceKey);
    } catch {
      return nonce;
    }
    return nonce;
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

/** Whether `url` is Telegram's authorize page, asked for with exactly this challenge, nonce and scope. */
function isTelegramAuthorizeUrl(url: unknown, challenge: string, expectedNonce: string): boolean {
  if (typeof url !== "string") return false;
  try {
    const parsed = new URL(url);
    return (
      parsed.protocol === "https:" &&
      parsed.host === "oauth.telegram.org" &&
      parsed.pathname === "/auth" &&
      parsed.searchParams.get("response_type") === "code" &&
      parsed.searchParams.get("code_challenge") === challenge &&
      parsed.searchParams.get("code_challenge_method") === "S256" &&
      parsed.searchParams.get("nonce") === expectedNonce &&
      parsed.searchParams.get("scope") === "openid profile"
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
    case ENCLAVE_TELEGRAM_ISSUER:
      return "telegram";
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
