import * as WebBrowser from "expo-web-browser";
import type { AuthProvider, Identity } from "../auth/AuthProvider";
import { decodeUtf8, fromBase64 } from "./encoding";
import {
  assertLoginBinding,
  loginNonce,
  loginSecretFrom,
  requiresLoginBinding,
} from "../auth/loginBinding";
import { nativeModule } from "./NativeModule";
import {
  createSocialRecoveryCredential,
  isSocialRecoveryIssuer,
  type SocialRecoveryCredential,
} from "../recovery/SocialRecoveryCredential";

export interface NativeCavosAuthOptions {
  appId: string;
  redirectUri: string;
  backendUrl?: string;
}

export type NativeCavosAuthErrorCode =
  | "invalid-config"
  | "cancelled"
  | "callback-invalid"
  | "not-authenticated"
  | "http-error"
  | "unsupported";

export class NativeCavosAuthError extends Error {
  readonly name = "NativeCavosAuthError";
  constructor(readonly code: NativeCavosAuthErrorCode, message: string, readonly status?: number) {
    super(message);
  }
}

export class NativeCavosAuth implements AuthProvider {
  private readonly backendUrl: string;
  private readonly storageKey: string;
  private last: Identity | null = null;
  /** Never persisted; every recovery requires a fresh social login. */
  private recoveryCredential: SocialRecoveryCredential | null = null;
  /** The secret of the login in flight; see `auth/loginBinding`. */
  private loginSecret: string | null = null;

  constructor(private readonly opts: NativeCavosAuthOptions) {
    if (!opts.appId) throw new NativeCavosAuthError("invalid-config", "kit/native-auth: appId is required");
    if (!opts.redirectUri) throw new NativeCavosAuthError("invalid-config", "kit/native-auth: redirectUri is required");
    this.backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    this.storageKey = `cavos-kit:identity:${opts.appId}`;
  }

  async restoreIdentity(): Promise<Identity | null> {
    const raw = await nativeModule().getStoredValue(this.storageKey);
    if (!raw) return null;
    try {
      const identity = JSON.parse(raw) as Identity;
      if (!identity.userId) return null;
      this.last = identity;
      return identity;
    } catch {
      return null;
    }
  }

  async clearStoredIdentity(): Promise<void> {
    this.last = null;
    this.recoveryCredential = null;
    await nativeModule().setStoredValue(this.storageKey, null);
  }

  async login(provider: "google" | "apple"): Promise<Identity> {
    // Kept in memory: the system browser returns to this same call, and a
    // callback that arrives in a new process is refused (see `loginBinding`).
    this.loginSecret = loginSecretFrom(fromBase64(await nativeModule().randomBytes(32)));
    const params = new URLSearchParams({
      nonce: loginNonce(this.loginSecret),
      redirect_uri: this.opts.redirectUri,
      app_id: this.opts.appId,
    });
    const { url } = await this.get(`/api/oauth/v2/${provider}?${params}`);
    const result = await WebBrowser.openAuthSessionAsync(url, this.opts.redirectUri);
    if (result.type !== "success" || !result.url) {
      throw new NativeCavosAuthError(
        result.type === "cancel" ? "cancelled" : "callback-invalid",
        result.type === "cancel" ? "kit/native-auth: login cancelled" : "kit/native-auth: login failed",
      );
    }
    return this.handleCallback(result.url, provider);
  }

  async sendOtp(_email: string): Promise<void> {
    throw emailUnsupported();
  }

  async verifyOtp(_email: string, _code: string): Promise<Identity> {
    throw emailUnsupported();
  }

  async handleCallback(input: string, provider = "oauth"): Promise<Identity> {
    const callbackCode = extractCallbackCode(input);
    if (callbackCode) {
      const result = await this.post("/api/oauth/callback/exchange", {
        code: callbackCode,
        app_id: this.opts.appId,
        redirect_uri: this.opts.redirectUri,
      });
      return this.identityFromAuthData(JSON.stringify(result), provider);
    }
    let authData = input;
    if (input.includes("auth_data=") || input.includes("zk_auth_data=")) {
      const params = new URL(input).searchParams;
      authData = params.get("auth_data") ?? params.get("zk_auth_data") ?? input;
    }
    return this.identityFromAuthData(authData, provider);
  }

  async authenticate(): Promise<Identity> {
    if (!this.last) throw new NativeCavosAuthError("not-authenticated", "kit/native-auth: complete login first");
    return this.last;
  }

  getSocialRecoveryCredential(): SocialRecoveryCredential {
    if (!this.recoveryCredential) {
      throw new NativeCavosAuthError(
        "not-authenticated",
        "kit/native-auth: complete a fresh social login before recovery",
      );
    }
    return this.recoveryCredential;
  }

  private async identityFromAuthData(data: string, provider: string, email?: string): Promise<Identity> {
    let token = data;
    try {
      const parsed = JSON.parse(data);
      token = parsed.id_token ?? parsed.jwt ?? parsed.token ?? data;
    } catch { /* raw JWT */ }
    const payload = token.split(".")[1];
    if (!payload) throw new NativeCavosAuthError("callback-invalid", "kit/native-auth: malformed JWT");
    const claims = JSON.parse(decodeUtf8(fromBase64(normalizeBase64url(payload))));
    let loginSecret: string | undefined;
    if (requiresLoginBinding(claims.iss)) {
      const kept = this.loginSecret;
      this.loginSecret = null;
      try {
        assertLoginBinding(claims.nonce, kept);
      } catch (error) {
        throw new NativeCavosAuthError("callback-invalid", (error as Error).message);
      }
      loginSecret = kept;
    }
    this.recoveryCredential = isSocialRecoveryIssuer(claims.iss)
      ? createSocialRecoveryCredential(token, loginSecret)
      : null;
    const identity: Identity = {
      userId: String(claims.sub ?? claims.user_id ?? claims.uid),
      email: claims.email ?? email,
      name: claims.name,
      provider: claims.provider ?? provider,
    };
    this.last = identity;
    await nativeModule().setStoredValue(this.storageKey, JSON.stringify(identity));
    return identity;
  }

  private async get(path: string): Promise<any> {
    const response = await fetch(`${this.backendUrl}${path}`);
    if (!response.ok) throw new NativeCavosAuthError("http-error", `kit/native-auth: ${path} -> ${response.status} ${await response.text()}`, response.status);
    return response.json();
  }

  private async post(path: string, body: unknown): Promise<any> {
    const response = await fetch(`${this.backendUrl}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    if (!response.ok) throw new NativeCavosAuthError("http-error", `kit/native-auth: ${path} -> ${response.status} ${await response.text()}`, response.status);
    return response.json();
  }
}

function normalizeBase64url(value: string): string {
  const base = value.replace(/-/g, "+").replace(/_/g, "/");
  return base + "=".repeat((4 - base.length % 4) % 4);
}

function extractCallbackCode(input: string): string | null {
  if (/^[A-Za-z0-9_-]{43}$/.test(input)) return input;
  try { return new URL(input).searchParams.get("cavos_auth_code"); }
  catch { return null; }
}

function emailUnsupported(): NativeCavosAuthError {
  return new NativeCavosAuthError(
    "unsupported",
    "kit/native-auth: email sign-in is not supported in React Native yet. It needs to verify the enclave's attestation, which this build cannot do. Use Google or Apple.",
  );
}
