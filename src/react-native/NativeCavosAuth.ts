import { hash, num } from "starknet";
import * as WebBrowser from "expo-web-browser";
import type { AuthProvider, Identity } from "../auth/AuthProvider";
import { decodeUtf8, fromBase64 } from "./encoding";
import { nativeModule } from "./NativeModule";

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
  | "http-error";

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
    await nativeModule().setStoredValue(this.storageKey, null);
  }

  async login(provider: "google" | "apple"): Promise<Identity> {
    const nonce = await this.freshNonce();
    const params = new URLSearchParams({
      nonce,
      redirect_uri: this.opts.redirectUri,
      app_id: this.opts.appId,
    });
    const { url } = await this.get(`/api/oauth/${provider}?${params}`);
    const result = await WebBrowser.openAuthSessionAsync(url, this.opts.redirectUri);
    if (result.type !== "success" || !result.url) {
      throw new NativeCavosAuthError(
        result.type === "cancel" ? "cancelled" : "callback-invalid",
        result.type === "cancel" ? "kit/native-auth: login cancelled" : "kit/native-auth: login failed",
      );
    }
    return this.handleCallback(result.url, provider);
  }

  async sendOtp(email: string): Promise<void> {
    await this.post("/api/oauth/firebase/otp/request", {
      email,
      nonce: await this.freshNonce(),
      app_id: this.opts.appId,
    });
  }

  async sendMagicLink(email: string): Promise<void> {
    await this.post("/api/oauth/firebase/magic-link", {
      email,
      nonce: await this.freshNonce(),
      app_id: this.opts.appId,
      redirect_uri: this.opts.redirectUri,
    });
  }

  async verifyOtp(email: string, code: string): Promise<Identity> {
    const res = await this.post("/api/oauth/firebase/otp/verify", {
      email,
      code,
      nonce: await this.consumeNonce(),
      app_id: this.opts.appId,
    });
    return this.identityFromAuthData(res.id_token ?? res.jwt ?? res.token ?? JSON.stringify(res), "otp", email);
  }

  async handleCallback(input: string, provider = "oauth"): Promise<Identity> {
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

  private async freshNonce(): Promise<string> {
    const bytes = fromBase64(await nativeModule().randomBytes(31));
    let word = 0n;
    for (const byte of bytes) word = (word << 8n) | BigInt(byte);
    const nonce = num.toHex(hash.computePoseidonHashOnElements([word]));
    await nativeModule().setStoredValue(`${this.storageKey}:nonce`, nonce);
    return nonce;
  }

  private async consumeNonce(): Promise<string> {
    const key = `${this.storageKey}:nonce`;
    const nonce = await nativeModule().getStoredValue(key);
    await nativeModule().setStoredValue(key, null);
    return nonce ?? this.freshNonce();
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
    const identity: Identity = {
      userId: String(claims.sub ?? claims.user_id ?? claims.uid),
      email: claims.email ?? email,
      name: claims.name,
      provider: claims.firebase?.sign_in_provider ?? claims.provider ?? provider,
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
