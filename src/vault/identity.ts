import { assertLoginBinding, loginNonceOf } from "../auth/loginBinding";
import { WebCryptoLoginKey } from "../auth/loginKey";
import { unverifiedIssuer, verifyIdToken, type JwksLoader, type TokenIssuer } from "./idToken";
import { SIGN_IN_REQUIRED } from "./protocol";
import type { SessionStore } from "./session";

/** How an app's users prove who they are, set in the Cavos dashboard and read by the vault from Cavos. */
export interface IdentitySettings {
  /** The OAuth client ids Cavos signs users in with. A Google or Apple token for any other client is refused. */
  google: string[];
  apple: string[];
  /** The app's own identity provider, for an app that signs its users in itself. */
  external?: { issuer: string; audience?: string };
}

/** Used when the app's settings cannot be read: no token opens a wallet. */
export const NO_IDENTITY: IdentitySettings = { google: [], apple: [] };

export function parseIdentitySettings(raw: unknown): IdentitySettings {
  if (typeof raw !== "object" || raw === null) return NO_IDENTITY;
  const { google, apple, external } = raw as Record<string, unknown>;
  const issuer = (external as { issuer?: unknown } | undefined)?.issuer;
  const audience = (external as { audience?: unknown } | undefined)?.audience;
  return {
    google: strings(google),
    apple: strings(apple),
    ...(typeof issuer === "string" && issuer && !isHostedIssuer(issuer)
      ? { external: { issuer, ...(typeof audience === "string" && audience ? { audience } : {}) } }
      : {}),
  };
}

export interface Gatekeeper {
  /**
   * Let `userId` open their wallet, or throw. A live session is enough. Without
   * one, `token` has to prove a sign-in: a Google or Apple token answering the
   * login this vault started, or a token from the app's own identity provider.
   */
  admit(userId: string, token: string | null): Promise<void>;
  /** Record a sign-in the vault itself completed with the enclave. */
  signedIn(enclaveToken: string): Promise<void>;
  /** End the user's session and the login that opened it. */
  signOut(userId: string): Promise<void>;
}

export interface GatekeeperDeps {
  appId: string;
  backendUrl: string;
  settings: IdentitySettings;
  sessions: SessionStore;
  loadKeys?: JwksLoader;
}

export function createGatekeeper(deps: GatekeeperDeps): Gatekeeper {
  const sessionKey = (userId: string) => `${deps.appId}|${userId}`;
  const verify = (token: string, issuer: TokenIssuer) =>
    verifyIdToken(token, issuer, deps.loadKeys ? { loadKeys: deps.loadKeys } : {});

  /** The issuer Cavos signs in with for this token, or null when it is none of them or the app has no client for it. */
  function hostedIssuer(token: string): TokenIssuer | null {
    const iss = unverifiedIssuer(token);
    const issuer = HOSTED_ISSUERS.find((candidate) => candidate.issuers.includes(iss as string));
    const audiences = issuer ? deps.settings[issuer.provider] : [];
    return issuer && audiences.length > 0 ? { ...issuer, audiences } : null;
  }

  async function admitExternal(userId: string, token: string, external: NonNullable<IdentitySettings["external"]>) {
    const claims = await verify(token, {
      issuers: [external.issuer],
      jwksUrl: `${deps.backendUrl}/api/vault/identity-keys?app_id=${encodeURIComponent(deps.appId)}`,
      audiences: external.audience ? [external.audience] : [],
    });
    if (claims.sub !== userId) throw new Error("kit/vault: the sign-in token is for another user");
  }

  async function openSession(userId: string, token: string, issuer: TokenIssuer) {
    const claims = await verify(token, issuer);
    if (claims.sub !== userId) throw new Error("kit/vault: the sign-in token is for another user");
    const loginKey = await WebCryptoLoginKey.load(deps.appId);
    assertLoginBinding(claims.nonce, loginKey ? loginNonceOf(loginKey.publicKeyRaw()) : null);
    await deps.sessions.open(sessionKey(userId));
  }

  /** A token that proves nothing leaves the user where they were: signed out. */
  async function proving(check: Promise<void>): Promise<void> {
    try {
      await check;
    } catch (error) {
      throw new Error(`${SIGN_IN_REQUIRED} (${error instanceof Error ? error.message : String(error)})`);
    }
  }

  return {
    async admit(userId, token) {
      const { external } = deps.settings;
      // An app that signs its users in itself keeps no session here: its own
      // token is asked for every time, so the wallet never outlives its login.
      if (token && external && unverifiedIssuer(token) === external.issuer) {
        return proving(admitExternal(userId, token, external));
      }
      if (await deps.sessions.renew(sessionKey(userId))) return;
      const issuer = token ? hostedIssuer(token) : null;
      if (!token || !issuer) throw new Error(SIGN_IN_REQUIRED);
      await proving(openSession(userId, token, issuer));
    },
    async signedIn(enclaveToken) {
      const sub = subjectOf(enclaveToken);
      await deps.sessions.open(sessionKey(sub));
    },
    async signOut(userId) {
      await deps.sessions.end(sessionKey(userId));
      // The login key goes with the session, so the token it answered cannot open another.
      await WebCryptoLoginKey.remove(deps.appId);
    },
  };
}

const HOSTED_ISSUERS: (Omit<TokenIssuer, "audiences"> & { provider: "google" | "apple" })[] = [
  {
    provider: "google",
    issuers: ["https://accounts.google.com", "accounts.google.com"],
    jwksUrl: "https://www.googleapis.com/oauth2/v3/certs",
  },
  { provider: "apple", issuers: ["https://appleid.apple.com"], jwksUrl: "https://appleid.apple.com/auth/keys" },
];

/** Cavos's own sign-in providers are never an app's "own" one: their tokens must answer a login the vault started. */
function isHostedIssuer(issuer: string): boolean {
  return HOSTED_ISSUERS.some((hosted) => hosted.issuers.includes(issuer)) || issuer.startsWith("https://enclave.cavos.xyz");
}

/** The `sub` of a token the vault received from the attested enclave, which already verified it. */
function subjectOf(token: string): string {
  const payload = token.split(".")[1];
  const sub: unknown = payload ? JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/"))).sub : undefined;
  if (typeof sub !== "string" || !sub) throw new Error("kit/vault: the enclave token names no user");
  return sub;
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item !== "") : [];
}
