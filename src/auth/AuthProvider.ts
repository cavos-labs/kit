/**
 * Identity for a Cavos wallet. Login (email / social / OTP) only ever produces a
 * stable `userId`; that's all the wallet needs to derive its address. Auth never
 * touches signing — the device key does that, silently.
 *
 * Privy-style UX: the user "logs in" and the wallet is provisioned behind the
 * scenes (device key + auto-deployed smart account). The app never handles keys.
 */
export interface Identity {
  /** Stable, backend-managed user identifier. */
  userId: string;
  /** Optional metadata (email, provider) for display only. */
  email?: string;
  /**
   * Display name from the OAuth id_token (standard OIDC `name` claim).
   * Populated by Google, GitHub and Telegram sign-in; absent for email and Apple
   * (their tokens don't carry it). Optional on purpose —
   * consumers should fall back to `email` / `userId` when unset.
   */
  name?: string;
  provider?: "google" | "apple" | "email" | "github" | "telegram" | "otp" | string;
}

/**
 * Authenticates a user and returns their stable identity. Implementations:
 * - `CavosAuth` (hosted, mirrors `@cavos/react`: Google/Apple/email/OTP via the
 *   Cavos backend) — the default, Privy-like experience.
 * - any custom provider (the app already authenticated the user elsewhere).
 */
export interface AuthProvider {
  authenticate(): Promise<Identity>;
  /**
   * The token that proves who the user is: the provider id_token of a Cavos
   * login, or the JWT of the app's own auth. The vault opens the wallet with
   * it and the wallet registry authenticates the end user with it, so a public
   * app id is not enough. Kept in memory only.
   */
  getAuthToken?(): string | null;
}

/**
 * Provider for an app that signs its users in itself. `token` returns the
 * current JWT its own auth issued for the user; the vault and the registry
 * verify it against the identity provider registered for the app.
 */
export class StaticIdentity implements AuthProvider {
  constructor(
    private readonly identity: Identity,
    private readonly token?: () => string | null,
  ) {}
  async authenticate(): Promise<Identity> {
    return this.identity;
  }
  getAuthToken(): string | null {
    return this.token?.() ?? null;
  }
}
