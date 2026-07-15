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
   * Populated by Google sign-in; absent for email/OTP/magic-link and Apple
   * (the Cavos-signed Firebase JWT doesn't mint it). Optional on purpose —
   * consumers should fall back to `email` / `userId` when unset.
   */
  name?: string;
  provider?: "google" | "apple" | "email" | "otp" | string;
}

/**
 * Authenticates a user and returns their stable identity. Implementations:
 * - `CavosAuth` (hosted, mirrors `@cavos/react`: Google/Apple/email/OTP via the
 *   Cavos backend) — the default, Privy-like experience.
 * - any custom provider (the app already authenticated the user elsewhere).
 */
export interface AuthProvider {
  authenticate(): Promise<Identity>;
}

/** Trivial provider when the app already has the user's stable id. */
export class StaticIdentity implements AuthProvider {
  constructor(private readonly identity: Identity) {}
  async authenticate(): Promise<Identity> {
    return this.identity;
  }
}
