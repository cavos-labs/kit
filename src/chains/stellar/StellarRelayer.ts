import type { StellarNetwork } from "./constants";

export interface StellarRelayerOptions {
  /** Base URL of the Cavos backend exposing /api/stellar/relay. */
  baseUrl: string;
  /** Cavos App ID (authorizes the sponsored request). */
  appId: string;
  /** Optional Cavos console environment. Omitted means production. */
  environment?: "development" | "production";
  network: StellarNetwork;
}

/** Options for relayer submission that may include anti-squatting verification. */
export interface StellarRelayerSubmitOptions {
  /**
   * Identity token (JWT) for anti-squatting verification. Required for account
   * creation (`kind: "create"`) to prove the caller owns the userId that the
   * master keypair is derived from. The relayer validates the token's subject
   * matches the transaction's address derivation before sponsoring.
   */
  idToken?: string;
}

/** What the transaction is, so the backend applies the right validation gate.
 *  - `create`         sponsored account creation (relayer = source + sponsor)
 *  - `fee-bump`       a control-signed payment wrapped in a relayer fee-bump
 *  - `sponsored-data` a control-signed data write (add factor/device slot) whose
 *                     new subentry reserves the relayer sponsors
 *  - `trustline`      a control-signed `changeTrust` whose new subentry reserve
 *                     the relayer sponsors
 *  - `soroban`        a control-signed Soroban contract invocation wrapped in a
 *                     relayer fee-bump (the relayer pays the resource + inclusion
 *                     fees; the account's control key signs the auth entries) */
export type StellarRelayKind =
  | "create"
  | "fee-bump"
  | "sponsored-data"
  | "trustline"
  | "soroban";

/**
 * Client for the classic-G sponsoring relayer. Unlike the Soroban relayer (which
 * is the tx *source*), the classic relayer plays two roles:
 *   - **create**: it is the tx source + fee payer AND sponsors the new account's
 *     reserves (`begin/endSponsoringFutureReserves`), so the user locks no XLM.
 *     The SDK sends a master-signed create tx; the relayer co-signs + submits.
 *   - **fee-bump**: the user's control-signed inner tx (source = their `G…`) is
 *     wrapped in a fee-bump whose fee source is the relayer. The relayer signs the
 *     outer envelope only — it pays the fee, never moves the user's funds.
 *
 * Either way the relayer is a fee payer / reserve sponsor, never a custodian.
 *
 * Anti-squatting: for account creation, the relayer validates an identity token
 * (JWT) to ensure the caller owns the userId that the master keypair is derived
 * from. This prevents attackers who know (userId, appSalt) from squatting
 * deterministic addresses before the legitimate user.
 */
export class StellarRelayer {
  private source?: string;

  constructor(private readonly opts: StellarRelayerOptions) {}

  /** The relayer's source/fee-payer/sponsor G-account (fetched + cached). */
  async getSource(): Promise<string> {
    if (this.source) return this.source;
    this.source = (await this.fetchSourceAccount()).address;
    return this.source;
  }

  /**
   * The relayer account together with its CURRENT sequence number, straight from
   * the server. Sponsored writes are sourced by the relayer, so building one
   * needs its sequence — and reading that from this device's own Horizon is
   * reading a stale view of an account the server owns, which the network then
   * rejects as `tx_bad_seq`. The sequence is deliberately NOT cached.
   *
   * `sequence` is undefined on older backends, in which case the caller falls
   * back to loading the account itself.
   */
  async fetchSourceAccount(): Promise<{ address: string; sequence?: string }> {
    const qs = new URLSearchParams({
      network: this.opts.network,
      app_id: this.opts.appId,
    });
    if (this.opts.environment) qs.set('environment', this.opts.environment);
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay?${qs.toString()}`);
    if (!res.ok) throw new Error(`kit/stellar: relayer source lookup failed (${res.status})`);
    const { fee_payer, sequence } = (await res.json()) as { fee_payer: string; sequence?: string };
    this.source = fee_payer;
    return { address: fee_payer, ...(sequence ? { sequence } : {}) };
  }

  /**
   * POST a (partially) signed transaction XDR for the relayer to co-sign + submit.
   * `kind` selects the validation gate. Returns the confirmed transaction hash.
   *
   * For account creation (`kind: "create"`), pass `opts.idToken` to enable
   * anti-squatting verification. The relayer validates that the token's subject
   * matches the userId in the master keypair derivation before sponsoring,
   * preventing attackers from claiming addresses they don't own.
   */
  async submit(kind: StellarRelayKind, transactionXdr: string, opts?: StellarRelayerSubmitOptions): Promise<string> {
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        network: this.opts.network,
        kind,
        transaction: transactionXdr,
        // Anti-squatting: the relayer verifies the identity token matches the
        // userId in the master keypair derivation before sponsoring creation.
        ...(opts?.idToken ? { id_token: opts.idToken } : {}),
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`kit/stellar: relay failed (${res.status}) ${detail}`);
    }
    const { hash } = (await res.json()) as { hash: string };
    return hash;
  }
}
