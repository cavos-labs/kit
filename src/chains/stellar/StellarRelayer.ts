import type { StellarNetwork } from "./constants";

export interface StellarRelayerOptions {
  /** Base URL of the Cavos backend exposing /api/stellar/relay. */
  baseUrl: string;
  /** Cavos App ID (authorizes the sponsored request). */
  appId: string;
  network: StellarNetwork;
}

/** What the transaction is, so the backend applies the right validation gate.
 *  - `create`         sponsored account creation (relayer = source + sponsor)
 *  - `fee-bump`       a control-signed payment wrapped in a relayer fee-bump
 *  - `sponsored-data` a control-signed data write (add factor/device slot) whose
 *                     new subentry reserves the relayer sponsors
 *  - `soroban`        a control-signed Soroban contract invocation wrapped in a
 *                     relayer fee-bump (the relayer pays the resource + inclusion
 *                     fees; the account's control key signs the auth entries) */
export type StellarRelayKind = "create" | "fee-bump" | "sponsored-data" | "soroban";

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
 */
export class StellarRelayer {
  private source?: string;

  constructor(private readonly opts: StellarRelayerOptions) {}

  /** The relayer's source/fee-payer/sponsor G-account (fetched + cached). */
  async getSource(): Promise<string> {
    if (this.source) return this.source;
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay?network=${this.opts.network}`);
    if (!res.ok) throw new Error(`kit/stellar: relayer source lookup failed (${res.status})`);
    const { fee_payer } = (await res.json()) as { fee_payer: string };
    this.source = fee_payer;
    return this.source;
  }

  /** POST a (partially) signed transaction XDR for the relayer to co-sign + submit.
   *  `kind` selects the validation gate. Returns the confirmed transaction hash. */
  async submit(kind: StellarRelayKind, transactionXdr: string): Promise<string> {
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: this.opts.appId,
        network: this.opts.network,
        kind,
        transaction: transactionXdr,
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
