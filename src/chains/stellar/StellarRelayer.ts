import type { StellarNetwork } from "./constants";

export interface StellarRelayerOptions {
  /** Base URL of the Cavos backend exposing /api/stellar/relay. */
  baseUrl: string;
  /** Cavos App ID (authorizes the sponsored request). */
  appId: string;
  network: StellarNetwork;
}

/**
 * Client for the Cavos Stellar sponsoring relayer. On Stellar the account is a
 * *contract*, which cannot be a transaction source — so the relayer's own
 * G-account is the transaction source AND fee payer. The user's silent device
 * key never pays: it only signs the Soroban *authorization entry* (verified by
 * the account's `__check_auth`), which is independent of who submits or pays.
 * That gives a seedless, gasless experience with no fee-payer keypair on the
 * integrator side — the same "relayer pays, device authorizes" split as Solana.
 *
 * The SDK builds the fully-assembled transaction (source = relayer, Soroban auth
 * entries already device-signed) and hands its unsigned XDR to the relayer, which
 * validates it against its allowlist, signs the envelope and submits.
 */
export class StellarRelayer {
  private source?: string;

  constructor(private readonly opts: StellarRelayerOptions) {}

  /** The relayer's source/fee-payer G-account (fetched + cached from the backend). */
  async getSource(): Promise<string> {
    if (this.source) return this.source;
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay?network=${this.opts.network}`);
    if (!res.ok) throw new Error(`kit/stellar: relayer source lookup failed (${res.status})`);
    const { fee_payer } = (await res.json()) as { fee_payer: string };
    this.source = fee_payer;
    return this.source;
  }

  /**
   * POST the assembled, device-authorized transaction XDR to the relayer to sign
   * the envelope + submit. Returns the confirmed transaction hash.
   */
  async submit(transactionXdr: string): Promise<string> {
    const res = await fetch(`${this.opts.baseUrl}/api/stellar/relay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: this.opts.appId,
        network: this.opts.network,
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
