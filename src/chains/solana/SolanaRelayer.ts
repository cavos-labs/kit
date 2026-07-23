import {
  Connection,
  PublicKey,
  Transaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import type { SolanaNetwork } from "./constants";

export interface SolanaRelayerOptions {
  /** Base URL of the Cavos backend exposing /api/solana/relay. */
  baseUrl: string;
  /** Cavos App ID (authorizes the sponsored request). */
  appId: string;
  /** Optional Cavos console environment. Omitted means production. */
  environment?: "development" | "production";
  network: SolanaNetwork;
  /** Connection used only to fetch a recent blockhash before serializing. */
  connection: Connection;
}

/**
 * Client for the Cavos Solana sponsoring relayer. Lets the SDK submit
 * device-account transactions WITHOUT the integrator holding a fee-payer
 * keypair: the relayer co-signs as fee payer and pays the fee/rent. The relayer
 * only pays — the device signature inside the instructions (verified by the
 * secp256r1 precompile) is what authorizes the action, and it does not bind the
 * fee payer, so sponsorship needs no re-signing.
 */
export class SolanaRelayer {
  private feePayer?: PublicKey;

  constructor(private readonly opts: SolanaRelayerOptions) {}

  /** The relayer's fee-payer pubkey (fetched + cached from the backend). */
  async getFeePayer(): Promise<PublicKey> {
    if (this.feePayer) return this.feePayer;
    const res = await fetch(`${this.opts.baseUrl}/api/solana/relay?network=${this.opts.network}`);
    if (!res.ok) throw new Error(`kit/solana: relayer fee-payer lookup failed (${res.status})`);
    const { fee_payer } = (await res.json()) as { fee_payer: string };
    this.feePayer = new PublicKey(fee_payer);
    return this.feePayer;
  }

  /**
   * Build a tx with the relayer as fee payer, serialize it unsigned, and POST it
   * to the relayer to co-sign + submit. Returns the confirmed signature.
   */
  async send(instructions: TransactionInstruction[]): Promise<string> {
    const feePayer = await this.getFeePayer();
    const { blockhash } = await this.opts.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
    tx.feePayer = feePayer;
    tx.recentBlockhash = blockhash;
    tx.add(...instructions);

    const serialized = tx
      .serialize({ requireAllSignatures: false, verifySignatures: false })
      .toString("base64");

    const res = await fetch(`${this.opts.baseUrl}/api/solana/relay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        network: this.opts.network,
        transaction: serialized,
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`kit/solana: relay failed (${res.status}) ${detail}`);
    }
    const { signature } = (await res.json()) as { signature: string };
    return signature;
  }
}
