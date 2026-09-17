import {
  Connection,
  PublicKey,
} from "@solana/web3.js";
import type { SolanaNetwork } from "./constants";

export interface SolanaRelayerOptions {
  baseUrl: string;
  appId: string;
  environment?: "development" | "production";
  network: SolanaNetwork;
  connection: Connection;
}

/**
 * Client for the Cavos Solana sponsoring relayer. The user signs; the relayer
 * co-signs as fee payer. Native system accounts only.
 */
export class SolanaRelayer {
  private feePayer?: PublicKey;

  constructor(private readonly opts: SolanaRelayerOptions) {}

  async getFeePayer(): Promise<PublicKey> {
    if (this.feePayer) return this.feePayer;
    const res = await fetch(`${this.opts.baseUrl}/api/solana/relay?network=${this.opts.network}`);
    if (!res.ok) throw new Error(`kit/solana: relayer fee-payer lookup failed (${res.status})`);
    const { fee_payer } = (await res.json()) as { fee_payer: string };
    this.feePayer = new PublicKey(fee_payer);
    return this.feePayer;
  }

  async sendSigned(serialized: Uint8Array): Promise<string> {
    const res = await fetch(`${this.opts.baseUrl}/api/solana/relay`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        network: this.opts.network,
        kind: "native",
        transaction: Buffer.from(serialized).toString("base64"),
      }),
    });
    if (!res.ok) {
      const detail = await res.text().catch(() => "");
      throw new Error(`kit/solana: native relay failed (${res.status}) ${detail}`);
    }
    const { signature } = (await res.json()) as { signature: string };
    return signature;
  }
}
