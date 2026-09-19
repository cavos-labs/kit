import { PublicKey } from "@solana/web3.js";

export interface TollQuote {
  /** Opaque sealed payload; submit it back unchanged. */
  quote: string;
  feePayer: PublicKey;
  treasury: PublicKey;
  mint: PublicKey;
  /** Base units of `mint` the user owes. */
  amount: bigint;
  decimals: number;
  expiresAt: number;
}

export interface TollClientOptions {
  /** e.g. https://toll.cavos.xyz */
  baseUrl: string;
}

export interface QuoteRequest {
  mint: string;
  /** Instructions the transaction will carry, the payment included. */
  instructions: number;
  computeUnits?: number;
  microLamportsPerUnit?: number;
  fundedTokenAccounts?: number;
}

/**
 * Client for Toll, which pays a transaction's SOL fee and takes settlement in
 * the token the user already holds.
 *
 * Toll is the fee payer, never a custodian: it co-signs a transaction the user
 * signed and cannot alter its instructions.
 */
export class TollClient {
  constructor(private readonly opts: TollClientOptions) {}

  async quote(req: QuoteRequest): Promise<TollQuote> {
    const res = await fetch(`${this.opts.baseUrl}/v1/quote`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        fee_mint: req.mint,
        instructions: req.instructions,
        ...(req.computeUnits ? { compute_units: req.computeUnits } : {}),
        ...(req.microLamportsPerUnit
          ? { micro_lamports_per_unit: req.microLamportsPerUnit }
          : {}),
        ...(req.fundedTokenAccounts
          ? { funded_token_accounts: req.fundedTokenAccounts }
          : {}),
      }),
    });
    if (!res.ok) throw new Error(`kit/solana: toll quote failed (${res.status}) ${await detail(res)}`);
    const body = (await res.json()) as {
      quote: string;
      fee_payer: string;
      treasury: string;
      mint: string;
      amount: number;
      decimals: number;
      expires_at: number;
    };
    return {
      quote: body.quote,
      feePayer: new PublicKey(body.fee_payer),
      treasury: new PublicKey(body.treasury),
      mint: new PublicKey(body.mint),
      amount: BigInt(body.amount),
      decimals: body.decimals,
      expiresAt: body.expires_at,
    };
  }

  async submit(quote: string, serialized: Uint8Array): Promise<string> {
    const res = await fetch(`${this.opts.baseUrl}/v1/submit`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        quote,
        transaction: Buffer.from(serialized).toString("base64"),
      }),
    });
    if (!res.ok) throw new Error(`kit/solana: toll submit failed (${res.status}) ${await detail(res)}`);
    const { signature } = (await res.json()) as { signature: string };
    return signature;
  }
}

async function detail(res: Response): Promise<string> {
  try {
    const body = (await res.json()) as { error?: string };
    return body.error ?? "";
  } catch {
    return "";
  }
}
