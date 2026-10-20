import { num, shortString, stark, type Signature, type TypedData } from "starknet";
import type { PrivacyFeeMode } from "./config";

export interface RelayCall {
  to: string;
  selector: string;
  calldata: string[];
}

export interface RelayInvoke {
  userAddress: string;
  calls: RelayCall[];
  chainId: string;
}

export interface FeeAction {
  recipient: string;
  token: string;
  amount: bigint;
}

export interface RelayQuote {
  /** Null when the sponsor pays the pool fee: the proof must carry no fee withdrawal. */
  feeAction: FeeAction | null;
  typedData?: TypedData;
  parameters: unknown;
}

export interface RelayProof {
  data: string;
  proofFacts: string[];
}

export interface RelayOptions {
  url: string;
  apiKey: () => string;
  maxFee: bigint;
  allowedFeeRecipients: string[];
  /** The fee the pool itself publishes. A user-paid quote above it is refused. */
  publishedFee: () => Promise<bigint>;
  /** Token the published fee is denominated in; quotes in other tokens are bounded by `maxFee` alone. */
  publishedFeeToken: string;
  fetch?: typeof fetch;
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const SNIP9_DOMAIN = "Account.execute_from_outside";
const SNIP9_REVISIONS = [
  { version: 1n, revision: 0n },
  { version: 2n, revision: 1n },
];

/** Talks to the paymaster's private transaction endpoints and refuses anything that costs the user more than the app allowed. */
export class PrivacyRelay {
  private readonly allowed: bigint[];

  constructor(private readonly opts: RelayOptions) {
    this.allowed = opts.allowedFeeRecipients.map((entry) => BigInt(entry));
  }

  async quote(pool: string, fee: PrivacyFeeMode, invoke?: RelayInvoke): Promise<RelayQuote> {
    const apply_action = { pool_address: pool };
    const result = await this.send<{
      fee_action?: { type?: string; recipient?: string; token?: string; amount?: string };
      typed_data?: TypedData;
      parameters?: unknown;
    }>("paymaster_buildTransaction", {
      transaction: invoke
        ? { type: "invoke_and_apply_action", apply_action, invoke: { user_address: invoke.userAddress, calls: invoke.calls } }
        : { type: "apply_action", apply_action },
      parameters: { version: "0x1", fee_mode: fee },
    });

    const feeAction = await this.checkFee(result.fee_action, fee);
    if (invoke) {
      if (!result.typed_data) throw new Error("kit/starknet: the relay returned nothing to sign for the approval");
      this.checkTypedData(result.typed_data, invoke);
    }
    return {
      feeAction,
      ...(result.typed_data ? { typedData: result.typed_data } : {}),
      parameters: result.parameters ?? { version: "0x1", fee_mode: fee },
    };
  }

  async execute(
    call: RelayCall,
    proof: RelayProof,
    parameters: unknown,
    invoke?: { userAddress: string; typedData: TypedData; signature: Signature },
  ): Promise<{ transactionHash: string }> {
    const apply_action = { apply_actions_call: call, proof: proof.data, proof_facts: proof.proofFacts };
    const result = await this.send<{ transaction_hash?: unknown }>("paymaster_executeTransaction", {
      transaction: invoke
        ? {
            type: "invoke_and_apply_action",
            apply_action,
            invoke: {
              user_address: invoke.userAddress,
              typed_data: invoke.typedData,
              signature: stark.signatureToHexArray(invoke.signature),
            },
          }
        : { type: "apply_action", apply_action },
      parameters,
    });
    if (typeof result.transaction_hash !== "string" || !result.transaction_hash) {
      throw new Error("kit/starknet: the relay returned no transaction hash; the transaction may still have been submitted");
    }
    return { transactionHash: result.transaction_hash };
  }

  private async checkFee(
    action: { type?: string; recipient?: string; token?: string; amount?: string } | undefined,
    fee: PrivacyFeeMode,
  ): Promise<FeeAction | null> {
    if (!action) throw new Error("kit/starknet: the relay returned no fee action");
    const sponsored = fee.mode === "sponsored" && fee.pool_fee.paid_by === "sponsor";
    if (action.type === "none") return null;
    if (sponsored) throw new Error("kit/starknet: the relay asked for a fee although the sponsor pays it; nothing was withdrawn");
    if (action.type !== "withdraw") throw new Error("kit/starknet: the relay returned a fee action Cavos does not know");

    const recipient = felt(action.recipient);
    const token = felt(action.token);
    const amount = felt(action.amount);
    if (recipient === undefined || token === undefined || amount === undefined) {
      throw new Error("kit/starknet: the relay returned a malformed fee action");
    }
    if (!this.allowed.includes(recipient)) {
      throw new Error(`kit/starknet: the relay wants its fee sent to ${hex(recipient)}, which this app does not allow; nothing was withdrawn`);
    }
    const chosen = fee.mode === "default" ? fee.gas_token : fee.pool_fee.paid_by === "user" ? fee.pool_fee.token : undefined;
    if (chosen !== undefined && BigInt(chosen) !== token) {
      throw new Error("kit/starknet: the relay quoted its fee in a token the app did not choose; nothing was withdrawn");
    }
    if (amount > this.opts.maxFee) {
      throw new Error(`kit/starknet: the relay quoted a fee of ${amount}, above the ${this.opts.maxFee} this app allows; nothing was withdrawn`);
    }
    if (fee.mode === "sponsored" && token === BigInt(this.opts.publishedFeeToken)) {
      const published = await this.opts.publishedFee();
      if (amount > published) {
        throw new Error(`kit/starknet: the relay quoted a pool fee of ${amount}, above the ${published} the pool publishes; nothing was withdrawn`);
      }
    }
    return { recipient: hex(recipient), token: hex(token), amount };
  }

  private checkTypedData(typedData: TypedData, invoke: RelayInvoke): void {
    const refuse = (why: string): never => {
      throw new Error(`kit/starknet: the relay asked for a signature over something other than the requested approval (${why}); nothing was signed`);
    };
    if (typedData.primaryType !== "OutsideExecution") refuse("not an outside execution");

    const domain = (typedData.domain ?? {}) as Record<string, unknown>;
    if (shortFelt(domain.chainId) !== shortFelt(invoke.chainId)) refuse("another chain");
    if (shortFelt(domain.name) !== shortFelt(SNIP9_DOMAIN)) refuse("another domain");
    const version = shortFelt(domain.version);
    const revision = domain.revision === undefined ? 0n : shortFelt(domain.revision);
    if (!SNIP9_REVISIONS.some((known) => known.version === version && known.revision === revision)) refuse("another domain version");

    const message = (typedData.message ?? {}) as Record<string, unknown>;
    const caller = felt(message.Caller);
    if (caller === undefined || !this.allowed.includes(caller)) refuse("the caller is not an address this app allows");

    const now = BigInt(Math.floor(Date.now() / 1000));
    const before = felt(message["Execute Before"]);
    if (before === undefined || before <= now) refuse("it has expired or never expires");
    const after = felt(message["Execute After"]);
    if (after !== undefined && after > now) refuse("it is not valid yet");

    const calls = message.Calls;
    if (!Array.isArray(calls) || calls.length !== invoke.calls.length) refuse("a different number of calls");
    invoke.calls.forEach((expected, index) => {
      const actual = ((calls as unknown[])[index] ?? {}) as Record<string, unknown>;
      if (felt(actual.To) !== felt(expected.to)) refuse(`call ${index} targets another contract`);
      if (felt(actual.Selector) !== felt(expected.selector)) refuse(`call ${index} runs another entrypoint`);
      const calldata = actual.Calldata;
      if (!Array.isArray(calldata) || calldata.length !== expected.calldata.length) refuse(`call ${index} has other arguments`);
      expected.calldata.forEach((value, position) => {
        if (felt((calldata as unknown[])[position]) !== felt(value)) refuse(`call ${index} has other arguments`);
      });
    });
  }

  private async send<T>(method: string, params: unknown): Promise<T> {
    const send = this.opts.fetch ?? globalThis.fetch;
    const response = await send(this.opts.url, {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json", "x-paymaster-api-key": this.opts.apiKey() },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
      signal: AbortSignal.timeout(this.opts.timeoutMs ?? DEFAULT_TIMEOUT_MS),
    }).catch((error: unknown) => {
      if ((error as { name?: string } | null)?.name === "TimeoutError") {
        throw new Error(`kit/starknet: the relay did not answer ${method} in time`);
      }
      throw error;
    });
    const body = (await response.json().catch(() => undefined)) as
      | { result?: T; error?: { code?: number; message?: string; data?: unknown } }
      | undefined;
    if (body?.error && typeof body.error.code === "number") {
      const detail = typeof body.error.data === "string" ? `: ${body.error.data}` : "";
      throw new Error(`kit/starknet: the relay rejected ${method} (code ${body.error.code}): ${body.error.message ?? "no message"}${detail}`);
    }
    if (!response.ok || body?.result === undefined) {
      throw new Error(`kit/starknet: the relay returned no result for ${method} (HTTP ${response.status})`);
    }
    return body.result;
  }
}

function felt(value: unknown): bigint | undefined {
  if (typeof value !== "string" && typeof value !== "number" && typeof value !== "bigint") return undefined;
  try {
    return num.toBigInt(value);
  } catch {
    return undefined;
  }
}

function shortFelt(value: unknown): bigint | undefined {
  const parsed = felt(value);
  if (parsed !== undefined) return parsed;
  if (typeof value !== "string" || !value) return undefined;
  try {
    return BigInt(shortString.encodeShortString(value));
  } catch {
    return undefined;
  }
}

function hex(value: bigint): string {
  return `0x${value.toString(16)}`;
}
