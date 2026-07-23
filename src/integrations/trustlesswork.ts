import { Address, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import type { CavosStellar } from "../chains/stellar/CavosStellar";
import type { StellarAdapter } from "../chains/stellar/StellarAdapter";
import type { ExecuteOptions } from "../chains/ChainAdapter";
import { secureRandomBytes } from "../crypto/encoding";

/**
 * Turnkey wrapper over `CavosStellar.invokeContract` for Trustless Work's
 * single-release milestone escrow (Soroban). Each method maps 1:1 to a contract
 * entrypoint and passes THIS Cavos account's `G…` as the role argument that the
 * contract `require_auth`s — so the account's control key signs the matching
 * Soroban auth entry. See the escrow contract reference for the lifecycle.
 *
 * Gasless by default (the relayer fee-bumps); pass `{ sponsored: false }` to have
 * the account pay its own fee.
 *
 *   const escrow = new TrustlessWorkEscrow(wallet, contractId);
 *   await escrow.approveMilestone(0);   // wallet acts as `approver`
 *   await escrow.releaseFunds(TW_ADDR); // wallet acts as `release_signer`
 */
export class TrustlessWorkEscrow {
  constructor(
    private readonly wallet: CavosStellar,
    private readonly contractId: string,
  ) {}

  /** This account's `G…` as a Soroban address ScVal — the role argument. */
  private self(): xdr.ScVal {
    return new Address(this.wallet.address).toScVal();
  }

  private addr(g: string): xdr.ScVal {
    return new Address(g).toScVal();
  }

  // ── Milestones ────────────────────────────────────────────────────────────

  /** `approve_milestone(milestone_index, approver=self)` — the client approves. */
  approveMilestone(milestoneIndex: number, opts?: ExecuteOptions): Promise<string> {
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "approve_milestone",
      args: [nativeToScVal(milestoneIndex, { type: "u32" }), this.self()],
      opts,
    });
  }

  /** `change_milestone_status(index, new_status, new_evidence?, service_provider=self)`. */
  changeMilestoneStatus(
    milestoneIndex: number,
    newStatus: string,
    newEvidence?: string,
    opts?: ExecuteOptions,
  ): Promise<string> {
    const evidence =
      newEvidence === undefined
        ? xdr.ScVal.scvVoid()
        : nativeToScVal(newEvidence, { type: "string" });
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "change_milestone_status",
      args: [
        nativeToScVal(milestoneIndex, { type: "u32" }),
        nativeToScVal(newStatus, { type: "string" }),
        evidence,
        this.self(),
      ],
      opts,
    });
  }

  // ── Release / Dispute ───────────────────────────────────────────────────────

  /** `release_funds(release_signer=self, trustless_work_address)`. */
  releaseFunds(trustlessWorkAddress: string, opts?: ExecuteOptions): Promise<string> {
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "release_funds",
      args: [this.self(), this.addr(trustlessWorkAddress)],
      opts,
    });
  }

  /** `dispute_escrow(signer=self)` — any role (except resolver) can dispute. */
  disputeEscrow(opts?: ExecuteOptions): Promise<string> {
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "dispute_escrow",
      args: [this.self()],
      opts,
    });
  }

  // ── Funding & resolution (complex args) ─────────────────────────────────────

  /**
   * `fund_escrow(signer=self, expected_escrow, amount)`. `expected_escrow` must be
   * the current on-chain `Escrow` struct as an ScVal — read it via `getEscrow()`
   * and pass the raw simulated value, or build it with `nativeToScVal`.
   */
  fundEscrow(expectedEscrow: xdr.ScVal, amount: bigint, opts?: ExecuteOptions): Promise<string> {
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "fund_escrow",
      args: [this.self(), expectedEscrow, nativeToScVal(amount, { type: "i128" })],
      opts,
    });
  }

  /**
   * `resolve_dispute(dispute_resolver=self, trustless_work_address, distributions)`.
   * `distributions` is a `Map<Address, i128>` — pass as `{ [gAddress]: amount }`.
   */
  resolveDispute(
    trustlessWorkAddress: string,
    distributions: Record<string, bigint>,
    opts?: ExecuteOptions,
  ): Promise<string> {
    const entries = Object.entries(distributions).map(
      ([g, amount]) =>
        new xdr.ScMapEntry({
          key: new Address(g).toScVal(),
          val: nativeToScVal(amount, { type: "i128" }),
        }),
    );
    return this.wallet.invokeContract({
      contractId: this.contractId,
      method: "resolve_dispute",
      args: [this.self(), this.addr(trustlessWorkAddress), xdr.ScVal.scvMap(entries)],
      opts,
    });
  }

  /** Read the current on-chain escrow state (roles, milestones, flags, amount).
   *  Read-only simulation — needs an adapter but no signing. */
  async getEscrow(adapter: StellarAdapter): Promise<EscrowState> {
    return adapter.readContract({
      from: this.wallet.address,
      contractId: this.contractId,
      method: "get_escrow",
    }) as Promise<EscrowState>;
  }
}

// ── Escrow struct encoding + factory deploy ───────────────────────────────────

export interface MilestoneInput {
  description: string;
  status?: string;
  evidence?: string;
  approved?: boolean;
}

export interface EscrowInput {
  engagementId: string;
  title: string;
  description: string;
  /** Total amount in the trustline token's base units (7-dp for USDC/XLM). */
  amount: bigint;
  /** Platform fee in basis points (e.g. 100 = 1%). */
  platformFeeBps: number;
  roles: {
    approver: string;
    serviceProvider: string;
    platform: string;
    releaseSigner: string;
    disputeResolver: string;
    receiver: string;
  };
  milestones: MilestoneInput[];
  /** Trustline token contract (SAC) address — e.g. USDC's `C…`. */
  trustline: string;
  receiverMemo?: number;
}

/** Decoded `get_escrow` result (native JS shape from `scValToNative`). */
export interface EscrowState {
  engagement_id: string;
  title: string;
  description: string;
  amount: bigint;
  platform_fee: number;
  roles: Record<string, string>;
  milestones: { description: string; status: string; evidence: string; approved: boolean }[];
  flags: { disputed: boolean; released: boolean; resolved: boolean };
  trustline: { address: string };
  receiver_memo: number;
}

const sym = (s: string) => xdr.ScVal.scvSymbol(s);
const str = (s: string) => nativeToScVal(s, { type: "string" });
const u32 = (n: number) => nativeToScVal(n, { type: "u32" });
const boolVal = (b: boolean) => xdr.ScVal.scvBool(b);
const addrVal = (g: string) => new Address(g).toScVal();

/** A contracttype struct → scvMap with symbol keys sorted by name. */
function struct(fields: Record<string, xdr.ScVal>): xdr.ScVal {
  const entries = Object.keys(fields)
    .sort()
    .map((k) => new xdr.ScMapEntry({ key: sym(k), val: fields[k] }));
  return xdr.ScVal.scvMap(entries);
}

/** Encode an `EscrowInput` as the Soroban `Escrow` struct ScVal. */
export function buildEscrowScVal(input: EscrowInput): xdr.ScVal {
  return struct({
    engagement_id: str(input.engagementId),
    title: str(input.title),
    roles: struct({
      approver: addrVal(input.roles.approver),
      service_provider: addrVal(input.roles.serviceProvider),
      platform: addrVal(input.roles.platform),
      release_signer: addrVal(input.roles.releaseSigner),
      dispute_resolver: addrVal(input.roles.disputeResolver),
      receiver: addrVal(input.roles.receiver),
    }),
    description: str(input.description),
    amount: nativeToScVal(input.amount, { type: "i128" }),
    platform_fee: u32(input.platformFeeBps),
    milestones: xdr.ScVal.scvVec(
      input.milestones.map((m) =>
        struct({
          description: str(m.description),
          status: str(m.status ?? "pending"),
          evidence: str(m.evidence ?? ""),
          approved: boolVal(m.approved ?? false),
        }),
      ),
    ),
    flags: struct({ disputed: boolVal(false), released: boolVal(false), resolved: boolVal(false) }),
    trustline: struct({ address: addrVal(input.trustline) }),
    receiver_memo: u32(input.receiverMemo ?? 0),
  });
}

/**
 * Deploy + initialize a fresh escrow instance through a Trustless Work factory
 * contract (`tw_new_single_release_escrow`), signed by a Cavos account. Returns
 * the deployed escrow contract address. This is TW's production pattern: one
 * factory spawns an independent escrow per engagement.
 */
export async function deployEscrow(
  wallet: CavosStellar,
  params: {
    factoryId: string;
    wasmHash: string;
    adapter: StellarAdapter;
    escrow: EscrowInput;
    opts?: ExecuteOptions;
  },
): Promise<{ escrowId: string; txHash: string }> {
  const salt = secureRandomBytes(32);
  const txHash = await wallet.invokeContract({
    contractId: params.factoryId,
    method: "tw_new_single_release_escrow",
    args: [
      new Address(wallet.address).toScVal(),
      xdr.ScVal.scvBytes(Buffer.from(params.wasmHash, "hex")),
      xdr.ScVal.scvBytes(Buffer.from(salt)),
      sym("initialize_escrow"),
      xdr.ScVal.scvVec([buildEscrowScVal(params.escrow)]),
      xdr.ScVal.scvVec([]),
    ],
    opts: params.opts,
  });
  const result = (await params.adapter.transactionResult(txHash)) as unknown[];
  const escrowId = Array.isArray(result) ? String(result[0]) : "";
  if (!escrowId) throw new Error("kit/tw: factory did not return a deployed address");
  return { escrowId, txHash };
}
