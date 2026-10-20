import { CallData, Signer, hash, num, type Call, type TypedData } from "starknet";
import type {
  PrivateTransfersBuilder,
  ProofProviderConfig,
  TokenOperationsBuilder,
} from "@starkware-libs/starknet-privacy-sdk";
import { viewingPublicKey, deriveViewingKey } from "../viewingKey";
import {
  DEFAULT_POLL,
  PROOF_BASE_BLOCK_DEPTH,
  assertProofFresh,
  provableBlock,
  rpcChain,
  type PollOptions,
  type PrivacyChain,
} from "./chain";
import type { PrivacyFeeMode, StarknetPrivacyConfig } from "./config";
import { PrivacyRelay, type FeeAction, type RelayCall } from "./relay";
import type { PrivacySdk } from "./sdk";

export type PrivacyRequirement = "register" | "setup-channel" | "setup-token" | "ready";

export interface PrivacyStatus {
  /** The pool holds a viewing key for this account. */
  registered: boolean;
  /** What the account still needs before it can use `token`. Only present when a token was asked about. */
  requirement?: PrivacyRequirement;
}

export interface PrivacySubmission {
  transactionHash: string;
}

/** The only operations a private account offers. No method returns a key, a note or a witness. */
export interface PrivacyOperations {
  status(token?: string): Promise<PrivacyStatus>;
  balance(token: string): Promise<bigint>;
  register(): Promise<PrivacySubmission>;
  deposit(token: string, amount: bigint): Promise<PrivacySubmission>;
  transfer(token: string, recipient: string, amount: bigint): Promise<PrivacySubmission>;
  withdraw(token: string, recipient: string, amount: bigint): Promise<PrivacySubmission>;
}

type Sdk = PrivacySdk;
type TransfersClient = ReturnType<Sdk["createPrivateTransfers"]>;
type Registry = ReturnType<Sdk["createEmptyRegistry"]>;
type CreateParams = Parameters<Sdk["createPrivateTransfers"]>[0];

/** Replaceable pieces, for tests that run against the SDK's in-memory pool. */
export interface PrivacySessionDeps {
  chain?: PrivacyChain;
  sdk?: PrivacySdk;
  provingProvider?: CreateParams["provingProvider"];
  discoveryProvider?: CreateParams["discoveryProvider"];
  proofInvocationFactory?: CreateParams["proofInvocationFactory"];
  fetch?: typeof fetch;
  poll?: PollOptions;
}

export interface PrivacySessionInit {
  config: StarknetPrivacyConfig;
  /** Felt of the chain the account lives on. */
  chainId: string;
  /** RPC used when the config names none. */
  rpcUrl: string;
  account: { address: string; spend: { privateKey(): string } };
  paymasterApiKey: () => string;
  /** Loads the privacy SDK. Injected so that only builds that bundle it name the package. */
  loadSdk: () => Promise<PrivacySdk>;
  deps?: PrivacySessionDeps;
}

const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
const SPONSOR_FEE: PrivacyFeeMode = { mode: "sponsored", pool_fee: { paid_by: "sponsor" } };
const REQUIREMENTS: PrivacyRequirement[] = ["register", "setup-channel", "setup-token", "ready"];

interface Operation {
  fee: PrivacyFeeMode;
  invoke?: { token: string; amount: bigint };
  autoRegister?: boolean;
  compose(builder: PrivateTransfersBuilder, fee: FeeAction | null): void;
}

/**
 * One account's private state in one pool. It lives only where the account key
 * lives: the viewing key, the discovered notes and the witnesses are held here
 * and never returned.
 */
export class PrivacySession implements PrivacyOperations {
  private readonly config: StarknetPrivacyConfig;
  private readonly address: string;
  private readonly chain: PrivacyChain;
  private readonly poll: PollOptions;
  private readonly relay: PrivacyRelay;
  private viewingKey?: string;
  private transfers?: Promise<TransfersClient>;
  private registry?: Registry;
  private lastTransaction?: string;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly init: PrivacySessionInit) {
    this.config = init.config;
    this.address = init.account.address;
    this.chain = init.deps?.chain ?? rpcChain(init.config.rpcUrl ?? init.rpcUrl);
    this.poll = init.deps?.poll ?? DEFAULT_POLL;
    this.relay = new PrivacyRelay({
      url: init.config.relay.url,
      apiKey: init.paymasterApiKey,
      maxFee: BigInt(init.config.relay.maxFee),
      allowedFeeRecipients: init.config.relay.allowedFeeRecipients,
      publishedFee: async () => {
        const [fee] = await this.chain.call(this.config.pool, "get_fee_amount");
        return BigInt(fee ?? "0");
      },
      publishedFeeToken: STRK,
      ...(init.deps?.fetch ? { fetch: init.deps.fetch } : {}),
    });
  }

  async status(token?: string): Promise<PrivacyStatus> {
    return this.scrubbed(async () => {
      const registered = await this.registered();
      if (token === undefined) return { registered };
      const transfers = await this.client();
      const requirement = await transfers.discoverRequirement(this.address, requireAddress(token, "token"));
      return { registered, requirement: REQUIREMENTS[requirement] ?? "ready" };
    });
  }

  async balance(token: string): Promise<bigint> {
    return this.scrubbed(async () => {
      const id = BigInt(requireAddress(token, "token"));
      if (!(await this.registered())) return 0n;
      const transfers = await this.client();
      const { notes } = await transfers.discoverNotes({ tokens: [id] });
      return (notes.get(id) ?? []).reduce((total, note) => total + note.amount, 0n);
    });
  }

  async register(): Promise<PrivacySubmission> {
    return this.run(async () => {
      if (await this.registered()) throw new Error("kit/starknet: this account is already registered in the pool");
      if (this.config.relay.fee.mode !== "sponsored") {
        throw new Error("kit/starknet: this app does not sponsor private transfers, so the first deposit registers the account");
      }
      return { fee: SPONSOR_FEE, compose: (builder) => void builder.register() };
    });
  }

  async deposit(token: string, amount: bigint): Promise<PrivacySubmission> {
    const id = requireAddress(token, "token");
    requireAmount(amount);
    return this.run(async () => ({
      fee: this.config.relay.fee,
      invoke: { token: id, amount },
      autoRegister: true,
      compose: (builder, fee) =>
        this.withToken(builder, id, fee, (t) => t.deposit({ amount }).surplusTo(this.address, false)),
    }));
  }

  async transfer(token: string, recipient: string, amount: bigint): Promise<PrivacySubmission> {
    const id = requireAddress(token, "token");
    const to = requireAddress(recipient, "recipient");
    requireAmount(amount);
    return this.run(async () => ({
      fee: this.config.relay.fee,
      compose: (builder, fee) =>
        this.withToken(builder, id, fee, (t) => t.transfer({ recipient: to, amount }).surplusTo(this.address, false)),
    }));
  }

  async withdraw(token: string, recipient: string, amount: bigint): Promise<PrivacySubmission> {
    const id = requireAddress(token, "token");
    const to = requireAddress(recipient, "recipient");
    requireAmount(amount);
    return this.run(async () => ({
      fee: this.config.relay.fee,
      compose: (builder, fee) =>
        this.withToken(builder, id, fee, (t) => t.withdraw({ recipient: to, amount }).surplusTo(this.address, false)),
    }));
  }

  private withToken(
    builder: PrivateTransfersBuilder,
    token: string,
    fee: FeeAction | null,
    operate: (t: TokenOperationsBuilder) => unknown,
  ): void {
    const charge = fee && fee.amount > 0n ? fee : null;
    const sameToken = charge !== null && BigInt(charge.token) === BigInt(token);
    builder.with(token, (t) => {
      operate(t);
      if (sameToken) t.withdraw({ recipient: charge.recipient, amount: charge.amount });
    });
    if (charge && !sameToken) {
      builder.with(charge.token, (t) => t.withdraw({ recipient: charge.recipient, amount: charge.amount }));
    }
  }

  private run(plan: () => Promise<Operation>): Promise<PrivacySubmission> {
    const result = this.queue.then(() => this.scrubbed(async () => this.submit(await plan())));
    this.queue = result.then(
      () => undefined,
      () => undefined,
    );
    return result;
  }

  private async submit(operation: Operation): Promise<PrivacySubmission> {
    await this.registered();
    const transfers = await this.client();
    const invoke = operation.invoke ? this.approval(operation.invoke) : undefined;
    const quote = await this.relay.quote(this.config.pool, operation.fee, invoke);

    let approval: { userAddress: string; typedData: TypedData; signature: Awaited<ReturnType<Signer["signMessage"]>> } | undefined;
    if (invoke && quote.typedData) {
      approval = {
        userAddress: this.address,
        typedData: quote.typedData,
        signature: await new Signer(this.init.account.spend.privateKey()).signMessage(quote.typedData, this.address),
      };
    }

    const provingBlockId = await this.provingBlock();
    this.registry ??= (await this.sdk()).createEmptyRegistry();
    this.registry.notes.clear();
    const builder = transfers.build({
      autoSelectNotes: "naive",
      autoSetup: true,
      autoDiscover: { notes: "refresh", channels: "refresh" },
      ...(operation.autoRegister ? { autoRegister: true } : {}),
      registry: this.registry,
      provingBlockId,
    });
    operation.compose(builder, quote.feeAction);

    try {
      const { callAndProof, registry } = await builder.execute();
      this.registry = registry;
      await assertProofFresh(this.chain, this.config.pool, callAndProof.proof.proofFacts);
      const submission = await this.relay.execute(
        toRelayCall(callAndProof.call),
        { data: callAndProof.proof.data, proofFacts: callAndProof.proof.proofFacts },
        quote.parameters,
        approval,
      );
      this.lastTransaction = submission.transactionHash;
      return submission;
    } catch (error) {
      transfers.invalidateProofNonceCache();
      throw error;
    }
  }

  private approval(spec: { token: string; amount: bigint }): { userAddress: string; chainId: string; calls: RelayCall[] } {
    const low = spec.amount & ((1n << 128n) - 1n);
    const high = spec.amount >> 128n;
    const call: Call = {
      contractAddress: spec.token,
      entrypoint: "approve",
      calldata: [this.config.pool, `0x${low.toString(16)}`, `0x${high.toString(16)}`],
    };
    return { userAddress: this.address, chainId: this.init.chainId, calls: [toRelayCall(call)] };
  }

  private async provingBlock(): Promise<number> {
    const previous = this.lastTransaction ? await this.chain.confirm(this.lastTransaction, this.poll) : -1;
    return provableBlock(this.chain, previous, this.poll, PROOF_BASE_BLOCK_DEPTH);
  }

  /** Reads the registered key and refuses to go on when it is not the one this account derives: a replacement is never registered. */
  private async registered(): Promise<boolean> {
    const mine = BigInt(viewingPublicKey(this.derived()));
    const [stored] = await this.chain.call(this.config.pool, "get_public_key", [this.address]);
    const key = BigInt(stored ?? "0");
    if (key === 0n) return false;
    if (key !== mine) {
      throw new Error(
        "kit/starknet: this account is registered in the pool with a different viewing key. Cavos will not register a replacement; the private balance stays reachable only with the original key.",
      );
    }
    return true;
  }

  private derived(): string {
    this.viewingKey ??= deriveViewingKey(this.init.account.spend.privateKey(), {
      chainId: this.init.chainId,
      accountAddress: this.address,
      poolAddress: this.config.pool,
    });
    return this.viewingKey;
  }

  private sdk(): Promise<PrivacySdk> {
    return this.init.deps?.sdk ? Promise.resolve(this.init.deps.sdk) : this.init.loadSdk();
  }

  private client(): Promise<TransfersClient> {
    this.transfers ??= this.createClient().catch((error: unknown) => {
      this.transfers = undefined;
      throw error;
    });
    return this.transfers;
  }

  private async createClient(): Promise<TransfersClient> {
    const sdk = await this.sdk();
    const deps = this.init.deps;
    const ohttp = this.config.ohttp ?? true;
    const chainId = this.init.chainId as ProofProviderConfig["chainId"];
    const params: CreateParams = {
      account: {
        address: this.address,
        signer: new Signer(this.init.account.spend.privateKey()) as unknown as CreateParams["account"]["signer"],
      },
      viewingKeyProvider: { getViewingKey: async () => this.derived() },
      provingProvider: deps?.provingProvider ?? {
        url: this.config.prover,
        chainId,
        nodeUrl: this.config.rpcUrl ?? this.init.rpcUrl,
        ...(ohttp ? { ohttp: true } : {}),
      },
      discoveryProvider:
        deps?.discoveryProvider ??
        new sdk.IndexerDiscoveryProvider(this.config.discovery, this.config.pool, ohttp ? { ohttp: true } : {}),
      poolContractAddress: this.config.pool,
      ...(deps?.proofInvocationFactory ? { proofInvocationFactory: deps.proofInvocationFactory } : {}),
    };
    return sdk.createPrivateTransfers(params);
  }

  private async scrubbed<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (error) {
      throw this.redact(error);
    }
  }

  private redact(error: unknown): Error {
    const secrets = [this.viewingKey, this.init.account.spend.privateKey()].filter((value): value is string => Boolean(value));
    let message = error instanceof Error ? error.message : String(error);
    for (const secret of secrets) {
      const bare = BigInt(secret).toString(16);
      message = message.split(secret).join("[redacted]").replace(new RegExp(bare, "gi"), "[redacted]");
    }
    return new Error(message);
  }
}

function toRelayCall(call: Call): RelayCall {
  return {
    to: call.contractAddress,
    selector: /^0x[0-9a-f]+$/i.test(call.entrypoint) ? call.entrypoint : hash.getSelectorFromName(call.entrypoint),
    calldata: CallData.compile(call.calldata ?? []).map((felt) => num.toHex(felt)),
  };
}

function requireAddress(value: string, field: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value) || BigInt(value) === 0n) {
    throw new Error(`kit/starknet: ${field} must be a 0x-prefixed Starknet address`);
  }
  return value;
}

function requireAmount(amount: bigint): void {
  if (typeof amount !== "bigint" || amount <= 0n) throw new Error("kit/starknet: amount must be a positive number of base units");
}

export function createPrivacySession(init: PrivacySessionInit): PrivacySession {
  return new PrivacySession(init);
}

/** Stands in for the operations when nothing can run them, so every call says why. */
export function unavailablePrivacy(reason: string): PrivacyOperations {
  const refuse = async (): Promise<never> => {
    throw new Error(reason);
  };
  return { status: refuse, balance: refuse, register: refuse, deposit: refuse, transfer: refuse, withdraw: refuse };
}
