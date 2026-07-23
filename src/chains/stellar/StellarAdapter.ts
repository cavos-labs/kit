import {
  Account,
  Asset,
  BASE_FEE,
  Config,
  Contract,
  Horizon,
  Keypair,
  Operation,
  TransactionBuilder,
  rpc,
  scValToNative,
  type Transaction,
  type FeeBumpTransaction,
  type xdr,
} from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import { HORIZON_URL, SOROBAN_RPC_URL, STELLAR_NETWORKS, type StellarNetwork } from "./constants";
import { toDataEntries, type AccountEnvelope } from "./datamap";

export interface StellarAdapterOptions {
  network: StellarNetwork;
  /** Horizon URL override (else the per-network default). */
  horizonUrl?: string;
  /** Soroban RPC URL override (else the per-network default). Only used for
   *  contract invocation; classic account state/pay still goes through Horizon. */
  rpcUrl?: string;
  /** Per-request network timeout (ms) for Horizon/RPC calls. Without this the
   *  Stellar SDK's axios client never aborts, so a slow/stalled Horizon hangs
   *  `loadAccount` forever — which surfaces as the login stuck on "Setting up
   *  your account". Defaults to 20s. */
  requestTimeoutMs?: number;
}

/** How long a built transaction stays valid before it must be rebuilt. */
const TX_TIMEOUT = 180;

/** Default per-request timeout for Horizon/RPC reads and submits. */
const DEFAULT_REQUEST_TIMEOUT_MS = 20_000;

/**
 * Classic-Stellar (`G…`) multisig account adapter.
 *
 * Unlike the Soroban `StellarAdapter` (contract `C…` accounts authorized by a
 * `__check_auth` device signature) this operates on a *classic* account whose
 * signing is ordinary ed25519 multisig:
 *
 *   - the **master** key (deterministic from identity) names the `G…` address and
 *     is set to weight 0 at creation — powerless afterwards;
 *   - the **control** key (random, weight 1, thresholds 1) is the real signer,
 *     recovered by decrypting the on-chain envelope (see `envelope.ts`).
 *
 * The adapter builds/read classic transactions and account state via Horizon; it
 * never holds a secret — callers pass in the `Keypair`s to sign with. Gasless
 * submission is a fee-bump whose fee source is the relayer (Phase 3).
 */
export class StellarAdapter {
  readonly chain = "stellar" as const;
  readonly network: StellarNetwork;
  readonly passphrase: string;
  private readonly horizonUrl: string;
  private readonly rpcUrl: string;
  private readonly requestTimeoutMs: number;
  private _server?: Horizon.Server;
  private _rpc?: rpc.Server;

  constructor(opts: StellarAdapterOptions) {
    this.network = opts.network;
    this.passphrase = STELLAR_NETWORKS[opts.network].passphrase;
    this.horizonUrl = opts.horizonUrl ?? HORIZON_URL[opts.network];
    this.rpcUrl = opts.rpcUrl ?? SOROBAN_RPC_URL[opts.network];
    this.requestTimeoutMs = opts.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
    // Horizon's Server.Options has no per-instance `timeout`; the SDK exposes it
    // only through the global Config. Without it, a stalled Horizon hangs
    // `loadAccount` forever (login stuck on "Setting up your account").
    if (this.requestTimeoutMs > 0) Config.setTimeout(this.requestTimeoutMs);
  }

  server(): Horizon.Server {
    if (!this._server) {
      this._server = new Horizon.Server(this.horizonUrl, {
        allowHttp: this.horizonUrl.startsWith("http://"),
      });
    }
    return this._server;
  }

  /** Soroban RPC server (lazily created). Used for contract simulation + submit. */
  rpc(): rpc.Server {
    if (!this._rpc) {
      this._rpc = new rpc.Server(this.rpcUrl, {
        allowHttp: this.rpcUrl.startsWith("http://"),
        timeout: this.requestTimeoutMs,
      });
    }
    return this._rpc;
  }

  /** Whether the classic account already exists on-chain. */
  async isDeployed(address: string): Promise<boolean> {
    try {
      await this.server().loadAccount(address);
      return true;
    } catch (e) {
      if (isNotFound(e)) return false;
      throw e;
    }
  }

  /** Read the account's `MANAGE_DATA` entries as raw bytes (name → value). */
  async loadDataEntries(address: string): Promise<Record<string, Uint8Array>> {
    const account = await this.server().loadAccount(address);
    const out: Record<string, Uint8Array> = {};
    for (const [name, b64] of Object.entries(account.data_attr ?? {})) {
      out[name] = new Uint8Array(Buffer.from(b64 as string, "base64"));
    }
    return out;
  }

  /** Native XLM balance in stroops. Returns 0n if the account doesn't exist. */
  async balance(address: string): Promise<bigint> {
    try {
      const account = await this.server().loadAccount(address);
      const native = account.balances.find((b) => b.asset_type === "native");
      return native ? toStroops(native.balance) : 0n;
    } catch (e) {
      if (isNotFound(e)) return 0n;
      throw e;
    }
  }

  /**
   * Build the account-creation transaction (source = funder, the relayer or a
   * self-funded keypair):
   *   1. `createAccount` funds the deterministic `G…` master address,
   *   2. `manageData` writes the control-key envelope entries (authorized by the
   *      still-weight-1 master),
   *   3. `setOptions` adds the control signer (weight 1), sets all thresholds to
   *      1, and zeroes the master weight — after this the master can never sign.
   *
   * The returned tx must be signed by BOTH the master keypair (for the account's
   * own ops) and the funder (source + fee). Sponsorship of reserves is layered on
   * in Phase 3.
   */
  async buildCreateTx(params: {
    funder: string;
    masterAddress: string;
    controlAddress: string;
    envelope: AccountEnvelope;
    /** Starting balance in stroops (must cover base reserve + entries). */
    startingBalance: bigint;
  }): Promise<Transaction> {
    const funderAccount = await this.server().loadAccount(params.funder);
    const builder = new TransactionBuilder(funderAccount, {
      fee: BASE_FEE,
      networkPassphrase: this.passphrase,
    });

    builder.addOperation(
      Operation.createAccount({
        destination: params.masterAddress,
        startingBalance: fromStroops(params.startingBalance),
      }),
    );

    for (const [name, value] of Object.entries(toDataEntries(params.envelope))) {
      builder.addOperation(
        Operation.manageData({ name, value: Buffer.from(value), source: params.masterAddress }),
      );
    }

    builder.addOperation(
      Operation.setOptions({
        source: params.masterAddress,
        masterWeight: 0,
        lowThreshold: 1,
        medThreshold: 1,
        highThreshold: 1,
        signer: { ed25519PublicKey: params.controlAddress, weight: 1 },
      }),
    );

    return builder.setTimeout(TX_TIMEOUT).build();
  }

  /**
   * Build a **sponsored** account-creation transaction whose source is the
   * relayer. Wraps the account setup in `beginSponsoringFutureReserves` /
   * `endSponsoringFutureReserves`, so the relayer (not the user) pays every
   * reserve — the account is created with a 0 starting balance and holds no
   * locked XLM of the user's. Ops:
   *   0. beginSponsoringFutureReserves(G)          source = relayer
   *   1. createAccount(G, 0)                        source = relayer
   *   2. manageData(cv:… envelope)                  source = G (master-signed)
   *   3. setOptions(control signer, master → 0)     source = G
   *   4. endSponsoringFutureReserves()              source = G
   *
   * Signed by the master (for the G ops, while it's still weight 1); the relayer
   * co-signs (source + fee + sponsorship) before submitting.
   */
  async buildSponsoredCreateTx(params: {
    relayer: string;
    masterAddress: string;
    controlAddress: string;
    envelope: AccountEnvelope;
  }): Promise<Transaction> {
    const relayerAccount = await this.server().loadAccount(params.relayer);
    const builder = new TransactionBuilder(relayerAccount, {
      fee: BASE_FEE,
      networkPassphrase: this.passphrase,
    });

    builder.addOperation(
      Operation.beginSponsoringFutureReserves({ sponsoredId: params.masterAddress, source: params.relayer }),
    );
    builder.addOperation(
      Operation.createAccount({ destination: params.masterAddress, startingBalance: "0", source: params.relayer }),
    );
    for (const [name, value] of Object.entries(toDataEntries(params.envelope))) {
      builder.addOperation(
        Operation.manageData({ name, value: Buffer.from(value), source: params.masterAddress }),
      );
    }
    builder.addOperation(
      Operation.setOptions({
        source: params.masterAddress,
        masterWeight: 0,
        lowThreshold: 1,
        medThreshold: 1,
        highThreshold: 1,
        signer: { ed25519PublicKey: params.controlAddress, weight: 1 },
      }),
    );
    builder.addOperation(Operation.endSponsoringFutureReserves({ source: params.masterAddress }));

    return builder.setTimeout(TX_TIMEOUT).build();
  }

  /**
   * Build a classic native-XLM payment as an *inner* transaction whose source is
   * the account itself (`G…`), signed by the control key. Wrap it in a fee-bump
   * (see `wrapFeeBump`) so the relayer pays the fee — gasless.
   */
  async buildPaymentTx(params: {
    from: string;
    to: string;
    /** Amount in stroops. */
    amount: bigint;
  }): Promise<Transaction> {
    const source = await this.server().loadAccount(params.from);
    return new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(
        Operation.payment({
          destination: params.to,
          asset: Asset.native(),
          amount: fromStroops(params.amount),
        }),
      )
      .setTimeout(TX_TIMEOUT)
      .build();
  }

  /**
   * Build a data-entry write (e.g. re-wrapping the DEK for a newly approved
   * device) as an inner tx sourced by the account, signed by the control key.
   */
  async buildDataTx(params: { account: string; entries: Record<string, Uint8Array> }): Promise<Transaction> {
    const source = await this.server().loadAccount(params.account);
    const builder = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.passphrase });
    for (const [name, value] of Object.entries(params.entries)) {
      builder.addOperation(Operation.manageData({ name, value: Buffer.from(value) }));
    }
    return builder.setTimeout(TX_TIMEOUT).build();
  }

  /**
   * Build a **sponsored** data-entry write whose source is the relayer, so the
   * relayer (not the 0-balance account) pays the reserve of any NEW subentry.
   * Adding a factor (passkey / recovery) or a device slot creates a data entry
   * that needs ~0.5 XLM of reserve; a sponsored account holds no XLM, so — like
   * account creation — the write must be wrapped in begin/endSponsoringFuture
   * reserves with the relayer as sponsor. Ops:
   *   0. beginSponsoringFutureReserves(account)   source = relayer
   *   1..n. manageData(cv:…)                       source = account (control-signed)
   *   last. endSponsoringFutureReserves()          source = account
   *
   * Signed by the control key (account ops) + the relayer (source + fee + sponsor).
   */
  async buildSponsoredDataTx(params: {
    relayer: string;
    account: string;
    entries: Record<string, Uint8Array>;
  }): Promise<Transaction> {
    const relayerAccount = await this.server().loadAccount(params.relayer);
    const builder = new TransactionBuilder(relayerAccount, {
      fee: BASE_FEE,
      networkPassphrase: this.passphrase,
    });
    builder.addOperation(
      Operation.beginSponsoringFutureReserves({ sponsoredId: params.account, source: params.relayer }),
    );
    for (const [name, value] of Object.entries(params.entries)) {
      builder.addOperation(Operation.manageData({ name, value: Buffer.from(value), source: params.account }));
    }
    builder.addOperation(Operation.endSponsoringFutureReserves({ source: params.account }));
    return builder.setTimeout(TX_TIMEOUT).build();
  }

  /**
   * Build a `changeTrust` inner tx (account-sourced, control-signed) that opens a
   * trustline to a classic asset like USDC — required before the account can hold
   * or receive that token (e.g. to fund a Trustless Work escrow in USDC).
   */
  async buildChangeTrustTx(params: {
    account: string;
    asset: { code: string; issuer: string };
    /** Trustline limit as a 7-dp string; omit for the SDK max. */
    limit?: string;
  }): Promise<Transaction> {
    const source = await this.server().loadAccount(params.account);
    return new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(
        Operation.changeTrust({
          asset: new Asset(params.asset.code, params.asset.issuer),
          limit: params.limit,
        }),
      )
      .setTimeout(TX_TIMEOUT)
      .build();
  }

  /**
   * Build a **sponsored** `changeTrust`: a trustline adds a subentry (~0.5 XLM
   * reserve), so a 0-balance sponsored account can't open one via a plain
   * fee-bump. Wrap it in begin/endSponsoringFutureReserves with the relayer as
   * sponsor + source, exactly like `buildSponsoredDataTx`. Signed by the control
   * key (account op) + the relayer (source + fee + sponsor).
   */
  async buildSponsoredChangeTrustTx(params: {
    relayer: string;
    account: string;
    asset: { code: string; issuer: string };
    limit?: string;
  }): Promise<Transaction> {
    const relayerAccount = await this.server().loadAccount(params.relayer);
    return new TransactionBuilder(relayerAccount, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(
        Operation.beginSponsoringFutureReserves({ sponsoredId: params.account, source: params.relayer }),
      )
      .addOperation(
        Operation.changeTrust({
          asset: new Asset(params.asset.code, params.asset.issuer),
          limit: params.limit,
          source: params.account,
        }),
      )
      .addOperation(Operation.endSponsoringFutureReserves({ source: params.account }))
      .setTimeout(TX_TIMEOUT)
      .build();
  }

  /** A classic token balance (e.g. USDC) in its native decimals as a string, or
   *  "0" if the account holds no trustline to that asset. */
  async tokenBalance(address: string, asset: { code: string; issuer: string }): Promise<string> {
    try {
      const account = await this.server().loadAccount(address);
      const bal = account.balances.find(
        (b) =>
          (b.asset_type === "credit_alphanum4" || b.asset_type === "credit_alphanum12") &&
          b.asset_code === asset.code &&
          b.asset_issuer === asset.issuer,
      );
      return bal ? bal.balance : "0";
    } catch (e) {
      if (isNotFound(e)) return "0";
      throw e;
    }
  }

  /** Wrap a control-signed inner tx in a fee-bump whose fee source is `feeSource`
   *  (the relayer). The inner tx pays nothing; the relayer pays all fees. */
  wrapFeeBump(inner: Transaction, feeSource: string): FeeBumpTransaction {
    return TransactionBuilder.buildFeeBumpTransaction(feeSource, BASE_FEE, inner, this.passphrase);
  }

  /** Submit a fully-signed classic transaction and return its hash. Throws with
   *  the Horizon result codes on failure. */
  async submit(tx: Transaction | FeeBumpTransaction): Promise<string> {
    try {
      const res = await this.server().submitTransaction(tx);
      return res.hash;
    } catch (e) {
      throw new Error(`kit/stellar: submit failed: ${horizonError(e)}`);
    }
  }

  /**
   * Build a Soroban contract-invocation transaction, sourced by the user's `G…`,
   * and run it through `prepareTransaction` (simulate → assemble footprint +
   * resource fees + soroban auth entries). The returned tx is UNSIGNED and ready
   * for the caller to (a) sign the auth entries whose credential address is the
   * user, then (b) sign the tx envelope. See `CavosStellar.invokeContract`.
   *
   * `args` must already be `xdr.ScVal`s (use `nativeToScVal`/`Address.toScVal`).
   */
  async buildInvokeTx(params: {
    from: string;
    contractId: string;
    method: string;
    args: xdr.ScVal[];
  }): Promise<Transaction> {
    const source = await this.rpc().getAccount(params.from);
    const contract = new Contract(params.contractId);
    const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(contract.call(params.method, ...params.args))
      .setTimeout(TX_TIMEOUT)
      .build();
    return this.rpc().prepareTransaction(tx) as Promise<Transaction>;
  }

  /** Submit a fully-signed Soroban tx via the RPC and poll until it leaves
   *  `PENDING`. Returns the tx hash on success; throws on failure. */
  async submitSoroban(tx: Transaction | FeeBumpTransaction): Promise<string> {
    const sent = await this.rpc().sendTransaction(tx);
    if (sent.status === "ERROR") {
      throw new Error(`kit/stellar: soroban send failed: ${JSON.stringify(sent.errorResult)}`);
    }
    for (let i = 0; i < 30; i++) {
      const got = await this.rpc().getTransaction(sent.hash);
      if (got.status === "SUCCESS") return sent.hash;
      if (got.status === "FAILED") {
        throw new Error(`kit/stellar: soroban tx failed: ${JSON.stringify(got.resultXdr)}`);
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`kit/stellar: soroban tx ${sent.hash} not confirmed in time`);
  }

  /** The current ledger sequence — used to bound Soroban auth-entry validity. */
  async latestLedger(): Promise<number> {
    return (await this.rpc().getLatestLedger()).sequence;
  }

  /**
   * Read-only contract call: simulate `method(args)` and return the decoded
   * native result. No account, signing, or submission — for view functions like
   * the escrow's `get_escrow`. `from` only sources the simulation (any funded or
   * even the deployer address works).
   */
  async readContract(params: {
    from: string;
    contractId: string;
    method: string;
    args?: xdr.ScVal[];
  }): Promise<unknown> {
    const source = await this.rpc().getAccount(params.from);
    const contract = new Contract(params.contractId);
    const tx = new TransactionBuilder(source, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(contract.call(params.method, ...(params.args ?? [])))
      .setTimeout(TX_TIMEOUT)
      .build();
    const sim = await this.rpc().simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`kit/stellar: read ${params.method} failed: ${sim.error}`);
    }
    const retval = sim.result?.retval;
    return retval ? scValToNative(retval) : undefined;
  }

  /** Decode the return value of a submitted Soroban tx (e.g. the factory's
   *  deployed escrow address). Polls until the tx is visible. */
  async transactionResult(hash: string): Promise<unknown> {
    for (let i = 0; i < 30; i++) {
      const got = await this.rpc().getTransaction(hash);
      if (got.status === "SUCCESS") {
        const ret = (got as { returnValue?: xdr.ScVal }).returnValue;
        return ret ? scValToNative(ret) : undefined;
      }
      if (got.status === "FAILED") throw new Error(`kit/stellar: tx ${hash} failed`);
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`kit/stellar: tx ${hash} not visible in time`);
  }

  /** Build an `Account` handle for a known address + sequence (avoids a Horizon
   *  round-trip when the caller already has the sequence). */
  accountAt(address: string, sequence: string): Account {
    return new Account(address, sequence);
  }
}

function isNotFound(e: unknown): boolean {
  const status = (e as { response?: { status?: number }; status?: number })?.response?.status ??
    (e as { status?: number })?.status;
  return status === 404;
}

function horizonError(e: unknown): string {
  const codes = (e as { response?: { data?: { extras?: { result_codes?: unknown } } } })?.response?.data?.extras
    ?.result_codes;
  return codes ? JSON.stringify(codes) : String((e as Error)?.message ?? e);
}

/** 7-dp XLM string → stroops (integer). */
function toStroops(amount: string): bigint {
  const [whole, frac = ""] = amount.split(".");
  const fracPadded = (frac + "0000000").slice(0, 7);
  return BigInt(whole) * 10_000_000n + BigInt(fracPadded);
}

/** Stroops → 7-dp XLM string (the stellar-sdk amount format). */
function fromStroops(stroops: bigint): string {
  const neg = stroops < 0n;
  const abs = neg ? -stroops : stroops;
  const whole = abs / 10_000_000n;
  const frac = (abs % 10_000_000n).toString().padStart(7, "0");
  return `${neg ? "-" : ""}${whole}.${frac}`;
}

/** Sign helpers — the adapter never holds keys, so signing is done by callers,
 *  but these keep the (control/master) signing idiom in one place. */
export function signWith(tx: Transaction, ...keypairs: Keypair[]): Transaction {
  tx.sign(...keypairs);
  return tx;
}
