import {
  Connection,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
} from "@solana/web3.js";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import type { DevicePublicKey } from "../../signer/DeviceSigner";
import type { WalletRegistry } from "../../registry/WalletRegistry";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { appNamespace } from "../../identity";
import { SolanaRelayer } from "./SolanaRelayer";
import { SOLANA_NETWORKS, type SolanaNetwork } from "./constants";
import type { PasskeyApprover, PasskeyEnrollParams, PasskeyPrfProvider } from "../../signer/PasskeyProvider";
import { resolveFeeMode, type ExecuteOptions } from "../../chains/ChainAdapter";
import { utf8ToBytes } from "../../crypto/encoding";
import type { MessageSignature, SolanaSignedTransaction } from "../../signing";
import type { SocialRecoveryClient } from "../../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import type { Ed25519Seed } from "../../secret/dek";
import type { Ed25519SpendSigner } from "../../signer/Ed25519SpendSigner";
import { resolveNativeSolana } from "./nativeConnect";
import { TollClient } from "./TollClient";
import { associatedTokenAddress, transferCheckedInstruction } from "./spl";
import { passkeyRestoreInput } from "../../secret/nativeAccount";
import { connectThroughVault, vaultConnectParams, type VaultClient } from "../../vault/VaultClient";

export interface InstructionAccount {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

export interface InstructionData {
  programId: string;
  accounts: InstructionAccount[];
  data: Uint8Array;
}

export interface ConnectSolanaOptions {
  network: SolanaNetwork;
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  environment?: "development" | "production";
  backendUrl?: string;
  registry?: WalletRegistry;
  rpcUrl?: string;
  relayer?: SolanaRelayer;
  /** Pays fees in a token the user already holds. See `fee: { token }`. */
  toll?: TollClient;
  credential?: SocialRecoveryCredential;
  socialRecovery?: SocialRecoveryClient;
  recovery?: EnclaveDekPort;
  factor?: DeviceFactor;
  wrapStore?: WrapStore;
  importSpend?: (seed: Ed25519Seed, keyId: string) => Promise<Ed25519SpendSigner>;
  passkey?: PasskeyPrfProvider;
  /** Keep the key in the Cavos vault instead of this page's storage. */
  vault?: VaultClient;
}

export type ConnectStatus = "undeployed" | "ready" | "needs-device-approval";

/** @deprecated Native Solana restores via connect, not backup add_signer. */
export type RecoverSolanaOptions = ConnectSolanaOptions;

/**
 * Native Ed25519 system account. The address is HKDF of the MasterDEK.
 * There is no device-account program and no second on-chain spender.
 */
export class CavosSolana {
  readonly chain = "solana" as const;
  readonly identity: Identity;
  readonly address: string;
  readonly connection: Connection;
  pendingRequestId: string | null = null;
  isNewAccount = false;
  onAuthorizationNeeded?: () => Promise<void>;
  private statusValue: ConnectStatus;
  private readonly relayer?: SolanaRelayer;
  private readonly toll?: TollClient;
  private readonly spend?: Ed25519SpendSigner;
  private readonly passkeyRestore: boolean;
  private readonly statusListeners = new Set<() => void>();

  /**
   * An object, not positions: this list grows with every capability, and each
   * time it grew positionally something downstream silently read the wrong
   * argument.
   */
  private constructor(init: {
    identity: Identity;
    address: string;
    status: ConnectStatus;
    connection: Connection;
    relayer?: SolanaRelayer;
    toll?: TollClient;
    spend?: Ed25519SpendSigner;
    restoredWithPasskey?: boolean;
  }) {
    this.identity = init.identity;
    this.address = init.address;
    this.statusValue = init.status;
    this.connection = init.connection;
    this.relayer = init.relayer;
    this.toll = init.toll;
    this.spend = init.spend;
    this.passkeyRestore = init.restoredWithPasskey ?? false;
  }

  get status(): ConnectStatus {
    return this.statusValue;
  }

  onStatusChange(listener: () => void): () => void {
    this.statusListeners.add(listener);
    return () => {
      this.statusListeners.delete(listener);
    };
  }

  private setStatus(next: ConnectStatus): void {
    if (this.statusValue === next) return;
    this.statusValue = next;
    for (const listener of this.statusListeners) {
      try {
        listener();
      } catch {
        /* a bad listener must not break the wallet */
      }
    }
  }

  /**
   * Always true. A native Ed25519 system account is not deployed — its address
   * IS its public key, so it exists the moment it is derived. Kept because the
   * shared wallet shape exposes it.
   */
  get isDeployed(): boolean {
    return true;
  }

  static async connect(opts: ConnectSolanaOptions): Promise<CavosSolana> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/solana: connect requires `identity` or `auth`");

    if (opts.network === "solana-mainnet" && !opts.rpcUrl) {
      console.warn(
        "[cavos] Using the public mainnet-beta RPC. Pass `rpcUrl` with your own " +
          "provider (Helius/Triton/QuickNode) for production — the public endpoint is rate-limited.",
      );
    }
    const connection = new Connection(opts.rpcUrl ?? SOLANA_NETWORKS[opts.network], "confirmed");
    const namespace = appNamespace({ appId: opts.appId ?? "local", environmentId: opts.environment });
    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({
            baseUrl: backendUrl,
            appId: opts.appId,
            network: opts.network,
            environment: opts.environment,
            authToken: () => opts.auth?.getAuthToken?.() ?? null,
          })
        : defaultRegistry);
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new SolanaRelayer({
            baseUrl: backendUrl,
            appId: opts.appId,
            network: opts.network,
            connection,
            environment: opts.environment,
          })
        : undefined);

    const native = opts.vault
      ? await connectThroughVault("solana", identity, opts.appSalt, () =>
          opts.vault!.connectSolana(vaultConnectParams({ ...opts, identity })),
        )
      : await resolveNativeSolana({
          identity,
          appSalt: opts.appSalt,
          registry,
          credential: opts.credential,
          socialRecovery: opts.socialRecovery,
          recovery: opts.recovery,
          factor: opts.factor,
          store: opts.wrapStore,
          importSpend: opts.importSpend,
          ...passkeyRestoreInput({
            passkey: opts.passkey,
            appId: opts.appId,
            backendUrl,
            environment: opts.environment,
            authToken: () => opts.auth?.getAuthToken?.() ?? null,
          }),
        });

    void namespace;
    void registry;
    const wallet = new CavosSolana({
      identity,
      address: native.address,
      status: native.spend ? "ready" : "needs-device-approval",
      connection,
      relayer,
      toll: opts.toll,
      spend: native.spend ?? undefined,
      // In the vault, `passkey` only lets it ask; whether one holds the key is its answer.
      restoredWithPasskey: "passkey" in native ? native.passkey === true : Boolean(opts.passkey),
    });
    wallet.isNewAccount = native.isNewAccount;
    return wallet;
  }

  async addSigner(_pubkey: DevicePublicKey): Promise<string> {
    throw new Error("kit/solana: a native account has one spend key");
  }

  async removeSigner(_pubkey: DevicePublicKey): Promise<string> {
    throw new Error("kit/solana: a native account has one spend key");
  }

  async pendingSocialRecovery(): Promise<null> {
    return null;
  }

  async pendingRecoveryIsForThisDevice(): Promise<boolean> {
    return false;
  }

  async enrollSocialRecovery(): Promise<{ transactionHash: string }> {
    throw new Error("kit/solana: native accounts enroll the DEK at connect");
  }

  async socialRecoveryNonce(): Promise<bigint> {
    throw new Error("kit/solana: native accounts have no on-chain recovery nonce");
  }

  async scheduleSocialRecovery(): Promise<{ transactionHash: string }> {
    throw new Error("kit/solana: native accounts restore by connecting");
  }

  async finalizeSocialRecovery(): Promise<{ transactionHash: string }> {
    throw new Error("kit/solana: native accounts restore by connecting");
  }

  async enrollPasskey(
    _passkey: PasskeyApprover,
    _params: PasskeyEnrollParams,
  ): Promise<{ publicKey: DevicePublicKey; transactionHash?: string }> {
    throw new Error("kit/solana: a passkey derives the spend key at connect; it is not an on-chain approver");
  }

  async addApprover(_pubkey: DevicePublicKey): Promise<{ transactionHash?: string }> {
    throw new Error("kit/solana: a native account has one spend key");
  }

  async isApprover(_pubkey: DevicePublicKey): Promise<boolean> {
    return false;
  }

  async hasPasskey(): Promise<boolean> {
    return this.passkeyRestore;
  }

  /**
   * Ready means one thing here: this device holds the spend key. There is no
   * on-chain signer set to wait for, so this resolves off-chain and never
   * flips back to false once the key is in hand.
   */
  async isReady(): Promise<boolean> {
    if (!this.spend) return false;
    this.setStatus("ready");
    return true;
  }

  async approveThisDeviceWithPasskey(_passkey: PasskeyApprover): Promise<string> {
    throw new Error("kit/solana: restore this device by connecting with your passkey");
  }

  async execute(amount: bigint, destination: string, opts?: ExecuteOptions): Promise<string> {
    const from = new PublicKey(this.address);
    const to = new PublicKey(destination);
    const ix = SystemProgram.transfer({
      fromPubkey: from,
      toPubkey: to,
      lamports: amount,
    });
    return this.sendNative([ix], opts);
  }

  async executeInstructions(instructions: InstructionData[], opts?: ExecuteOptions): Promise<string> {
    const ixs = instructions.map(
      (instruction) =>
        new TransactionInstruction({
          programId: new PublicKey(instruction.programId),
          keys: instruction.accounts.map((account) => ({
            pubkey: new PublicKey(account.pubkey),
            isSigner: account.isSigner,
            isWritable: account.isWritable,
          })),
          data: Buffer.from(instruction.data),
        }),
    );
    return this.sendNative(ixs, opts);
  }

  async signMessage(message: string | Uint8Array): Promise<MessageSignature> {
    const spend = this.requireSpend();
    const msgBytes = typeof message === "string" ? utf8ToBytes(message) : message;
    const signature = await spend.signMessage(msgBytes);
    return { signature, publicKey: spend.address(), curve: "ed25519" };
  }

  /**
   * Sign a transfer without submitting it. The account signs as its own fee
   * payer, matching the default `execute()` route — web3.js cannot compile a
   * message at all without a fee payer set.
   */
  async signTransaction(amount: bigint, destination: string): Promise<SolanaSignedTransaction> {
    const spend = this.requireSpend();
    const self = new PublicKey(this.address);
    const ix = SystemProgram.transfer({
      fromPubkey: self,
      toPubkey: new PublicKey(destination),
      lamports: amount,
    });
    const { blockhash } = await this.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
    tx.feePayer = self;
    tx.recentBlockhash = blockhash;
    tx.add(ix);
    const message = tx.serializeMessage();
    const signature = await spend.signTransaction(message);
    return { chain: "solana", message, signature, publicKey: spend.publicKeyRaw() };
  }

  async setupRecovery(_code: string): Promise<string | undefined> {
    return undefined;
  }

  private requireSpend(): Ed25519SpendSigner {
    if (!this.spend) throw new Error("kit/solana: this wallet has no native spend key");
    return this.spend;
  }

  /**
   * Three ways to pay, and the account signs its own transaction in all of them:
   *
   *   - `'self'` (default) → the account pays from its own SOL. It is a native
   *     Ed25519 system account, so it is signer and fee payer at once.
   *   - `'sponsored'`      → the Cavos relayer is fee payer and submits.
   *   - `{ token }`        → Toll is fee payer and settles in that token, paid
   *     from the account's own token balance in the same transaction.
   */
  private async sendNative(ixs: TransactionInstruction[], opts?: ExecuteOptions): Promise<string> {
    const spend = this.requireSpend();
    const mode = resolveFeeMode(opts, "self");
    const self = new PublicKey(this.address);

    if (typeof mode === "object") {
      return this.sendViaToll(ixs, mode.token, self, spend);
    }
    if (mode === "sponsored" && !this.relayer) {
      throw new Error("kit/solana: cannot sponsor — no relayer configured (set `appId`, or pass `relayer`)");
    }

    const payer = mode === "sponsored" ? await this.relayer!.getFeePayer() : self;
    const { blockhash, lastValidBlockHeight } = await this.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
    tx.feePayer = payer;
    tx.recentBlockhash = blockhash;
    tx.add(...ixs);
    const signature = await spend.signTransaction(tx.serializeMessage());
    tx.addSignature(self, Buffer.from(signature));

    if (mode === "sponsored") {
      return this.relayer!.sendSigned(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
    }
    // Self-funded: the account is the only signer AND the fee payer, so the
    // transaction is already complete — send it straight to the RPC.
    const raw = tx.serialize({ requireAllSignatures: true, verifySignatures: false });
    const txid = await this.connection.sendRawTransaction(raw, {
      preflightCommitment: "confirmed",
    });
    await this.connection.confirmTransaction({ signature: txid, blockhash, lastValidBlockHeight }, "confirmed");
    return txid;
  }

  /**
   * Quote first, because the amount owed has to be inside the message the user
   * signs — settling the fee and doing the thing are one transaction, so either
   * both happen or neither does.
   */
  private async sendViaToll(
    ixs: TransactionInstruction[],
    token: string,
    self: PublicKey,
    spend: Ed25519SpendSigner,
  ): Promise<string> {
    if (!this.toll) {
      throw new Error("kit/solana: cannot pay in a token — no `toll` client configured");
    }
    const quote = await this.toll.quote({ mint: token, instructions: ixs.length + 1 });
    const payment = transferCheckedInstruction({
      source: associatedTokenAddress(quote.mint, self),
      mint: quote.mint,
      destination: quote.treasury,
      authority: self,
      amount: quote.amount,
      decimals: quote.decimals,
    });

    const { blockhash } = await this.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
    tx.feePayer = quote.feePayer;
    tx.recentBlockhash = blockhash;
    tx.add(payment, ...ixs);
    const signature = await spend.signTransaction(tx.serializeMessage());
    tx.addSignature(self, Buffer.from(signature));

    return this.toll.submit(
      quote.quote,
      tx.serialize({ requireAllSignatures: false, verifySignatures: false }),
    );
  }

  static async recover(): Promise<CavosSolana> {
    throw new Error("kit/solana: native accounts restore by connecting with the enclave or a passkey");
  }
}

const defaultRegistry = new InMemoryWalletRegistry();
