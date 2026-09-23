import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
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
import type { ExecuteOptions } from "../../chains/ChainAdapter";
import { utf8ToBytes } from "../../crypto/encoding";
import type { MessageSignature, SolanaSignedTransaction } from "../../signing";
import type { SocialRecoveryClient } from "../../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import type { Ed25519Seed } from "../../secret/dek";
import type { Ed25519SpendSigner } from "../../signer/Ed25519SpendSigner";
import { resolveNativeSolana } from "./nativeConnect";
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
  feePayer?: Keypair;
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
  pendingRequestId: string | null = null;
  isNewAccount = false;
  private _isDeployed: boolean;
  onAuthorizationNeeded?: () => Promise<void>;
  private readonly statusListeners = new Set<() => void>();

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    _namespace: Uint8Array,
    private statusValue: ConnectStatus,
    readonly connection: Connection,
    private readonly devicePubkey: DevicePublicKey,
    private readonly relayer?: SolanaRelayer,
    private readonly feePayer?: Keypair,
    _registry?: WalletRegistry,
    private readonly spend?: Ed25519SpendSigner,
    private readonly passkeyRestore = false,
  ) {
    void _namespace;
    void _registry;
    this._isDeployed = statusValue !== "undeployed";
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

  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  get isDeployed(): boolean {
    return this._isDeployed;
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
          passkey: opts.passkey,
        });

    const wallet = new CavosSolana(
      identity,
      native.address,
      namespace,
      native.spend ? "ready" : "needs-device-approval",
      connection,
      { x: 0n, y: 0n },
      relayer,
      opts.feePayer,
      registry,
      native.spend ?? undefined,
      Boolean(opts.passkey),
    );
    wallet.isNewAccount = native.isNewAccount;
    wallet._isDeployed = true;
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

  async isReady(): Promise<boolean> {
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
      lamports: Number(amount),
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

  async signTransaction(amount: bigint, destination: string): Promise<SolanaSignedTransaction> {
    const spend = this.requireSpend();
    const ix = SystemProgram.transfer({
      fromPubkey: new PublicKey(this.address),
      toPubkey: new PublicKey(destination),
      lamports: Number(amount),
    });
    const { blockhash } = await this.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
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

  private async sendNative(ixs: TransactionInstruction[], opts?: ExecuteOptions): Promise<string> {
    const spend = this.requireSpend();
    const sponsored = opts?.sponsored !== false;
    const payer = sponsored && this.relayer
      ? await this.relayer.getFeePayer()
      : this.feePayer?.publicKey;
    if (!payer) {
      throw new Error(
        `kit/solana: cannot ${sponsored ? "sponsor" : "self-fund"} — no ${sponsored ? "relayer" : "feePayer"} configured`,
      );
    }
    const { blockhash } = await this.connection.getLatestBlockhash("confirmed");
    const tx = new Transaction();
    tx.feePayer = payer;
    tx.recentBlockhash = blockhash;
    tx.add(...ixs);
    const signature = await spend.signTransaction(tx.serializeMessage());
    tx.addSignature(new PublicKey(this.address), Buffer.from(signature));
    if (sponsored && this.relayer) {
      return this.relayer.sendSigned(tx.serialize({ requireAllSignatures: false, verifySignatures: false }));
    }
    if (!this.feePayer) {
      throw new Error("kit/solana: cannot self-fund — no feePayer configured");
    }
    return sendAndConfirmTransaction(this.connection, tx, [this.feePayer]);
  }

  static async recover(): Promise<CavosSolana> {
    throw new Error("kit/solana: native accounts restore by connecting with the enclave or a passkey");
  }
}

const defaultRegistry = new InMemoryWalletRegistry();
