import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  sendAndConfirmTransaction,
  type TransactionInstruction,
} from "@solana/web3.js";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { WebCryptoSigner } from "../../signer/WebCryptoSigner";
import type { WalletRegistry } from "../../registry/WalletRegistry";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { deriveAddressSeedSolana } from "../../identity";
import { SolanaAdapter } from "./SolanaAdapter";
import type { InstructionData } from "./SolanaAdapter";
import { SolanaRelayer } from "./SolanaRelayer";
import { SOLANA_NETWORKS, type SolanaNetwork } from "./constants";
import { BackupSigner, deriveBackupKey } from "../../recovery/BackupSigner";
import type { PasskeySigner, PasskeyEnrollParams } from "../../signer/PasskeySigner";
import { webauthnDigest, recoverCandidatePublicKeys, batchChallenge } from "../../crypto/webauthn";
import type { PasskeyAssertion } from "../../crypto/webauthn";

export interface ConnectSolanaOptions {
  network: SolanaNetwork;
  /** Authenticated user (pass `identity` directly, or an `auth` provider). */
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  backendUrl?: string;
  registry?: WalletRegistry;
  /** RPC override (else the network default). */
  rpcUrl?: string;
  /** Cavos device-account program id override. */
  programId?: string;
  /** Override the device signer factory (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
  /**
   * Gasless sponsorship via the Cavos relayer. When set (or when `appId` +
   * `backendUrl` are given), transactions are co-signed + paid by the Cavos
   * relayer, so the integrator needs NO fee-payer keypair — the user's silent
   * device key (which holds no SOL) gets a seedless, gasless experience.
   */
  relayer?: SolanaRelayer;
  /**
   * Self-funded fallback: a fee-payer keypair the integrator funds. Used only
   * when no `relayer` is configured (tests / advanced). Sponsored relaying is
   * the default path when `appId` is provided.
   */
  feePayer?: Keypair;
}

export type ConnectStatus = "ready" | "needs-device-approval";

/**
 * Options for recovering a Solana account after losing every device signer.
 * Mirrors `RecoveryOptions` (Starknet), adapted to the Solana path: the backup
 * key signs the `add_signer` bundle via the secp256r1 precompile and the Cavos
 * relayer sponsors it (no fee-payer keypair needed).
 */
export interface RecoverSolanaOptions {
  /** The recovery code the user stored when they ran setupRecovery. */
  code: string;
  /** Authenticated identity (same user who owns the account). */
  identity: Identity;
  /** Solana network the account lives on. */
  network: SolanaNetwork;
  appSalt: string;
  appId?: string;
  backendUrl?: string;
  registry?: WalletRegistry;
  /** RPC override (else the network default). */
  rpcUrl?: string;
  /** Cavos device-account program id override. */
  programId?: string;
  /** Override the new device's signer (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
  /** Gasless sponsorship via the Cavos relayer (defaults to hosted when appId set). */
  relayer?: SolanaRelayer;
  /** Self-funded fallback when no relayer is configured (tests / advanced). */
  feePayer?: Keypair;
}

/**
 * High-level Solana entry — the Solana analogue of `Cavos.connect`. One call
 * derives the deterministic device-bound account, deploys it (PDA `initialize`)
 * if needed, registers it for cross-device recognition, and returns a ready
 * handle whose silent P-256 device key authorizes every action through the
 * native secp256r1 precompile.
 *
 *   const cavos = await CavosSolana.connect({ network: "solana-devnet", identity, appSalt, feePayer });
 *   if (cavos.status === "ready") await cavos.execute(amount, dest);
 *
 * Gasless by default: when an `appId` is provided the Cavos relayer co-signs +
 * pays (no fee-payer keypair needed). `feePayer` is the self-funded fallback.
 */
export class CavosSolana {
  /** Discriminant for the `CavosWallet` union — narrows `execute()` per chain. */
  readonly chain = "solana" as const;
  /** True when this connect just created a brand-new account (first sign-up). */
  isNewAccount = false;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    readonly status: ConnectStatus,
    readonly connection: Connection,
    private readonly adapter: SolanaAdapter,
    private readonly devicePubkey: DevicePublicKey,
    private readonly relayer?: SolanaRelayer,
    private readonly feePayer?: Keypair,
  ) {}

  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  static async connect(opts: ConnectSolanaOptions): Promise<CavosSolana> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/solana: connect requires `identity` or `auth`");

    // Client-side read RPC. The integrator SHOULD pass their own `rpcUrl` — the
    // public default is rate-limited and unfit for production. (This is separate
    // from the relayer's server-side RPC, which Cavos operates.) Warn loudly when
    // hitting mainnet on the shared public endpoint.
    if (opts.network === "solana-mainnet" && !opts.rpcUrl) {
      console.warn(
        "[cavos] Using the public mainnet-beta RPC. Pass `rpcUrl` with your own " +
          "provider (Helius/Triton/QuickNode) for production — the public endpoint is rate-limited.",
      );
    }
    const connection = new Connection(opts.rpcUrl ?? SOLANA_NETWORKS[opts.network], "confirmed");

    const signer = opts.createSigner
      ? await opts.createSigner(`${identity.userId}:${opts.appSalt}`)
      : await WebCryptoSigner.loadOrCreate({ keyId: `${identity.userId}:${opts.appSalt}` });
    const devicePubkey = await signer.getPublicKey();

    const adapter = new SolanaAdapter({ programId: opts.programId, connection, signer });
    const addressSeed = deriveAddressSeedSolana({ userId: identity.userId, appSalt: opts.appSalt });

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : defaultRegistry);

    // Default to gasless sponsorship via the Cavos relayer when an appId is set,
    // so the integrator needs no fee payer. `feePayer` is the self-funded fallback.
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new SolanaRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, connection })
        : undefined);

    // Returning user on another device? The address is device-bound, so the
    // registry (not the identity alone) recognizes it. A new device is flagged
    // needs-device-approval (add it from an existing device) — same model as Starknet.
    const existing = await registry.lookup(identity.userId);
    if (existing) {
      const isSigner = await adapter.isAuthorizedSigner(existing.address, devicePubkey);
      return new CavosSolana(
        identity,
        existing.address,
        isSigner ? "ready" : "needs-device-approval",
        connection,
        adapter,
        devicePubkey,
        relayer,
        opts.feePayer,
      );
    }

    const address = adapter.computeAddress(addressSeed);
    const deployed = (await connection.getAccountInfo(new PublicKey(address))) !== null;

    if (!deployed) {
      // Deploy: register the first device signer via `initialize`. Anti-squatting
      // is NOT enforced on-chain — it is the integrator's responsibility to keep
      // `appSalt` secret and to deploy each account on the user's first login.
      //
      // Whoever pays must be the `initialize` payer/fee payer: the relayer (when
      // sponsoring) or the self-funded feePayer. buildInitialize returns the
      // program ix to register the first signer.
      if (relayer) {
        const payer = await relayer.getFeePayer();
        const ixs = adapter.buildInitialize(addressSeed, payer.toBase58(), devicePubkey);
        await relayer.send(ixs);
      } else if (opts.feePayer) {
        const ixs = adapter.buildInitialize(addressSeed, opts.feePayer.publicKey.toBase58(), devicePubkey);
        await sendAndConfirmTransaction(connection, new Transaction().add(...ixs), [opts.feePayer]);
      } else {
        throw new Error("kit/solana: a relayer (appId) or feePayer is required to initialize a new account");
      }
    }

    await registry.register({ userId: identity.userId, address, initialSigner: devicePubkey });
    const isSigner = await adapter.isAuthorizedSigner(address, devicePubkey);
    const wallet = new CavosSolana(
      identity,
      address,
      isSigner ? "ready" : "needs-device-approval",
      connection,
      adapter,
      devicePubkey,
      relayer,
      opts.feePayer,
    );
    // First sign-up: a fresh initialize that made this device an authorized signer.
    wallet.isNewAccount = !deployed && isSigner;
    return wallet;
  }

  /** Authorize an additional device signer (device-signed via precompile). */
  async addSigner(pubkey: DevicePublicKey): Promise<string> {
    const ixs = await this.adapter.buildAddSigner(this.address, pubkey);
    return this.send(ixs);
  }

  /**
   * Enroll a passkey as an approver (2FA-style step-up). Device-signed + gasless;
   * requires a ready device. Idempotent. Returns the passkey pubkey + tx hash.
   */
  async enrollPasskey(
    passkey: PasskeySigner,
    params: PasskeyEnrollParams,
  ): Promise<{ publicKey: DevicePublicKey; transactionHash?: string }> {
    const enrolled = await passkey.enroll(params);
    const { transactionHash } = await this.addApprover(enrolled.publicKey);
    return { publicKey: enrolled.publicKey, transactionHash };
  }

  /** Register an already-enrolled passkey pubkey as an approver (gasless).
   * Idempotent. Lets one passkey be registered across chains without re-prompting. */
  async addApprover(pubkey: DevicePublicKey): Promise<{ transactionHash?: string }> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: addApprover requires a ready, authorized device");
    }
    if (await this.adapter.isApprover(this.address, pubkey)) return {};
    const ixs = await this.adapter.buildAddApprover(this.address, pubkey);
    const transactionHash = await this.send(ixs);
    return { transactionHash };
  }

  /** True if this account already has a passkey enrolled as an approver, so a
   * new device can be approved with the passkey instead of the email flow. */
  async hasPasskey(): Promise<boolean> {
    return this.adapter.hasPasskeyApprover(this.address);
  }

  /** Re-read (from chain) whether THIS device is now an authorized signer.
   * Used to poll for readiness after a passkey approval before it's indexed. */
  async isReady(): Promise<boolean> {
    return this.adapter.isAuthorizedSigner(this.address, this.devicePubkey);
  }

  /**
   * From a fresh browser (status `needs-device-approval`), approve adding THIS
   * device with the user's synced passkey. Gasless via the relayer — the bundle
   * carries the passkey's WebAuthn assertion, so no device signature is needed.
   */
  async approveThisDeviceWithPasskey(passkey: PasskeySigner): Promise<string> {
    if (this.status === "ready") {
      throw new Error("kit/solana: this device is already an authorized signer");
    }
    const { leaf, nonce } = await this.passkeyLeafForThisDevice();
    const leaves = [leaf];
    const assertion = await passkey.assert(batchChallenge(leaves));
    const { transactionHash } = await this.submitPasskeyApproval(assertion, leaves, 0, nonce);
    return transactionHash;
  }

  /** This device's leaf + passkey nonce for a (possibly multi-chain) batch. */
  async passkeyLeafForThisDevice(): Promise<{ leaf: Uint8Array; nonce: bigint }> {
    const nonce = await this.adapter.passkeyNonce(this.address);
    return { leaf: this.adapter.passkeyLeaf(this.devicePubkey, nonce), nonce };
  }

  /** Submit `add_signer_via_passkey` given a shared assertion + batch position.
   * Used by `approveThisDeviceWithPasskey` and `approveDeviceEverywhere`. */
  async submitPasskeyApproval(
    assertion: PasskeyAssertion,
    leaves: Uint8Array[],
    leafIndex: number,
    _nonce: bigint,
  ): Promise<{ transactionHash: string }> {
    const digest = webauthnDigest(assertion.authenticatorData, assertion.clientDataJSON);
    const candidates = recoverCandidatePublicKeys(assertion.r, assertion.s, digest);
    let approver: DevicePublicKey | null = null;
    for (const cand of candidates) {
      if (await this.adapter.isApprover(this.address, cand.publicKey)) {
        approver = cand.publicKey;
        break;
      }
    }
    if (!approver) throw new Error("kit/solana: this passkey is not a registered approver");
    const ixs = this.adapter.buildAddSignerViaPasskey(
      this.address, this.devicePubkey, approver, leaves, leafIndex, assertion,
    );
    return { transactionHash: await this.send(ixs) };
  }

  /** Move `amount` lamports out of the account to `destination` (device-signed). */
  async execute(amount: bigint, destination: string): Promise<string> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const ixs = await this.adapter.buildExecuteTransfer(this.address, destination, amount);
    return this.send(ixs);
  }

  /**
   * Run arbitrary CPI `instructions` with the account PDA as signer (device-
   * signed). The signature commits to sha256 of the canonical Borsh
   * serialization of the instructions, so it binds exactly the operations the
   * program will invoke. Unlocks SPL transfers, swaps, staking, etc.
   *
   * What the relayer will sponsor is constrained by the app's Solana program
   * allowlist (configured in the dashboard) — programs outside the allowlist are
   * rejected before co-signing.
   */
  async executeInstructions(instructions: InstructionData[]): Promise<string> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const ixs = await this.adapter.buildExecute(this.address, instructions);
    return this.send(ixs);
  }

  /**
   * Register the backup signer derived from `code` as an authorized signer of this
   * account (device-signed via precompile). Idempotent: returns without a tx if
   * the backup signer is already registered. The code never leaves the device —
   * only the derived public key travels on-chain.
   *
   * Self-custodial: anyone who can re-derive the backup key from the code (i.e.
   * the rightful owner) can later recover the account with `CavosSolana.recover`.
   * Run this once, on a registered device, and have the user store the code.
   */
  async setupRecovery(code: string): Promise<string | undefined> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: setupRecovery requires a ready, registered device");
    }
    const { publicKey: backupPubkey } = deriveBackupKey(code);
    // Skip the on-chain call if the backup signer is already registered.
    const already = await this.adapter.isAuthorizedSigner(this.address, backupPubkey);
    if (already) return undefined;
    return this.addSigner(backupPubkey);
  }

  /**
   * Recover an account after losing every device signer. Derives the backup key
   * from `code`, uses it (not the new device key) to sign an `add_signer` for the
   * new device, and returns a ready CavosSolana bound to the new device. The
   * account address is unchanged.
   *
   * Self-custodial: only someone holding the code (i.e. the rightful owner) can
   * re-derive the backup key. The backend never sees the code.
   *
   * This mirrors `Cavos.recover` (Starknet): the backup key is just another
   * authorized signer, so recovery is an `add_signer(newDevice)` bundle signed by
   * the backup key. The on-chain program needs no recovery-specific entrypoint.
   */
  static async recover(opts: RecoverSolanaOptions): Promise<CavosSolana> {
    if (opts.network === "solana-mainnet" && !opts.rpcUrl) {
      console.warn(
        "[cavos] Using the public mainnet-beta RPC. Pass `rpcUrl` with your own " +
          "provider (Helius/Triton/QuickNode) for production — the public endpoint is rate-limited.",
      );
    }
    const connection = new Connection(opts.rpcUrl ?? SOLANA_NETWORKS[opts.network], "confirmed");

    // The new device's signer (created/loaded the same way connect() does).
    const signer = opts.createSigner
      ? await opts.createSigner(`${opts.identity.userId}:${opts.appSalt}`)
      : await WebCryptoSigner.loadOrCreate({ keyId: `${opts.identity.userId}:${opts.appSalt}` });
    const devicePubkey = await signer.getPublicKey();

    // The backup key drives THIS transaction: it's the only signer that can
    // authorise adding the new device after all device keys are lost. The
    // adapter signs every bundle with whatever `signer` it's constructed with,
    // so a backup-backed adapter produces backup-signed `add_signer` bundles.
    const backup = BackupSigner.fromCode(opts.code);
    const backupAdapter = new SolanaAdapter({
      programId: opts.programId,
      connection,
      signer: backup,
    });

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : defaultRegistry);
    const existing = await registry.lookup(opts.identity.userId);
    if (!existing) {
      throw new Error("kit/solana: no account found for this identity — nothing to recover");
    }

    const relayer =
      opts.relayer ??
      (opts.appId
        ? new SolanaRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, connection })
        : undefined);

    // Authorise the new device, signed by the backup key (sponsored by the relayer,
    // or self-funded). The account address is unchanged.
    const alreadyAuthed = await backupAdapter.isAuthorizedSigner(existing.address, devicePubkey);
    if (!alreadyAuthed) {
      const ixs = await backupAdapter.buildAddSigner(existing.address, devicePubkey);
      if (relayer) {
        await relayer.send(ixs);
      } else if (opts.feePayer) {
        await sendAndConfirmTransaction(connection, new Transaction().add(...ixs), [opts.feePayer]);
      } else {
        throw new Error("kit/solana: a relayer (appId) or feePayer is required to recover");
      }
    }

    // Hand control to the new device's signer for all future operations.
    const adapter = new SolanaAdapter({ programId: opts.programId, connection, signer });
    return new CavosSolana(
      opts.identity,
      existing.address,
      "ready",
      connection,
      adapter,
      devicePubkey,
      relayer,
      opts.feePayer,
    );
  }

  private async send(ixs: TransactionInstruction[]): Promise<string> {
    // Prefer the sponsored relayer (no fee payer needed); fall back to self-funded.
    if (this.relayer) return this.relayer.send(ixs);
    if (this.feePayer) {
      return sendAndConfirmTransaction(this.connection, new Transaction().add(...ixs), [this.feePayer]);
    }
    throw new Error("kit/solana: no relayer or feePayer configured to submit transactions");
  }
}

const defaultRegistry = new InMemoryWalletRegistry();
