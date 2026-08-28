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
import type { WalletRegistry } from "../../registry/WalletRegistry";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { appNamespace } from "../../identity";
import { resolveAddress } from "../../registry/resolveAddress";
import { SolanaAdapter, compressedPubkey } from "./SolanaAdapter";
import type { PendingRecovery } from "./SolanaAdapter";
import type { InstructionData } from "./SolanaAdapter";
import { SolanaRelayer } from "./SolanaRelayer";
import { SOLANA_NETWORKS, type SolanaNetwork } from "./constants";
import { BackupSigner, deriveBackupKey } from "../../recovery/BackupSigner";
import { HttpRecoveryClient } from "../../recovery/HttpRecoveryClient";
import type { PasskeyApprover, PasskeyEnrollParams } from "../../signer/PasskeyProvider";
import type { ExecuteOptions } from "../../chains/ChainAdapter";
import { webauthnDigest, recoverCandidatePublicKeys, batchChallenge } from "../../crypto/webauthn";
import type { PasskeyAssertion } from "../../crypto/webauthn";
import { bytesToHex, utf8ToBytes } from "../../crypto/encoding";
import { prefixedMessageBytes, type MessageSignature, type SolanaSignedTransaction } from "../../signing";

export interface ConnectSolanaOptions {
  network: SolanaNetwork;
  /** Authenticated user (pass `identity` directly, or an `auth` provider). */
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: "development" | "production";
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
  /**
   * Keep the legacy owner-device/email approval request enabled. Set false when
   * hardware-isolated social recovery owns the new-device flow.
   */
  legacyDeviceApproval?: boolean;
}

/**
 * Chain status for Solana accounts.
 * - `undeployed`: Address derived but no on-chain PDA exists yet. First execute will deploy.
 * - `ready`: Account deployed and this device is an authorized signer.
 * - `needs-device-approval`: Account deployed but this device is not yet authorized.
 */
export type ConnectStatus = "undeployed" | "ready" | "needs-device-approval";

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
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: "development" | "production";
  backendUrl?: string;
  registry?: WalletRegistry;
  /** Provides the login token the registry lookup authenticates with. */
  auth?: AuthProvider;
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
 * derives the deterministic device-bound account and returns a handle whose
 * silent P-256 device key authorizes every action through the native secp256r1
 * precompile.
 *
 * **Lazy deploy**: Connect NEVER deploys. The first `execute` or `executeInstructions`
 * call on an undeployed account triggers deployment + the user operation atomically.
 *
 *   const cavos = await CavosSolana.connect({ network: "solana-devnet", identity, appSalt, appId });
 *   // cavos.status may be "undeployed" — first execute will deploy
 *   await cavos.execute(amount, dest); // deploys + transfers if undeployed
 *
 * Gasless by default: when an `appId` is provided the Cavos relayer co-signs +
 * pays (no fee-payer keypair needed). `feePayer` is the self-funded fallback.
 */
export class CavosSolana {
  /** Discriminant for the `CavosWallet` union — narrows `execute()` per chain. */
  readonly chain = "solana" as const;
  /** Request id of the pending device-addition, when status is needs-device-approval. */
  pendingRequestId: string | null = null;
  /** True when this connect just created a brand-new account (first sign-up). */
  isNewAccount = false;

  /** Track whether deployment happened (for lazy deploy). */
  private _isDeployed: boolean;
  /** Pending passkey enrollment to include in first deploy. */
  private _pendingApprover: DevicePublicKey | null = null;
  /** Pending recovery signer to include in first deploy. */
  private _pendingRecoverySigner: DevicePublicKey | null = null;
  /** Address seed for lazy deploy. */
  private readonly namespace: Uint8Array;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    namespace: Uint8Array,
    private statusValue: ConnectStatus,
    readonly connection: Connection,
    private readonly adapter: SolanaAdapter,
    private readonly devicePubkey: DevicePublicKey,
    private readonly relayer?: SolanaRelayer,
    private readonly feePayer?: Keypair,
    private readonly registry?: WalletRegistry,
  ) {
    this.namespace = namespace;
    this._isDeployed = statusValue !== "undeployed";
  }

  /** Current status of this wallet. May change from "undeployed" to "ready" after first execute. */
  get status(): ConnectStatus {
    return this.statusValue;
  }

  /**
   * Listeners for status changes.
   *
   * The status moves when the first execute deploys the account, and it moves
   * by mutating this object — so nothing holding a reference re-renders, and an
   * effect keyed on the wallet never re-runs. That is how recovery enrolment
   * came to be skipped entirely: the wallet turned ready and nobody was told.
   */
  private readonly statusListeners = new Set<() => void>();

  /** Subscribe to status changes. Returns an unsubscribe. */
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
        /* a bad listener must not break the wallet that just became usable */
      }
    }
  }

  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  /** Whether this account is deployed on-chain. */
  get isDeployed(): boolean {
    return this._isDeployed;
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
      : await loadDefaultWebSigner(`${identity.userId}:${opts.appSalt}`);
    const devicePubkey = await signer.getPublicKey();

    const adapter = new SolanaAdapter({ programId: opts.programId, connection, signer });
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

    // Default to gasless sponsorship via the Cavos relayer when an appId is set,
    // so the integrator needs no fee payer. `feePayer` is the self-funded fallback.
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new SolanaRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, connection, environment: opts.environment })
        : undefined);

    // Recovery client drives the email device-approval flow (same as Starknet):
    // when a returning user signs in on a new device, we ask the backend to email
    // the owner an approval link. Chain-agnostic — Solana's secp256r1 device key
    // is the same curve Starknet uses, so the {x,y} pubkey passes through as-is.
    const recovery = opts.appId ? new HttpRecoveryClient({ baseUrl: backendUrl, appId: opts.appId, environment: opts.environment, authToken: () => opts.auth?.getAuthToken?.() ?? null }) : null;

    // The registry names the wallet; the PDA is only computed for a user who
    // does not have one yet. Its seeds include this device's pubkey, so the
    // address it claims is one no other device could have taken.
    const { address } = await resolveAddress({
      key: { userId: identity.userId, appId: opts.appId ?? "local", chain: "solana", network: opts.network },
      registry: opts.appId ? registry : null,
      initialSigner: devicePubkey,
      compute: () => adapter.computeAddress(namespace, devicePubkey),
    });

    // LAZY DEPLOY: Check deployment status but DO NOT deploy here.
    // Deployment happens on first execute() call.
    const deployed = (await connection.getAccountInfo(new PublicKey(address))) !== null;

    // Determine status: undeployed, ready, or needs-device-approval
    let status: ConnectStatus;
    let isSigner = false;

    if (!deployed) {
      // Account not deployed yet — first execute will deploy + initialize
      status = "undeployed";
    } else {
      // Account exists — check if this device is authorized
      isSigner = await adapter.isAuthorizedSigner(address, devicePubkey);
      status = isSigner ? "ready" : "needs-device-approval";
    }

    const wallet = new CavosSolana(
      identity,
      address,
      namespace,
      status,
      connection,
      adapter,
      devicePubkey,
      relayer,
      opts.feePayer,
      registry,
    );
    // isNewAccount is set after first deploy in execute(), not here
    wallet.isNewAccount = false;

    // Mirror only a signer that the chain actually recognizes.
    if (isSigner) {
      try {
        await registry.register({ userId: identity.userId, address, initialSigner: devicePubkey });
      } catch (e) {
        console.warn("[Cavos/solana] registry.register failed (non-fatal):", e);
      }
    }

    // Deployed account, but THIS device isn't an authorized signer yet — request approval
    if (status === "needs-device-approval" && recovery && opts.legacyDeviceApproval !== false) {
      const dedup = lastDeviceRequest.get(identity.userId);
      const fresh = dedup && Date.now() - dedup.requestedAt < DEVICE_REQUEST_DEDUP_MS;
      try {
        if (fresh) {
          wallet.pendingRequestId = dedup!.requestId;
        } else {
          const { requestId } = await recovery.requestDeviceAddition({
            userId: identity.userId,
            accountAddress: address,
            newSigner: devicePubkey,
            ...(identity.email ? { email: identity.email } : {}),
          });
          wallet.pendingRequestId = requestId;
          lastDeviceRequest.set(identity.userId, { requestId, requestedAt: Date.now() });
        }
      } catch (e) {
        console.warn("[Cavos/solana] requestDeviceAddition failed:", e);
      }
    }
    return wallet;
  }

  /** Authorize an additional device signer (device-signed via precompile). */
  async addSigner(pubkey: DevicePublicKey): Promise<string> {
    const ixs = await this.adapter.buildAddSigner(this.address, pubkey);
    return this.send(ixs);
  }

  /**
   * Revoke a device signer — the escape hatch behind the "this wasn't me" link
   * in the device-added email. Authorization is a device signature through the
   * secp256r1 precompile: only a device that is ALREADY authorized can revoke
   * another one, and Cavos holds no key that can do it on the user's behalf.
   */
  async removeSigner(pubkey: DevicePublicKey): Promise<string> {
    if (this.status !== "ready") {
      throw new Error(
        "kit/solana: removeSigner requires a device that is already an authorized signer",
      );
    }
    if (pubkey.x === this.devicePubkey.x && pubkey.y === this.devicePubkey.y) {
      throw new Error(
        "kit/solana: cannot revoke the device you are signing with — revoke it from another authorized device",
      );
    }
    const authorized = await this.adapter.isAuthorizedSigner(this.address, pubkey);
    if (!authorized) {
      throw new Error("kit/solana: that device is not an authorized signer of this wallet");
    }
    const ixs = await this.adapter.buildRemoveSigner(this.address, pubkey);
    return this.send(ixs);
  }

  /**
   * The social-recovery authorization already scheduled on-chain, if any.
   *
   * A run that scheduled but never finalized — a closed tab, a relay error
   * between the two calls — leaves one behind, and the program refuses to
   * schedule over it until it expires. Callers should check this before
   * scheduling and resume the existing authorization instead.
   */
  async pendingSocialRecovery(): Promise<PendingRecovery | null> {
    return this.adapter.pendingSocialRecovery(this.address);
  }

  /** Whether `pending` authorizes THIS device (so it can simply be finalized). */
  async pendingRecoveryIsForThisDevice(): Promise<boolean> {
    const pending = await this.pendingSocialRecovery();
    if (!pending) return false;
    const mine = compressedPubkey(this.devicePubkey);
    return (
      pending.signerCompressed.length === mine.length &&
      pending.signerCompressed.every((byte, i) => byte === mine[i])
    );
  }

  async enrollSocialRecovery(params: {
    recoveryPubkeyCompressed: Uint8Array;
    delaySeconds: number;
    policyHash: Uint8Array;
  }): Promise<string> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: social recovery enrolment requires a ready device");
    }
    const payer = this.relayer
      ? await this.relayer.getFeePayer()
      : this.feePayer?.publicKey;
    if (!payer) throw new Error("kit/solana: recovery enrolment requires a fee payer");
    const ixs = await this.adapter.buildEnrollSocialRecovery(
      this.address,
      payer.toBase58(),
      params.recoveryPubkeyCompressed,
      params.delaySeconds,
      params.policyHash,
    );
    return this.send(ixs);
  }

  async socialRecoveryNonce(): Promise<bigint> {
    return this.adapter.socialRecoveryNonce(this.address);
  }

  async scheduleSocialRecovery(params: {
    expiresAt: number;
    message: Uint8Array;
    signature: Uint8Array;
    recoveryPubkeyCompressed: Uint8Array;
  }): Promise<string> {
    const ixs = this.adapter.buildScheduleSocialRecovery({
      account: this.address,
      newSigner: this.devicePubkey,
      ...params,
    });
    return this.send(ixs);
  }

  async finalizeSocialRecovery(): Promise<string> {
    return this.send([this.adapter.buildFinalizeSocialRecovery(this.address)]);
  }

  /**
   * Schedule and finalize in a single transaction. Only valid when the
   * environment's recovery delay is zero.
   *
   * The two-step shape exists for the timelock: an account with a delay wants a
   * window in which a still-controlled device can cancel a recovery it did not
   * ask for. With no delay there is no window, and splitting the work costs a
   * second relay round trip and a second confirmation — about half the
   * wall-clock time of adding a device.
   *
   * This is safe because the program computes `ready_at` itself, as
   * `clock.unix_timestamp + delay_seconds`, and `finalize` requires
   * `clock.unix_timestamp >= ready_at`. Solana instructions in one transaction
   * see the same `Clock`, so with `delay_seconds == 0` the check passes — and
   * with any non-zero delay it fails, which is exactly the protection the
   * timelock is for. Batching cannot skip a delay that exists.
   */
  async scheduleAndFinalizeSocialRecovery(params: {
    expiresAt: number;
    message: Uint8Array;
    signature: Uint8Array;
    recoveryPubkeyCompressed: Uint8Array;
  }): Promise<string> {
    return this.send([
      ...this.adapter.buildScheduleSocialRecovery({
        account: this.address,
        newSigner: this.devicePubkey,
        ...params,
      }),
      this.adapter.buildFinalizeSocialRecovery(this.address),
    ]);
  }

  /**
   * Enroll a passkey as an approver (2FA-style step-up). Idempotent.
   *
   * **Undeployed accounts**: The passkey is stored pending and will be included
   * after the first deploy. No on-chain write happens until execute().
   *
   * Returns the passkey pubkey + tx hash (if deployed).
   */
  async enrollPasskey(
    passkey: PasskeyApprover,
    params: PasskeyEnrollParams,
  ): Promise<{ publicKey: DevicePublicKey; transactionHash?: string }> {
    const enrolled = await passkey.enroll(params);
    const { transactionHash } = await this.addApprover(enrolled.publicKey);
    return { publicKey: enrolled.publicKey, transactionHash };
  }

  /**
   * Register an already-enrolled passkey pubkey as an approver (gasless).
   * Idempotent. Lets one passkey be registered across chains without re-prompting.
   *
   * **Undeployed accounts**: The approver is stored pending and will be added
   * after the first deploy transaction.
   */
  async addApprover(pubkey: DevicePublicKey): Promise<{ transactionHash?: string }> {
    // For undeployed accounts, store the pending approver
    if (this.statusValue === "undeployed") {
      this._pendingApprover = pubkey;
      return {}; // No tx yet — will be added after first deploy
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit/solana: addApprover requires a ready, authorized device");
    }
    if (await this.adapter.isApprover(this.address, pubkey)) return {};
    const ixs = await this.adapter.buildAddApprover(this.address, pubkey);
    const transactionHash = await this.send(ixs);
    return { transactionHash };
  }

  /**
   * True if this account already has a passkey enrolled as an approver, so a
   * new device can be approved with the passkey instead of the email flow.
   *
   * Returns true for undeployed accounts if a passkey is pending enrollment.
   */
  async hasPasskey(): Promise<boolean> {
    if (this.statusValue === "undeployed") {
      return this._pendingApprover !== null;
    }
    return this.adapter.hasPasskeyApprover(this.address);
  }

  /**
   * Re-read (from chain) whether THIS device is now an authorized signer.
   * Used to poll for readiness after a passkey approval before it's indexed.
   *
   * For undeployed accounts, returns false (not yet on-chain).
   */
  async isReady(): Promise<boolean> {
    if (this.statusValue === "undeployed") {
      return false;
    }
    return this.adapter.isAuthorizedSigner(this.address, this.devicePubkey);
  }

  /**
   * From a fresh browser (status `needs-device-approval`), approve adding THIS
   * device with the user's synced passkey. Gasless via the relayer — the bundle
   * carries the passkey's WebAuthn assertion, so no device signature is needed.
   */
  async approveThisDeviceWithPasskey(passkey: PasskeyApprover): Promise<string> {
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

  /**
   * Move `amount` lamports out of the account to `destination` (device-signed).
   *
   * **Lazy deploy**: If the account is undeployed, the first execute initializes
   * + transfers atomically in a single transaction.
   */
  async execute(amount: bigint, destination: string, opts?: ExecuteOptions): Promise<string> {
    // Handle lazy deploy: first execute on undeployed account
    if (this.statusValue === "undeployed") {
      return this._deployAndExecuteTransfer(amount, destination, opts);
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const ixs = await this.adapter.buildExecuteTransfer(this.address, destination, amount);
    return this.send(ixs, opts);
  }

  /**
   * Run arbitrary CPI `instructions` with the account PDA as signer (device-
   * signed). The signature commits to sha256 of the canonical Borsh
   * serialization of the instructions, so it binds exactly the operations the
   * program will invoke. Unlocks SPL transfers, swaps, staking, etc.
   *
   * **Lazy deploy**: If the account is undeployed, the first executeInstructions
   * initializes + runs instructions atomically.
   *
   * What the relayer will sponsor is constrained by the app's Solana program
   * allowlist (configured in the dashboard) — programs outside the allowlist are
   * rejected before co-signing. Pass `{ sponsored: false }` to bypass the relayer
   * and pay the fee from a configured `feePayer` (e.g. for allowlisted programs
   * the relayer rejects, or to test the device signature end-to-end).
   */
  async executeInstructions(
    instructions: InstructionData[],
    opts?: ExecuteOptions,
  ): Promise<string> {
    // Handle lazy deploy: first execute on undeployed account
    if (this.statusValue === "undeployed") {
      return this._deployAndExecuteInstructions(instructions, opts);
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const ixs = await this.adapter.buildExecute(this.address, instructions);
    return this.send(ixs, opts);
  }

  /**
   * Deploy (initialize) + transfer atomically. Called by execute() when status is "undeployed".
   */
  private async _deployAndExecuteTransfer(
    amount: bigint,
    destination: string,
    opts?: ExecuteOptions,
  ): Promise<string> {
    // Build initialize + transfer instructions
    const payer = this.relayer
      ? await this.relayer.getFeePayer()
      : this.feePayer?.publicKey;
    if (!payer) {
      throw new Error("kit/solana: a relayer (appId) or feePayer is required to initialize + execute");
    }

    // Initialize instruction
    const initIxs = this.adapter.buildInitialize(
      this.namespace,
      payer.toBase58(),
      this.devicePubkey,
    );

    // After initialize, build the transfer instruction.
    // Note: Solana's execute_transfer requires the account to exist.
    // We send init + transfer in separate transactions for atomicity.
    const txHash = await this._deployThenExecute(initIxs, async () => {
      const transferIxs = await this.adapter.buildExecuteTransfer(this.address, destination, amount);
      return this.send(transferIxs, opts);
    }, opts);

    return txHash;
  }

  /**
   * Deploy (initialize) + execute instructions atomically. Called by executeInstructions() when undeployed.
   */
  private async _deployAndExecuteInstructions(
    instructions: InstructionData[],
    opts?: ExecuteOptions,
  ): Promise<string> {
    const payer = this.relayer
      ? await this.relayer.getFeePayer()
      : this.feePayer?.publicKey;
    if (!payer) {
      throw new Error("kit/solana: a relayer (appId) or feePayer is required to initialize + execute");
    }

    // Initialize instruction
    const initIxs = this.adapter.buildInitialize(
      this.namespace,
      payer.toBase58(),
      this.devicePubkey,
    );

    const txHash = await this._deployThenExecute(initIxs, async () => {
      const executeIxs = await this.adapter.buildExecute(this.address, instructions);
      return this.send(executeIxs, opts);
    }, opts);

    return txHash;
  }

  /**
   * Deploy the account first, then execute the user operation.
   * The Solana program may not support init+execute atomically (depends on nonce),
   * so we initialize first, wait for confirmation, then execute.
   */
  private async _deployThenExecute(
    initIxs: TransactionInstruction[],
    executeOp: () => Promise<string>,
    opts?: ExecuteOptions,
  ): Promise<string> {
    // Send the initialize transaction
    const sponsored = opts?.sponsored !== false;
    if (sponsored && this.relayer) {
      await this.relayer.send(initIxs);
    } else if (this.feePayer) {
      await sendAndConfirmTransaction(
        this.connection,
        new Transaction().add(...initIxs),
        [this.feePayer],
      );
    } else {
      throw new Error("kit/solana: a relayer (appId) or feePayer is required to initialize");
    }

    // Update status to ready
    this._isDeployed = true;
    this.setStatus("ready");
    this.isNewAccount = true;

    // Register with registry (best-effort)
    if (this.registry) {
      try {
        await this.registry.register({
          userId: this.identity.userId,
          address: this.address,
          initialSigner: this.devicePubkey,
        });
      } catch (e) {
        console.warn("[Cavos/solana] registry.register failed (non-fatal):", e);
      }
    }

    // Add pending factors that were enrolled before deploy
    if (this._pendingApprover) {
      const ixs = await this.adapter.buildAddApprover(this.address, this._pendingApprover);
      await this.send(ixs, opts);
      this._pendingApprover = null;
    }
    if (this._pendingRecoverySigner) {
      await this.addSigner(this._pendingRecoverySigner);
      this._pendingRecoverySigner = null;
    }

    // Now execute the user operation
    return executeOp();
  }

  /**
   * Sign an arbitrary message off-chain with the device key. Nothing is
   * submitted and no Solana transaction is involved. The device signs
   * `sha256(prefixedMessage)` with the Solana-standard prefix
   * `"\x18Solana Signed Message:\n<len>\n"`, so the signature is verifiable by
   * any Solana wallet/library that expects the `signMessage` convention.
   *
   * `publicKey` is the 33-byte compressed P-256 device key as hex.
   */
  async signMessage(message: string | Uint8Array): Promise<MessageSignature> {
    // Works while the account is still undeployed: the signature comes from the
    // local device key, and proving control of that key needs no chain state.
    if (this.status === "needs-device-approval") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const msgBytes = typeof message === "string" ? utf8ToBytes(message) : message;
    const prefixed = prefixedMessageBytes(msgBytes);
    const { signature, pubkey } = await this.adapter.signRaw(prefixed);
    return { signature, publicKey: bytesToHex(pubkey), curve: "secp256r1" };
  }

  /**
   * Build + sign the device's contribution to a SOL transfer WITHOUT submitting.
   *
   * **This is not a signed Solana transaction.** The device P-256 key never
   * signs the Solana transaction itself — it signs a domain-tagged message
   * (`DOMAIN_TRANSFER ‖ account ‖ destination ‖ amount ‖ nonce`) verified on-chain
   * by the native secp256r1 precompile. A relayer/feePayer must take this
   * `(message, signature, publicKey)` triple, assemble the
   * `[secp256r1 precompile ix, execute_transfer ix]` bundle, add a recent
   * blockhash + the feePayer's signature, and submit.
   *
   * The signature binds to the on-chain account nonce, so it is single-use: if
   * any other device-signed action from this account lands first, this signature
   * is invalid.
   */
  async signTransaction(amount: bigint, destination: string): Promise<SolanaSignedTransaction> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const message = await this.adapter.buildTransferMessage(this.address, destination, amount);
    const { signature, pubkey } = await this.adapter.signRaw(message);
    return { chain: "solana", message, signature, publicKey: pubkey };
  }

  /**
   * Register the backup signer derived from `code` as an authorized signer of this
   * account (device-signed via precompile). Idempotent: returns without a tx if
   * the backup signer is already registered. The code never leaves the device —
   * only the derived public key travels on-chain.
   *
   * **Undeployed accounts**: The backup signer is stored pending and will be
   * added after the first deploy transaction.
   *
   * Self-custodial: anyone who can re-derive the backup key from the code (i.e.
   * the rightful owner) can later recover the account with `CavosSolana.recover`.
   * Run this once, on a registered device, and have the user store the code.
   */
  async setupRecovery(code: string): Promise<string | undefined> {
    const { publicKey: backupPubkey } = deriveBackupKey(code);

    // For undeployed accounts, store the pending recovery signer
    if (this.statusValue === "undeployed") {
      this._pendingRecoverySigner = backupPubkey;
      return undefined; // No tx yet — will be added after first deploy
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit/solana: setupRecovery requires a ready, registered device");
    }

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
      : await loadDefaultWebSigner(`${opts.identity.userId}:${opts.appSalt}`);
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
        ? new HttpWalletRegistry({
            baseUrl: backendUrl,
            appId: opts.appId,
            network: opts.network,
            environment: opts.environment,
            authToken: () => opts.auth?.getAuthToken?.() ?? null,
          })
        : defaultRegistry);
    const existing = await registry.lookup(opts.identity.userId);
    if (!existing) {
      throw new Error("kit/solana: no account found for this identity — nothing to recover");
    }

    const relayer =
      opts.relayer ??
      (opts.appId
        ? new SolanaRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, connection, environment: opts.environment })
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
      appNamespace({ appId: opts.appId ?? "local", environmentId: opts.environment }),
      "ready",
      connection,
      adapter,
      devicePubkey,
      relayer,
      opts.feePayer,
      registry,
    );
  }

  /**
   * Submit a built instruction bundle. Sponsored by default (relayer pays the
   * fee); pass `{ sponsored: false }` to self-fund via the configured `feePayer`.
   * The device signature is embedded inside the secp256r1 precompile instruction,
   * NOT applied as a Solana tx signature — so switching only changes who pays,
   * never the signing identity.
   */
  private async send(ixs: TransactionInstruction[], opts?: ExecuteOptions): Promise<string> {
    const sponsored = opts?.sponsored !== false;
    if (sponsored && this.relayer) return this.relayer.send(ixs);
    if (this.feePayer) {
      return sendAndConfirmTransaction(this.connection, new Transaction().add(...ixs), [this.feePayer]);
    }
    throw new Error(
      `kit/solana: cannot ${sponsored ? "sponsor" : "self-fund"} — no ${sponsored ? "relayer" : "feePayer"} configured`,
    );
  }
}

const defaultRegistry = new InMemoryWalletRegistry();

// De-dup window for the email device-approval request — collapses a page refresh
// / reconnect burst so the owner doesn't get one email per attempt. The backend
// already dedups by request id within its 24h TTL; this client-side guard avoids
// minting fresh request ids on every reconnect. Mirrors Starknet (Cavos.ts).
const DEVICE_REQUEST_DEDUP_MS = 5 * 60 * 1000; // 5 minutes
const lastDeviceRequest = new Map<string, { requestId: string; requestedAt: number }>();

async function loadDefaultWebSigner(keyId: string): Promise<DeviceSigner> {
  if (typeof indexedDB === "undefined" || !globalThis.crypto?.subtle) {
    throw new Error(
      "kit/solana: this runtime requires a createSigner implementation; React Native apps must import @cavos/kit/react-native",
    );
  }
  const { WebCryptoSigner } = await import("../../signer/WebCryptoSigner");
  return WebCryptoSigner.loadOrCreate({ keyId });
}
