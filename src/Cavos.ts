import { Account, RpcProvider, PaymasterRpc, hash, num, ETransactionVersion3, type Call } from "starknet";
import type { Keypair } from "@solana/web3.js";
import type { AuthProvider, Identity } from "./auth/AuthProvider";
import type { DeviceSigner, DevicePublicKey } from "./signer/DeviceSigner";
import { StarknetAdapter } from "./chains/starknet/StarknetAdapter";
import { StarknetDeviceSigner } from "./chains/starknet/StarknetDeviceSigner";
import { CavosSolana } from "./chains/solana/CavosSolana";
import type { SolanaRelayer } from "./chains/solana/SolanaRelayer";
import type { SolanaNetwork } from "./chains/solana/constants";
import { CavosStellar } from "./chains/stellar/CavosStellar";
import type { StellarRelayer } from "./chains/stellar/StellarRelayer";
import type { DeviceUnwrapKey } from "./chains/stellar/DeviceUnwrapKey";
import type { StellarNetwork } from "./chains/stellar/constants";
import type { Keypair as StellarKeypair } from "@stellar/stellar-sdk";
import type { ChainCall, ExecuteOptions, ComputeAddressParams } from "./chains/ChainAdapter";
import type { WalletRegistry } from "./registry/WalletRegistry";
import { InMemoryWalletRegistry } from "./registry/WalletRegistry";
import { HttpWalletRegistry } from "./registry/HttpWalletRegistry";
import type { RecoveryClient } from "./recovery/RecoveryClient";
import { HttpRecoveryClient } from "./recovery/HttpRecoveryClient";
import { BackupSigner, deriveBackupKey } from "./recovery/BackupSigner";
import { appNamespace } from "./identity";
import { resolveAddress } from "./registry/resolveAddress";
import type { PasskeyApprover, PasskeyEnrollParams } from "./signer/PasskeyProvider";
import { webauthnDigest, recoverCandidatePublicKeys, batchChallenge } from "./crypto/webauthn";
import type { PasskeyAssertion } from "./crypto/webauthn";
import { bytesToHex, bigIntTo32Bytes, utf8ToBytes } from "./crypto/encoding";
import {
  prefixedMessageBytes,
  type MessageSignature,
  type StarknetSignedTransaction,
} from "./signing";
import {
  CAVOS_PAYMASTER_URL,
  DEVICE_ACCOUNT_CLASS_HASH,
  STARKNET_NETWORKS,
  type StarknetNetwork,
} from "./chains/starknet/constants";

/** The chains the unified `Cavos.connect` can target. */
export type Chain = "starknet" | "solana" | "stellar";

/**
 * Environment selector. `Cavos.connect` resolves it to the chain's concrete
 * network: starknet → sepolia/mainnet, solana → solana-devnet/solana-mainnet.
 */
export type NetworkEnv = "mainnet" | "testnet";

/** Resolve the abstract `{ chain, network }` to each chain's concrete network. */
const STARKNET_ENV: Record<NetworkEnv, StarknetNetwork> = {
  mainnet: "mainnet",
  testnet: "sepolia",
};
const SOLANA_ENV: Record<NetworkEnv, SolanaNetwork> = {
  mainnet: "solana-mainnet",
  testnet: "solana-devnet",
};
const STELLAR_ENV: Record<NetworkEnv, StellarNetwork> = {
  mainnet: "stellar-mainnet",
  testnet: "stellar-testnet",
};

/**
 * Chain status indicates whether an account is deployed, ready, or needs approval.
 * - `undeployed`: Address derived but no on-chain account exists yet.
 * - `ready`: Account deployed and this device is an authorized signer.
 * - `needs-device-approval`: Account deployed but this device is not yet authorized.
 */
export type ChainStatus = "undeployed" | "ready" | "needs-device-approval";

/** A connected wallet: discriminated by `chain`, so `execute()` stays native. */
export type CavosWallet = Cavos | CavosSolana | CavosStellar;

/**
 * Multi-chain session returned by `Cavos.connect` when multiple chains are configured.
 * The session IS the default chain's wallet (for back-compat), augmented with methods
 * to access other configured chains without re-connecting.
 *
 * Type-narrow on `wallet.chain` before calling chain-specific `execute()`.
 */
export interface CavosSession {
  /** The configured chains for this session. */
  readonly chains: Chain[];
  /** The default chain for this session. */
  readonly defaultChain: Chain;
  /**
   * Get the wallet for a specific configured chain. Throws if the chain is not
   * in the session's configured `chains`.
   */
  wallet(chain: Chain): CavosWallet;
  /**
   * Get the status of a specific configured chain. Returns the wallet's
   * `status` property for that chain.
   */
  chainStatus(chain: Chain): ChainStatus;
  /**
   * Get the address for a specific configured chain.
   */
  chainAddress(chain: Chain): string;
  /**
   * Enroll a passkey at session scope. For already-deployed chains, the passkey
   * is added immediately. For undeployed chains, the passkey is stored pending
   * and included in the first deploy transaction.
   *
   * One user prompt enrolls across all configured chains.
   */
  enrollPasskeySession(
    passkey: PasskeyApprover,
    params: PasskeyEnrollParams,
  ): Promise<{ publicKey: DevicePublicKey }>;
  /**
   * Set up recovery at session scope. For already-deployed chains, the recovery
   * signer is added immediately. For undeployed chains, the signer is stored
   * pending and included in the first deploy transaction.
   *
   * Returns the recovery code (only shown once).
   */
  setupRecoverySession(code: string): Promise<void>;
}

export interface ConnectOptions {
  /**
   * Target chain (single-chain mode). The returned wallet is discriminated by this value.
   * @deprecated Use `chains` and `defaultChain` for multi-chain sessions.
   * When `chains` is provided, this is ignored. If only `chain` is provided,
   * it's treated as `chains: [chain], defaultChain: chain` but connect still
   * does NOT deploy on connect (lazy deploy on first execute).
   */
  chain?: Chain;
  /**
   * Chains to configure for this session. Connect derives addresses for all
   * configured chains but NEVER deploys on connect. Deployment happens lazily
   * on the first `execute` call for each chain.
   */
  chains?: Chain[];
  /**
   * Default chain for the session. Must be in `chains`. When using the
   * single-chain `chain` option, `defaultChain` defaults to that chain.
   */
  defaultChain?: Chain;
  /** Environment. Resolved to sepolia/devnet (testnet) or mainnet per chain. */
  network: NetworkEnv;
  /** Authenticated user (pass `identity` directly, or an `auth` provider). */
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  /**
   * Cavos App ID. When set (with `backendUrl`), the kit uses the hosted
   * WalletRegistry + RecoveryClient by default for real multi-device support.
   */
  appId?: string;
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: "development" | "production";
  /** Cavos backend base URL. Defaults to https://cavos.xyz. */
  backendUrl?: string;
  /**
   * Off-chain user_id -> wallet map. Defaults to the hosted HttpWalletRegistry
   * when `appId` is set, else an in-memory registry (single-device only).
   */
  registry?: WalletRegistry;
  /**
   * Device-approval relay (Starknet). Defaults to HttpRecoveryClient when
   * `appId` is set; used to request addition of this device when it isn't a
   * signer yet.
   */
  recovery?: RecoveryClient;
  /**
   * Keep the legacy owner-device/email approval request enabled. Set false when
   * hardware-isolated social recovery owns the new-device flow.
   */
  legacyDeviceApproval?: boolean;
  rpcUrl?: string;
  /** Override the device signer factory (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;

  // --- Starknet-only ---
  /** Cavos paymaster API key (sponsors deploy + execute). Required for Starknet. */
  paymasterApiKey?: string;
  paymasterUrl?: string;
  classHash?: string;

  // --- Solana-only ---
  /** Cavos device-account program id override. */
  programId?: string;
  /** Gasless sponsorship relayer (defaults to the hosted one when `appId` set). */
  relayer?: SolanaRelayer;
  /** Self-funded fee-payer fallback when no relayer is configured. */
  feePayer?: Keypair;

  // --- Stellar-only (classic `G…` multisig) ---
  /** Gasless sponsorship relayer (defaults to the hosted one when `appId` set). */
  stellarRelayer?: StellarRelayer;
  /** Self-funded source/fee-payer Stellar keypair when no relayer is configured. */
  stellarSourceKeypair?: StellarKeypair;
  /**
   * This device's ECDH unwrap key for the Stellar control-key envelope. Defaults
   * to a persisted `WebCryptoDeviceUnwrapKey` in the browser; pass your own on
   * React Native / server.
   */
  stellarDeviceKey?: DeviceUnwrapKey;
  /** Create/load the Stellar ECDH unwrap key (native / tests). */
  createStellarDeviceKey?: (keyId: string) => Promise<DeviceUnwrapKey>;
}

/** The Starknet-specific connect options, resolved from the unified ones. */
interface StarknetConnectOptions {
  network: StarknetNetwork;
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  environment?: "development" | "production";
  backendUrl?: string;
  registry?: WalletRegistry;
  recovery?: RecoveryClient;
  legacyDeviceApproval?: boolean;
  paymasterApiKey: string;
  paymasterUrl?: string;
  rpcUrl?: string;
  classHash?: string;
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
}

/**
 * Whether this device can already operate the wallet, or needs to be added.
 * - `undeployed`: Address derived but no on-chain account exists yet. First execute will deploy.
 * - `ready`: Account deployed and this device is an authorized signer.
 * - `needs-device-approval`: Account deployed but this device is not yet authorized.
 */
export type ConnectStatus = "undeployed" | "ready" | "needs-device-approval";

/** Options for recovering an account after losing every device signer. */
export interface RecoveryOptions {
  /** The recovery code the user stored when they ran setupRecovery. */
  code: string;
  /** Authenticated identity (same user who owns the account). */
  identity: Identity;
  /** Environment (recovery is Starknet-only): testnet → sepolia, mainnet. */
  network: NetworkEnv;
  appSalt: string;
  paymasterApiKey: string;
  appId?: string;
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: "development" | "production";
  backendUrl?: string;
  rpcUrl?: string;
  paymasterUrl?: string;
  classHash?: string;
  registry?: WalletRegistry;
  /**
   * The account to recover. Optional only when `appId` is set: the address is
   * named by the first device, so it is looked up in the registry rather than
   * re-derived from the login.
   */
  address?: string;
  /** Provides the login token the registry lookup authenticates with. */
  auth?: AuthProvider;
  /** Override the new device's signer (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
}

/**
 * High-level Cavos wallet. One call logs the user in and returns a wallet handle
 * controlled by a silent device key.
 *
 * **Lazy deploy**: Connect NEVER deploys. The first `execute` call on an
 * undeployed account triggers deployment + the user operation atomically.
 *
 *   const cavos = await Cavos.connect({ network, identity, appSalt, registry, paymasterApiKey });
 *   // cavos.status may be "undeployed" — first execute will deploy
 *   await cavos.execute(calls); // deploys + runs calls atomically if undeployed
 *
 * The account address is named by the first device signer and looked up in the
 * Cavos registry; deployment status is resolved from chain state,
 * never from the hosted registry. A new device derives the same address and is
 * flagged `needs-device-approval` when its key is not authorized on-chain.
 */
export class Cavos {
  /** Discriminant for the `CavosWallet` union — narrows `execute()` per chain. */
  readonly chain = "starknet" as const;
  /** Request id of the pending device-addition, when status is needs-device-approval. */
  pendingRequestId: string | null = null;
  /** True when this connect just created & deployed a brand-new account (first
   * sign-up), so the UI can offer a one-time "secure your account" step. */
  isNewAccount = false;

  /** Track whether deployment happened (for lazy deploy). */
  private _isDeployed: boolean;
  /** Pending passkey enrollment to include in first deploy. */
  private _pendingApprover: DevicePublicKey | null = null;
  /** Pending recovery signer to include in first deploy. */
  private _pendingRecoverySigner: DevicePublicKey | null = null;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    private readonly addressParams: ComputeAddressParams,
    private readonly classHash: string,
    private statusValue: ConnectStatus,
    readonly account: Account,
    private readonly adapter: StarknetAdapter,
    private readonly devicePubkey: DevicePublicKey,
    /** Paymaster URL + API key, for the sponsored passkey-approval path. */
    private readonly paymaster?: { url: string; apiKey?: string },
    private readonly provider?: RpcProvider,
    private readonly registry?: WalletRegistry,
  ) {
    this._isDeployed = statusValue !== "undeployed";
  }

  /** Current status of this wallet. May change from "undeployed" to "ready" after first execute. */
  get status(): ConnectStatus {
    return this.statusValue;
  }

  /**
   * Unified entry point. Pick a `chain` (or `chains` + `defaultChain`) and a
   * `network` environment; the kit resolves the concrete network and returns
   * a chain-native wallet. The result is a discriminated union (`wallet.chain`),
   * so `execute()` keeps each chain's native signature.
   *
   * **Lazy deploy**: Connect NEVER deploys on connect. The first `execute` call
   * on an undeployed chain triggers deployment + the user operation atomically.
   *
   *   const wallet = await Cavos.connect({ chain: "solana", network: "testnet", identity, appSalt, appId });
   *   if (wallet.chain === "starknet") await wallet.execute(calls); // deploys here if needed
   *   else                              await wallet.execute(amount, dest);
   *
   * **Multi-chain** (new):
   *
   *   const wallet = await Cavos.connect({
   *     chains: ["solana", "stellar"],
   *     defaultChain: "stellar",
   *     network: "testnet",
   *     identity,
   *     appSalt,
   *     appId,
   *   });
   *   // wallet.chain is "stellar" (the default)
   *   // wallet.wallet("solana") → CavosSolana
   *   // wallet.chainStatus("solana") → "undeployed" | "ready" | "needs-device-approval"
   */
  static async connect(opts: ConnectOptions): Promise<CavosWallet & CavosSession> {
    // Resolve chains configuration: `chains`/`defaultChain` takes precedence,
    // `chain` alone is back-compat alias meaning `chains: [chain], defaultChain: chain`.
    const configuredChains = opts.chains ?? (opts.chain ? [opts.chain] : ["starknet" as Chain]);
    const defaultChain = opts.defaultChain ?? configuredChains[0];

    if (configuredChains.length === 0) {
      throw new Error("kit: at least one chain must be configured");
    }
    if (!configuredChains.includes(defaultChain)) {
      throw new Error(`kit: defaultChain "${defaultChain}" must be in chains [${configuredChains.join(", ")}]`);
    }

    // Resolve identity up-front (needed by Stellar and for session-level operations)
    const identity = opts.identity ?? (opts.auth ? await opts.auth.authenticate() : undefined);
    if (!identity) throw new Error("kit: connect requires `identity` or `auth`");

    // Connect ALL configured chains in parallel
    const walletPromises = configuredChains.map((chain) =>
      Cavos.connectSingleChain(chain, { ...opts, identity }),
    );
    const wallets = await Promise.all(walletPromises);

    // Build the wallet map
    const walletMap = new Map<Chain, CavosWallet>();
    for (let i = 0; i < configuredChains.length; i++) {
      walletMap.set(configuredChains[i], wallets[i]);
    }

    // Get the default chain wallet
    const defaultWallet = walletMap.get(defaultChain)!;

    // Create session methods and attach them to the default wallet
    const session: CavosSession = {
      chains: configuredChains,
      defaultChain,
      wallet(chain: Chain): CavosWallet {
        const w = walletMap.get(chain);
        if (!w) {
          throw new Error(`kit: chain "${chain}" is not configured in this session. Configured chains: [${configuredChains.join(", ")}]`);
        }
        return w;
      },
      chainStatus(chain: Chain): ChainStatus {
        const w = walletMap.get(chain);
        if (!w) {
          throw new Error(`kit: chain "${chain}" is not configured in this session. Configured chains: [${configuredChains.join(", ")}]`);
        }
        return w.status;
      },
      chainAddress(chain: Chain): string {
        const w = walletMap.get(chain);
        if (!w) {
          throw new Error(`kit: chain "${chain}" is not configured in this session. Configured chains: [${configuredChains.join(", ")}]`);
        }
        return w.address;
      },
      async enrollPasskeySession(passkey: PasskeyApprover, params: PasskeyEnrollParams) {
        // Enroll passkey on the first deployed chain to get the public key,
        // then propagate to other chains without re-prompting.
        const enrolled = await passkey.enroll(params);
        const publicKey = enrolled.publicKey;

        // For each chain: if deployed, add approver now; if undeployed, store pending
        for (const chain of configuredChains) {
          const w = walletMap.get(chain)!;
          if (w.chain === "stellar") {
            // Stellar uses PRF-based passkey, not approver pattern. Skip for now.
            // Session-level Stellar passkey enrollment would need a separate flow.
            continue;
          }
          await w.addApprover(publicKey);
        }

        return { publicKey };
      },
      async setupRecoverySession(code: string) {
        // For each chain: set up recovery (deployed: immediate; undeployed: pending)
        for (const chain of configuredChains) {
          const w = walletMap.get(chain)!;
          await w.setupRecovery(code);
        }
      },
    };

    // Return the default wallet with session methods attached
    return Object.assign(defaultWallet, session);
  }

  /**
   * Connect a single chain. Internal helper for multi-chain connect.
   */
  private static async connectSingleChain(
    chain: Chain,
    opts: ConnectOptions & { identity: Identity },
  ): Promise<CavosWallet> {
    if (chain === "solana") {
      return CavosSolana.connect({
        network: SOLANA_ENV[opts.network],
        identity: opts.identity,
        appSalt: opts.appSalt,
        ...(opts.appId ? { appId: opts.appId } : {}),
        ...(opts.environment ? { environment: opts.environment } : {}),
        ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
        ...(opts.registry ? { registry: opts.registry } : {}),
        ...(opts.rpcUrl ? { rpcUrl: opts.rpcUrl } : {}),
        ...(opts.programId ? { programId: opts.programId } : {}),
        ...(opts.createSigner ? { createSigner: opts.createSigner } : {}),
        ...(opts.relayer ? { relayer: opts.relayer } : {}),
        ...(opts.feePayer ? { feePayer: opts.feePayer } : {}),
        ...(opts.legacyDeviceApproval !== undefined
          ? { legacyDeviceApproval: opts.legacyDeviceApproval }
          : {}),
      });
    }
    if (chain === "stellar") {
      const keyId = `${opts.identity.userId}:${opts.appSalt}`;
      const deviceKey = opts.stellarDeviceKey
        ?? (opts.createStellarDeviceKey
          ? await opts.createStellarDeviceKey(keyId)
          : await loadDefaultWebDeviceKey(keyId));
      return CavosStellar.connect({
        network: STELLAR_ENV[opts.network],
        identity: opts.identity,
        appSalt: opts.appSalt,
        deviceKey,
        ...(opts.appId ? { appId: opts.appId } : {}),
        ...(opts.environment ? { environment: opts.environment } : {}),
        ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
        ...(opts.stellarRelayer ? { relayer: opts.stellarRelayer } : {}),
        ...(opts.stellarSourceKeypair ? { sourceKeypair: opts.stellarSourceKeypair } : {}),
      });
    }
    // Starknet
    if (!opts.paymasterApiKey) {
      throw new Error("kit: `paymasterApiKey` is required for Starknet connections");
    }
    return Cavos.connectStarknet({
      network: STARKNET_ENV[opts.network],
      identity: opts.identity,
      appSalt: opts.appSalt,
      appId: opts.appId,
      environment: opts.environment,
      backendUrl: opts.backendUrl,
      registry: opts.registry,
      recovery: opts.recovery,
      legacyDeviceApproval: opts.legacyDeviceApproval,
      paymasterApiKey: opts.paymasterApiKey,
      paymasterUrl: opts.paymasterUrl,
      rpcUrl: opts.rpcUrl,
      classHash: opts.classHash,
      createSigner: opts.createSigner,
    });
  }

  private static async connectStarknet(opts: StarknetConnectOptions): Promise<Cavos> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit: connect requires `identity` or `auth`");

    const classHash = opts.classHash ?? DEVICE_ACCOUNT_CLASS_HASH[opts.network];
    if (!classHash) throw new Error(`kit: no DeviceAccount class hash for ${opts.network}`);

    const provider = new RpcProvider({
      nodeUrl: opts.rpcUrl ?? STARKNET_NETWORKS[opts.network].rpcUrl,
    });
    const paymasterUrl = opts.paymasterUrl ?? CAVOS_PAYMASTER_URL[opts.network];
    const paymasterConfig = { url: paymasterUrl, apiKey: opts.paymasterApiKey };
    const paymaster = new PaymasterRpc({
      nodeUrl: paymasterUrl,
      headers: { "x-paymaster-api-key": opts.paymasterApiKey },
    });

    // This device's silent signer.
    const signer = opts.createSigner
      ? await opts.createSigner(`${identity.userId}:${opts.appSalt}`)
      : await loadDefaultWebSigner(`${identity.userId}:${opts.appSalt}`);
    const devicePubkey = await signer.getPublicKey();

    const adapter = new StarknetAdapter({ classHash, signer, provider });
    const makeAccount = (address: string) =>
      new Account({
        provider,
        address,
        signer: new StarknetDeviceSigner(signer),
        paymaster,
        cairoVersion: "1",
      });

    // The registry is the source of truth for this user's address, so a lookup
    // failure fails the connect (see resolveAddress): a second wallet for the
    // same user is worse than an error.
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
    const recovery =
      opts.recovery ?? (opts.appId ? new HttpRecoveryClient({ baseUrl: backendUrl, appId: opts.appId, environment: opts.environment }) : null);

    const namespace = appNamespace({ appId: opts.appId ?? "local", environmentId: opts.environment });
    const addressParams = { namespace, initialSigner: devicePubkey };
    const { address } = await resolveAddress({
      key: { userId: identity.userId, appId: opts.appId ?? "local", chain: "starknet", network: opts.network },
      registry: opts.appId ? registry : null,
      initialSigner: devicePubkey,
      compute: () => adapter.computeAddress(addressParams),
    });
    const account = makeAccount(address);

    // LAZY DEPLOY: Check deployment status but DO NOT deploy here.
    // Deployment happens on first execute() call.
    const alreadyDeployed = await isDeployed(provider, address);

    // Determine status: undeployed, ready, or needs-device-approval
    let status: ConnectStatus;
    let isSigner = false;

    if (!alreadyDeployed) {
      // Account not deployed yet — first execute will deploy + initialize
      status = "undeployed";
    } else {
      // Account exists — check if this device is authorized
      try {
        isSigner = await adapter.isAuthorizedSigner(address, devicePubkey);
      } catch (e) {
        console.warn("[Cavos] isAuthorizedSigner read failed:", e);
        isSigner = false;
      }
      status = isSigner ? "ready" : "needs-device-approval";
    }

    const cavos = new Cavos(
      identity,
      address,
      addressParams,
      classHash,
      status,
      account,
      adapter,
      devicePubkey,
      paymasterConfig,
      provider,
      registry,
    );
    // isNewAccount is set after first deploy in execute(), not here
    cavos.isNewAccount = false;

    // Deployed account, but THIS device isn't an authorized signer yet — request approval
    if (status === "needs-device-approval" && recovery && opts.legacyDeviceApproval !== false) {
      const dedup = lastDeviceRequest.get(identity.userId);
      const fresh = dedup && Date.now() - dedup.requestedAt < DEVICE_REQUEST_DEDUP_MS;
      try {
        if (fresh) {
          cavos.pendingRequestId = dedup!.requestId;
        } else {
          const { requestId } = await recovery.requestDeviceAddition({
            userId: identity.userId,
            accountAddress: address,
            newSigner: devicePubkey,
            ...(identity.email ? { email: identity.email } : {}),
          });
          cavos.pendingRequestId = requestId;
          lastDeviceRequest.set(identity.userId, { requestId, requestedAt: Date.now() });
        }
      } catch (e) {
        console.warn("[Cavos] requestDeviceAddition failed:", e);
      }
    }
    return cavos;
  }

  /** This device's public key (e.g. to request addition to an existing wallet). */
  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  /**
   * Execute a sponsored (gasless) multicall, signed silently by the device.
   *
   * **Lazy deploy**: If the account is undeployed, the first execute deploys +
   * initializes + runs the calls atomically in a single sponsored transaction.
   * The status changes from "undeployed" to "ready" after successful execution.
   */
  async execute(calls: ChainCall[], opts?: ExecuteOptions): Promise<{ transactionHash: string }> {
    // Handle lazy deploy: first execute on undeployed account
    if (this.statusValue === "undeployed") {
      return this._deployAndExecute(calls, opts);
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit: this device is not yet an authorized signer of the wallet");
    }

    // `sponsored` defaults to true → paymaster pays the gas. Pass `sponsored:
    // false` to submit directly: the account pays its own fee from its ETH
    // balance (starknet.js' `Account.execute` ignores the paymaster entirely, so
    // the same Account instance works for both paths). Both return
    // { transaction_hash }.
    if (opts?.sponsored === false) {
      const res = await this.account.execute(calls as Call[]);
      return { transactionHash: res.transaction_hash };
    }
    const res = await this.account.executePaymasterTransaction(calls as Call[], {
      feeMode: { mode: "sponsored" },
    });
    return { transactionHash: res.transaction_hash };
  }

  /**
   * Deploy + initialize + execute calls atomically in a single sponsored transaction.
   * Called automatically by execute() when status is "undeployed".
   */
  private async _deployAndExecute(
    userCalls: ChainCall[],
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string }> {
    // Build deployment data for the paymaster
    const deploymentData = {
      address: this.address,
      class_hash: this.classHash,
      salt: num.toHex(this.adapter.salt(this.addressParams)),
      calldata: this.adapter.constructorCalldata(this.addressParams),
      version: 1 as const,
    };

    // The constructor registers this device as the first signer, so there is no
    // initialize call — only the pending factors and the user's own calls.
    const allCalls: ChainCall[] = [];

    // 1. Add pending approver if enrolled before first deploy
    if (this._pendingApprover) {
      allCalls.push(this.adapter.buildAddApprover(this.address, this._pendingApprover));
    }

    // 2. Add pending recovery signer if set up before first deploy
    if (this._pendingRecoverySigner) {
      allCalls.push(this.adapter.buildAddSigner(this.address, this._pendingRecoverySigner));
    }

    // 3. User's calls
    allCalls.push(...userCalls);

    // Self-funded deploy is not supported — deploy always needs paymaster sponsorship
    if (opts?.sponsored === false) {
      throw new Error(
        "kit: self-funded deploy is not supported. The first execute on an undeployed account requires sponsored mode.",
      );
    }

    // Execute deploy + init + calls atomically via paymaster
    const res = await this.account.executePaymasterTransaction(allCalls as Call[], {
      feeMode: { mode: "sponsored" },
      deploymentData,
    });

    // Wait for the transaction to land before updating status
    if (this.provider) {
      try {
        await this.provider.waitForTransaction(res.transaction_hash);
      } catch (e) {
        console.warn("[Cavos] deploy+execute receipt wait failed:", e);
      }
    }

    // Update status to ready
    this._isDeployed = true;
    this.statusValue = "ready";
    this.isNewAccount = true;

    // Clear pending factors
    this._pendingApprover = null;
    this._pendingRecoverySigner = null;

    // Register with registry (best-effort)
    if (this.registry) {
      try {
        await this.registry.register({
          userId: this.identity.userId,
          address: this.address,
          initialSigner: this.devicePubkey,
        });
      } catch (e) {
        console.warn("[Cavos/starknet] registry.register failed (non-fatal):", e);
      }
    }

    return { transactionHash: res.transaction_hash };
  }

  /**
   * Sign an arbitrary message off-chain with the device key. Nothing is
   * submitted; no gas is paid. The signature is over `sha256(prefixedMessage)`
   * where the prefix is `"Cavos Signed Message:\n<len>\n"` (EIP-191-style).
   * A verifier recovers the secp256r1 pubkey from `(r, s, yParity)` over that
   * digest and compares it to the wallet's device pubkey.
   *
   * `publicKey` in the result is the uncompressed hex `04‖x‖y` of the device key.
   */
  async signMessage(message: string | Uint8Array): Promise<MessageSignature> {
    if (this.status !== "ready") {
      throw new Error("kit: this device is not yet an authorized signer of the wallet");
    }
    const msgBytes = typeof message === "string" ? utf8ToBytes(message) : message;
    const prefixed = prefixedMessageBytes(msgBytes);
    const sig = await this.adapter.signMessageRaw(prefixed);
    // 64-byte r‖s (Starknet's contract normalizes high-s, so no low-S needed here).
    const signature = new Uint8Array(64);
    signature.set(bigIntTo32Bytes(sig.r), 0);
    signature.set(bigIntTo32Bytes(sig.s), 32);
    const pk = this.devicePubkey;
    const publicKey =
      "04" + bytesToHex(bigIntTo32Bytes(pk.x)).slice(2) + bytesToHex(bigIntTo32Bytes(pk.y)).slice(2);
    return { signature, publicKey, curve: "secp256r1" };
  }

  /**
   * Build + sign a multicall WITHOUT submitting it. Returns the signed invoke
   * (calldata + 5-felt device signature + nonce + resource bounds). A relayer
   * can broadcast it later via the account's `invokeFunction`.
   *
   * The signature binds to the nonce and resource bounds at sign time — if any
   * other transaction from this account is submitted first, this signature is
   * invalid. Broadcast promptly.
   */
  async signTransaction(calls: ChainCall[]): Promise<StarknetSignedTransaction> {
    if (this.status !== "ready") {
      throw new Error("kit: this device is not yet an authorized signer of the wallet");
    }
    // Estimate fee to obtain nonce + resource bounds, then build + sign the
    // invocation without invoking `invokeFunction` (no submission).
    const fee = await this.account.estimateInvokeFee(calls as Call[], {
      skipValidate: false,
    });
    const nonce = await this.account.getNonce();
    const built = await this.account.accountInvocationsFactory(
      [{ type: "INVOKE" as const, payload: calls as Call[] }],
      {
        versions: [ETransactionVersion3.V3],
        nonce,
        resourceBounds: fee.resourceBounds,
        skipValidate: false,
      },
    );
    const inv = built[0] as unknown as {
      calldata: string[];
      signature: string | string[];
      nonce: string;
      resourceBounds: typeof fee.resourceBounds;
      version: string;
    };
    const signature = Array.isArray(inv.signature) ? inv.signature.map(String) : [String(inv.signature)];
    const rb = inv.resourceBounds ?? fee.resourceBounds;
    return {
      chain: "starknet",
      calldata: inv.calldata ?? [],
      signature,
      nonce: String(inv.nonce ?? nonce),
      resourceBounds: {
        l1Gas: {
          maxAmount: String((rb as { l1_gas: { max_amount: bigint } }).l1_gas.max_amount),
          maxPricePerUnit: String((rb as { l1_gas: { max_price_per_unit: bigint } }).l1_gas.max_price_per_unit),
        },
        l2Gas: {
          maxAmount: String((rb as { l2_gas: { max_amount: bigint } }).l2_gas.max_amount),
          maxPricePerUnit: String((rb as { l2_gas: { max_price_per_unit: bigint } }).l2_gas.max_price_per_unit),
        },
      },
      version: String(inv.version ?? ETransactionVersion3.V3),
    };
  }

  /**
   * Authorize an additional device signer. Sponsored by default; pass
   * `{ sponsored: false }` to pay the fee from the account's own ETH balance.
   */
  async addSigner(
    pubkey: DevicePublicKey,
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string }> {
    return this.execute([this.adapter.buildAddSigner(this.address, pubkey)], opts);
  }

  /**
   * Revoke a device signer — the escape hatch behind the "this wasn't me" link
   * in the device-added email. Sponsored by default; pass `{ sponsored: false }`
   * to pay the fee from the account's own ETH balance.
   *
   * Authorization is an ordinary device self-call: only a device that is ALREADY
   * an authorized signer can revoke another one. Cavos holds no key that can do
   * this on the user's behalf.
   */
  async removeSigner(
    pubkey: DevicePublicKey,
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string }> {
    if (this.status !== "ready") {
      throw new Error("kit: removeSigner requires a device that is already an authorized signer");
    }
    if (pubkey.x === this.devicePubkey.x && pubkey.y === this.devicePubkey.y) {
      throw new Error(
        "kit: cannot revoke the device you are signing with — revoke it from another authorized device",
      );
    }
    // Cheap read that avoids burning gas on a revert when the target was already
    // removed (e.g. the email link opened twice).
    const authorized = await this.adapter.isAuthorizedSigner(this.address, pubkey);
    if (!authorized) {
      throw new Error("kit: that device is not an authorized signer of this wallet");
    }
    return this.execute([this.adapter.buildRemoveSigner(this.address, pubkey)], opts);
  }

  /** Upgrade this account instance to a reviewed class. Existing account
   * addresses/storage are preserved; authorization is a normal device self-call. */
  async upgrade(
    newClassHash: string,
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string }> {
    if (this.status !== "ready") {
      throw new Error("kit: account upgrade requires a ready device");
    }
    return this.execute([this.adapter.buildUpgrade(this.address, newClassHash)], opts);
  }

  /** Enrol the P-256 authority generated inside the enclave. The call is a
   * normal device-signed self-call; the recovery key never becomes a signer. */
  async enrollSocialRecovery(params: {
    recoveryXHex: string;
    recoveryYHex: string;
    delaySeconds: number;
    policyHashHex: string;
    opts?: ExecuteOptions;
  }): Promise<{ transactionHash: string }> {
    if (this.status !== "ready") {
      throw new Error("kit: social recovery enrolment requires a ready device");
    }
    return this.execute(
      [
        this.adapter.buildEnrollSocialRecovery(
          this.address,
          { x: BigInt(params.recoveryXHex), y: BigInt(params.recoveryYHex) },
          BigInt(params.delaySeconds),
          BigInt(params.policyHashHex),
        ),
      ],
      params.opts,
    );
  }

  async socialRecoveryNonce(): Promise<bigint> {
    return this.adapter.getSocialRecoveryNonce(this.address);
  }

  /** Submit an enclave authorization through the direct paymaster path. This
   * entrypoint is intentionally public: its embedded P-256 signature is the
   * authorization, not the new device. */
  async scheduleSocialRecovery(params: {
    nonce: bigint;
    expiresAt: bigint;
    rHex: string;
    sHex: string;
    yParity: boolean;
    submit?: (call: ChainCall) => Promise<{ transactionHash: string }>;
  }): Promise<{ transactionHash: string }> {
    const call = this.adapter.buildScheduleSocialRecovery({
      accountAddress: this.address,
      newSigner: this.devicePubkey,
      nonce: params.nonce,
      expiresAt: params.expiresAt,
      r: BigInt(params.rHex),
      s: BigInt(params.sHex),
      yParity: params.yParity,
    });
    if (params.submit) return params.submit(call);
    if (!this.paymaster) throw new Error("kit: no paymaster configured for social recovery");
    const submitted = await paymasterExecuteDirect(this.paymaster, this.address, call);
    // A zero-delay recovery finalizes immediately after scheduling. The direct
    // paymaster returns as soon as the transaction is submitted, so wait until
    // Starknet has applied the pending recovery state before finalize reads it.
    await this.account.waitForTransaction(submitted.transactionHash);
    return submitted;
  }

  async finalizeSocialRecovery(
    submit?: (call: ChainCall) => Promise<{ transactionHash: string }>,
  ): Promise<{ transactionHash: string }> {
    const call = this.adapter.buildFinalizeSocialRecovery(this.address);
    if (submit) return submit(call);
    if (!this.paymaster) throw new Error("kit: no paymaster configured for social recovery");
    return paymasterExecuteDirect(this.paymaster, this.address, call);
  }

  async cancelSocialRecovery(
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string }> {
    return this.execute(
      [this.adapter.buildCancelSocialRecovery(this.address)],
      opts,
    );
  }

  /**
   * Enroll a passkey as an APPROVER so the user can later add devices from any
   * browser (2FA-style step-up). Idempotent: a no-op if the passkey is already
   * an approver.
   *
   * **Undeployed accounts**: The passkey is stored pending and will be included
   * in the first deploy transaction. No on-chain write happens until execute().
   *
   * Call this whenever the app decides to prompt "turn on device approvals".
   * Returns the passkey's public key + the enrollment tx hash (if deployed).
   */
  async enrollPasskey(
    passkey: PasskeyApprover,
    params: PasskeyEnrollParams,
    opts?: ExecuteOptions,
  ): Promise<{ publicKey: DevicePublicKey; transactionHash?: string }> {
    const enrolled = await passkey.enroll(params);
    const { transactionHash } = await this.addApprover(enrolled.publicKey, opts);
    return { publicKey: enrolled.publicKey, transactionHash };
  }

  /**
   * Register an ALREADY-enrolled passkey public key as an approver (gasless by
   * default, device-signed). Idempotent. Use this to register ONE passkey across
   * multiple chains without re-prompting `passkey.enroll()` on each: enroll once,
   * then call `addApprover(pubkey)` on each chain's wallet.
   *
   * **Undeployed accounts**: The approver is stored pending and will be included
   * in the first deploy transaction. No on-chain write happens until execute().
   *
   * Pass `{ sponsored: false }` to pay the fee from the account's own balance.
   */
  async addApprover(
    pubkey: DevicePublicKey,
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash?: string }> {
    // For undeployed accounts, store the pending approver for first deploy
    if (this.statusValue === "undeployed") {
      this._pendingApprover = pubkey;
      return {}; // No tx yet — will be included in first deploy
    }

    if (this.statusValue !== "ready") {
      throw new Error("kit: addApprover requires a ready, authorized device");
    }
    if (await this.adapter.isApprover(this.address, pubkey)) return {};
    const { transactionHash } = await this.execute(
      [this.adapter.buildAddApprover(this.address, pubkey)],
      opts,
    );
    // Confirm the approver is actually on-chain before returning: a new device
    // detects the passkey by reading `get_approver_count`, so a fire-and-forget
    // submit that never mines would leave the user stuck on the email flow.
    try {
      await this.account.waitForTransaction(transactionHash);
    } catch (e) {
      console.warn("[Cavos] add_approver receipt wait failed:", e);
    }
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
   * Cheap and side-effect free — used to poll for readiness after a passkey /
   * device approval submits, before the new signer is indexed.
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
   * Whether this account is deployed on-chain. Used to check if the first
   * execute will trigger deployment.
   */
  get isDeployed(): boolean {
    return this._isDeployed;
  }

  /**
   * From a brand-new browser (status `needs-device-approval`), use the user's
   * synced passkey to authorize adding THIS device — no trip back to an already-
   * authorized device.
   *
   * `add_signer_via_passkey` is a public external authorized by the embedded
   * WebAuthn assertion (no device signature), so by default we sponsor it through
   * the Cavos paymaster's `paymaster_executeDirectTransaction` (the forwarder's
   * `execute_sponsored` runs a generic call — it does NOT require SNIP-9). Pass a
   * custom `submit` to route it through your own relayer instead. Returns the tx.
   */
  async approveThisDeviceWithPasskey(opts: {
    passkey: PasskeyApprover;
    submit?: (call: ChainCall) => Promise<{ transactionHash: string }>;
  }): Promise<{ transactionHash: string }> {
    if (this.status === "ready") {
      throw new Error("kit: this device is already an authorized signer");
    }
    const { leaf, nonce } = await this.passkeyLeafForThisDevice();
    const leaves = [leaf];
    const assertion = await opts.passkey.assert(batchChallenge(leaves));
    return this.submitPasskeyApproval(assertion, leaves, 0, nonce, opts.submit);
  }

  /** This device's leaf + the current passkey nonce, for a (possibly multi-chain)
   * passkey approval batch. See `approveDeviceEverywhere`. */
  async passkeyLeafForThisDevice(): Promise<{ leaf: Uint8Array; nonce: bigint }> {
    const nonce = await this.adapter.getPasskeyNonce(this.address);
    return { leaf: this.adapter.passkeyLeaf(this.devicePubkey, nonce), nonce };
  }

  /** Submit `add_signer_via_passkey` given a (shared) assertion + this chain's
   * position in the batch. The assertion doesn't carry the passkey pubkey, so we
   * recover both candidates and pick the enrolled approver via the on-chain view
   * (no backend). Defaults to sponsoring through the paymaster. */
  async submitPasskeyApproval(
    assertion: PasskeyAssertion,
    leaves: Uint8Array[],
    leafIndex: number,
    nonce: bigint,
    submit?: (call: ChainCall) => Promise<{ transactionHash: string }>,
  ): Promise<{ transactionHash: string }> {
    const digest = webauthnDigest(assertion.authenticatorData, assertion.clientDataJSON);
    const candidates = recoverCandidatePublicKeys(assertion.r, assertion.s, digest);
    let yParity: boolean | null = null;
    for (const cand of candidates) {
      if (await this.adapter.isApprover(this.address, cand.publicKey)) {
        yParity = cand.yParity;
        break;
      }
    }
    if (yParity === null) {
      throw new Error("kit: this passkey is not a registered approver of the wallet");
    }
    const call = this.adapter.buildAddSignerViaPasskey(
      this.address, this.devicePubkey, nonce, leaves, leafIndex, assertion, yParity,
    );
    if (submit) return submit(call);
    if (!this.paymaster) {
      throw new Error("kit: no paymaster configured — pass a `submit` relayer to approveThisDeviceWithPasskey");
    }
    return paymasterExecuteDirect(this.paymaster, this.address, call);
  }

  /**
   * Register a self-custodial backup signer derived from `code`, so the account
   * can be recovered after the user loses every device. Idempotent: if the
   * derived backup key is already an authorised signer, this is a no-op.
   *
   * **Undeployed accounts**: The backup signer is stored pending and will be
   * included in the first deploy transaction. No on-chain write happens until
   * execute().
   *
   * The code never leaves the device — only its deterministic public key is
   * added on-chain as an ordinary signer. Sponsor this like any other
   * add_signer (gasless). Returns the transaction hash (or undefined when the
   * backup was already set up or account is undeployed).
   */
  async setupRecovery(
    code: string,
    opts?: ExecuteOptions,
  ): Promise<{ transactionHash: string } | undefined> {
    const { publicKey: backupPubkey } = deriveBackupKey(code);

    // For undeployed accounts, store the pending recovery signer for first deploy
    if (this.statusValue === "undeployed") {
      this._pendingRecoverySigner = backupPubkey;
      return undefined; // No tx yet — will be included in first deploy
    }

    // Skip the on-chain call if the backup signer is already registered.
    const already = await this.adapter.isAuthorizedSigner(this.address, backupPubkey);
    if (already) return undefined;
    return this.addSigner(backupPubkey, opts);
  }

  /**
   * Recover an account after losing every device signer. Derives the backup key
   * from `code`, uses it (not the new device key) to sign an `add_signer` for
   * the new device, and returns a ready Cavos bound to the new device. The
   * account address is unchanged.
   *
   * Self-custodial: only someone holding the code (i.e. the rightful owner) can
   * re-derive the backup key. The backend never sees the code.
   */
  static async recover(opts: RecoveryOptions): Promise<Cavos> {
    const network = STARKNET_ENV[opts.network];
    const classHash = opts.classHash ?? DEVICE_ACCOUNT_CLASS_HASH[network];
    if (!classHash) throw new Error(`kit: no DeviceAccount class hash for ${network}`);

    const provider = new RpcProvider({
      nodeUrl: opts.rpcUrl ?? STARKNET_NETWORKS[network].rpcUrl,
    });
    const paymaster = new PaymasterRpc({
      nodeUrl: opts.paymasterUrl ?? CAVOS_PAYMASTER_URL[network],
      headers: { "x-paymaster-api-key": opts.paymasterApiKey },
    });

    // The new device's signer (created/loaded the same way connect() does).
    const signer = opts.createSigner
      ? await opts.createSigner(`${opts.identity.userId}:${opts.appSalt}`)
      : await loadDefaultWebSigner(`${opts.identity.userId}:${opts.appSalt}`);
    const devicePubkey = await signer.getPublicKey();

    // The backup key drives THIS transaction: it's the only signer that can
    // authorise adding the new device after all device keys are lost.
    const backup = BackupSigner.fromCode(opts.code);
    const backupAdapter = new StarknetAdapter({ classHash, signer: backup, provider });

    // The address is named by the first device, so it cannot be re-derived from
    // a login: it comes from the registry, or the caller passes it explicitly.
    const registry = opts.appId
      ? new HttpWalletRegistry({
          baseUrl: opts.backendUrl ?? "https://cavos.xyz",
          appId: opts.appId,
          network,
          ...(opts.environment ? { environment: opts.environment } : {}),
          authToken: () => opts.auth?.getAuthToken?.() ?? null,
        })
      : null;
    const address =
      opts.address ?? (await registry?.lookup(opts.identity.userId))?.address;
    if (!address) {
      throw new Error(
        "kit: cannot find this user's wallet — pass `address`, or set `appId` so the registry can be consulted",
      );
    }
    if (!(await isDeployed(provider, address))) {
      throw new Error("kit: no account found for this identity — nothing to recover");
    }
    const existing = { address } as { address: string };

    // Authorise the new device, signed by the backup key (sponsored).
    const backupAccount = new Account({
      provider,
      address: existing.address,
      signer: new StarknetDeviceSigner(backup),
      paymaster,
      cairoVersion: "1",
    });
    const alreadyAuthed = await backupAdapter.isAuthorizedSigner(existing.address, devicePubkey);
    if (!alreadyAuthed) {
      const res = await backupAccount.executePaymasterTransaction(
        [backupAdapter.buildAddSigner(existing.address, devicePubkey)],
        { feeMode: { mode: "sponsored" } },
      );
      try {
        await provider.waitForTransaction(res.transaction_hash);
      } catch (e) {
        console.warn("[Cavos] recovery add_signer receipt wait failed:", e);
      }
    }

    // Hand control to the new device's signer for all future operations.
    const adapter = new StarknetAdapter({ classHash, signer, provider });
    const account = new Account({
      provider,
      address: existing.address,
      signer: new StarknetDeviceSigner(signer),
      paymaster,
      cairoVersion: "1",
    });
    const paymasterUrl = opts.paymasterUrl ?? CAVOS_PAYMASTER_URL[network];
    const paymasterConfig = { url: paymasterUrl, apiKey: opts.paymasterApiKey };
    return new Cavos(
      opts.identity,
      existing.address,
      {
        namespace: appNamespace({ appId: opts.appId ?? "local", environmentId: opts.environment }),
        initialSigner: devicePubkey,
      },
      classHash,
      "ready",
      account,
      adapter,
      devicePubkey,
      paymasterConfig,
      provider,
      undefined, // registry not needed for recovered account
    );
  }
}

/**
 * Shared in-memory registry used when `ConnectOptions.registry` is omitted.
 * Module-level so a returning user is recognized within a single browser session
 * (real cross-device recognition needs an HTTP backend implementation).
 */
const defaultRegistry = new InMemoryWalletRegistry();

/**
 * Client-side de-duplication of device-addition requests, keyed by user id. A
 * burst of connects (refresh, reconnect, retry) within this window reuses the
 * last requestId instead of emailing the owner again. Runtime-agnostic — works
 * without DOM/localStorage so the same code runs on native.
 */
const DEVICE_REQUEST_DEDUP_MS = 5 * 60 * 1000; // 5 minutes
const lastDeviceRequest = new Map<string, { requestId: string; requestedAt: number }>();

/** Whether an account contract is already deployed at `address`. */
async function isDeployed(provider: RpcProvider, address: string): Promise<boolean> {
  try {
    const classHash = await provider.getClassHashAt(address);
    return !!classHash && classHash !== "0x0";
  } catch {
    return false;
  }
}

/** A chain wallet that can approve THIS device via a batched WebAuthn assertion
 * (implemented by `Cavos` and `CavosSolana`). Classic Stellar uses a WebAuthn PRF
 * factor instead (`CavosStellar.approveThisDeviceWithPasskey`), so it is
 * not part of this batch. */
export interface PasskeyApprovable {
  readonly chain: string;
  readonly status: string;
  passkeyLeafForThisDevice(): Promise<{ leaf: Uint8Array; nonce: bigint }>;
  submitPasskeyApproval(
    assertion: PasskeyAssertion,
    leaves: Uint8Array[],
    leafIndex: number,
    nonce: bigint,
  ): Promise<{ transactionHash: string }>;
}

/**
 * Approve THIS device across several chains with a SINGLE passkey prompt. Each
 * chain is a separate account, so the device must be added per chain — but one
 * WebAuthn assertion over the batch challenge (`sha256(concat(leaves))`) suffices
 * for all of them. Only wallets whose status is `needs-device-approval` are
 * touched. Returns the per-chain tx hashes.
 *
 *   await approveDeviceEverywhere([starknet, solana], passkey);
 */
export async function approveDeviceEverywhere(
  wallets: PasskeyApprovable[],
  passkey: PasskeyApprover,
): Promise<{ chain: string; transactionHash?: string; error?: string }[]> {
  const targets = wallets.filter((w) => w.status === "needs-device-approval");
  if (targets.length === 0) return [];
  const infos = await Promise.all(targets.map((w) => w.passkeyLeafForThisDevice()));
  const leaves = infos.map((i) => i.leaf);
  // ONE prompt: the passkey signs the batch challenge over every chain's leaf.
  const assertion = await passkey.assert(batchChallenge(leaves));
  // Submit every chain IN PARALLEL (they're independent accounts) with error
  // ISOLATION: one chain's relay/RPC failure must not abort the others. The same
  // assertion authorizes all of them, so this is a single user gesture that fans
  // out to every chain at once. Failures are reported, never thrown.
  const settled = await Promise.allSettled(
    targets.map((w, i) => w.submitPasskeyApproval(assertion, leaves, i, infos[i].nonce)),
  );
  return settled.map((r, i) =>
    r.status === 'fulfilled'
      ? { chain: targets[i].chain, transactionHash: r.value.transactionHash }
      : {
          chain: targets[i].chain,
          error: r.reason instanceof Error ? r.reason.message : String(r.reason),
        },
  );
}

/**
 * Sponsor a single call through the Cavos paymaster's `paymaster_executeDirectTransaction`
 * (AVNU-fork extension). In sponsored mode the forwarder runs a generic
 * `call_contract_syscall` (no SNIP-9 / device signature required), so the
 * passkey-authorized `add_signer_via_passkey` external is paid for by the
 * paymaster's relayer. The account's on-chain check (approver membership +
 * challenge binding) is the real authorization.
 */
async function paymasterExecuteDirect(
  paymaster: { url: string; apiKey?: string },
  userAddress: string,
  call: ChainCall,
): Promise<{ transactionHash: string }> {
  const body = {
    jsonrpc: "2.0",
    id: 1,
    method: "paymaster_executeDirectTransaction",
    params: {
      transaction: {
        type: "invoke",
        invoke: {
          user_address: userAddress,
          execute_from_outside_call: {
            to: call.contractAddress,
            selector: hash.getSelectorFromName(call.entrypoint),
            calldata: call.calldata.map((c) => num.toHex(c)),
          },
        },
      },
      parameters: { version: "0x1", fee_mode: { mode: "sponsored" } },
    },
  };
  const res = await fetch(paymaster.url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      ...(paymaster.apiKey ? { "x-paymaster-api-key": paymaster.apiKey } : {}),
    },
    body: JSON.stringify(body),
  });
  const json = await res.json();
  if (json.error) {
    throw new Error(`kit: paymaster direct transaction failed: ${JSON.stringify(json.error)}`);
  }
  return { transactionHash: json.result?.transaction_hash ?? json.result?.tracking_id };
}

async function loadDefaultWebSigner(keyId: string): Promise<DeviceSigner> {
  if (typeof indexedDB === "undefined" || !globalThis.crypto?.subtle) {
    throw new Error(
      "kit: this runtime requires a createSigner implementation; React Native apps must import @cavos/kit/react-native",
    );
  }
  const { WebCryptoSigner } = await import("./signer/WebCryptoSigner");
  return WebCryptoSigner.loadOrCreate({ keyId });
}

async function loadDefaultWebDeviceKey(keyId: string): Promise<DeviceUnwrapKey> {
  if (typeof indexedDB === "undefined" || !globalThis.crypto?.subtle) {
    throw new Error(
      "kit/stellar: this runtime requires createStellarDeviceKey; React Native apps must import @cavos/kit/react-native",
    );
  }
  const { WebCryptoDeviceUnwrapKey } = await import("./chains/stellar/WebCryptoDeviceUnwrapKey");
  return WebCryptoDeviceUnwrapKey.loadOrCreate({ keyId });
}
