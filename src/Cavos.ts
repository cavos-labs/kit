import { Account, RpcProvider, PaymasterRpc, num, type Call } from "starknet";
import type { Keypair } from "@solana/web3.js";
import type { AuthProvider, Identity } from "./auth/AuthProvider";
import type { DeviceSigner, DevicePublicKey } from "./signer/DeviceSigner";
import { WebCryptoSigner } from "./signer/WebCryptoSigner";
import { StarknetAdapter } from "./chains/starknet/StarknetAdapter";
import { StarknetDeviceSigner } from "./chains/starknet/StarknetDeviceSigner";
import { CavosSolana } from "./chains/solana/CavosSolana";
import type { SolanaRelayer } from "./chains/solana/SolanaRelayer";
import type { SolanaNetwork } from "./chains/solana/constants";
import type { ChainCall } from "./chains/ChainAdapter";
import type { WalletRegistry } from "./registry/WalletRegistry";
import { InMemoryWalletRegistry } from "./registry/WalletRegistry";
import { HttpWalletRegistry } from "./registry/HttpWalletRegistry";
import type { RecoveryClient } from "./recovery/RecoveryClient";
import { HttpRecoveryClient } from "./recovery/HttpRecoveryClient";
import { BackupSigner, deriveBackupKey } from "./recovery/BackupSigner";
import { deriveAddressSeed } from "./identity";
import {
  CAVOS_PAYMASTER_URL,
  DEVICE_ACCOUNT_CLASS_HASH,
  STARKNET_NETWORKS,
  type StarknetNetwork,
} from "./chains/starknet/constants";

/** The chains the unified `Cavos.connect` can target. */
export type Chain = "starknet" | "solana";

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

/** A connected wallet: discriminated by `chain`, so `execute()` stays native. */
export type CavosWallet = Cavos | CavosSolana;

export interface ConnectOptions {
  /** Target chain. The returned wallet is discriminated by this same value. */
  chain: Chain;
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
}

/** The Starknet-specific connect options, resolved from the unified ones. */
interface StarknetConnectOptions {
  network: StarknetNetwork;
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  backendUrl?: string;
  registry?: WalletRegistry;
  recovery?: RecoveryClient;
  paymasterApiKey: string;
  paymasterUrl?: string;
  rpcUrl?: string;
  classHash?: string;
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
}

/** Whether this device can already operate the wallet, or needs to be added. */
export type ConnectStatus = "ready" | "needs-device-approval";

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
  backendUrl?: string;
  rpcUrl?: string;
  paymasterUrl?: string;
  classHash?: string;
  /** Off-chain user_id -> wallet map. Defaults to the hosted registry. */
  registry?: WalletRegistry;
  /** Override the new device's signer (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
}

/**
 * High-level Cavos wallet. One call logs the user in and returns a ready, gas-
 * sponsored smart account controlled by a silent device key.
 *
 *   const cavos = await Cavos.connect({ network, identity, appSalt, registry, paymasterApiKey });
 *   if (cavos.status === "ready") await cavos.execute(calls);
 *
 * The account address is `f(identity, device_pubkey)` — unforgeable, so it can't
 * be hijacked. The `registry` recognizes returning users across devices: a new
 * device on an existing account is flagged `needs-device-approval` (add it via
 * an already-registered device) instead of creating a second wallet.
 */
export class Cavos {
  /** Discriminant for the `CavosWallet` union — narrows `execute()` per chain. */
  readonly chain = "starknet" as const;
  /** Request id of the pending device-addition, when status is needs-device-approval. */
  pendingRequestId: string | null = null;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    readonly status: ConnectStatus,
    readonly account: Account,
    private readonly adapter: StarknetAdapter,
    private readonly devicePubkey: DevicePublicKey,
  ) {}

  /**
   * Unified entry point. Pick a `chain` and an `network` environment; the kit
   * resolves the concrete network (sepolia/devnet for testnet, mainnet for
   * mainnet) and returns a chain-native wallet. The result is a discriminated
   * union (`wallet.chain`), so `execute()` keeps each chain's native signature:
   *
   *   const wallet = await Cavos.connect({ chain: "solana", network: "testnet", identity, appSalt, appId });
   *   if (wallet.chain === "starknet") await wallet.execute(calls);
   *   else                              await wallet.execute(amount, dest);
   */
  static async connect(opts: ConnectOptions): Promise<CavosWallet> {
    if (opts.chain === "solana") {
      return CavosSolana.connect({
        network: SOLANA_ENV[opts.network],
        ...(opts.auth ? { auth: opts.auth } : {}),
        ...(opts.identity ? { identity: opts.identity } : {}),
        appSalt: opts.appSalt,
        ...(opts.appId ? { appId: opts.appId } : {}),
        ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
        ...(opts.registry ? { registry: opts.registry } : {}),
        ...(opts.rpcUrl ? { rpcUrl: opts.rpcUrl } : {}),
        ...(opts.programId ? { programId: opts.programId } : {}),
        ...(opts.createSigner ? { createSigner: opts.createSigner } : {}),
        ...(opts.relayer ? { relayer: opts.relayer } : {}),
        ...(opts.feePayer ? { feePayer: opts.feePayer } : {}),
      });
    }
    if (!opts.paymasterApiKey) {
      throw new Error("kit: `paymasterApiKey` is required for Starknet connections");
    }
    return Cavos.connectStarknet({
      network: STARKNET_ENV[opts.network],
      auth: opts.auth,
      identity: opts.identity,
      appSalt: opts.appSalt,
      appId: opts.appId,
      backendUrl: opts.backendUrl,
      registry: opts.registry,
      recovery: opts.recovery,
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
    const paymaster = new PaymasterRpc({
      nodeUrl: opts.paymasterUrl ?? CAVOS_PAYMASTER_URL[opts.network],
      headers: { "x-paymaster-api-key": opts.paymasterApiKey },
    });

    const addressSeed = deriveAddressSeed({ userId: identity.userId, appSalt: opts.appSalt });

    // This device's silent signer.
    const signer = opts.createSigner
      ? await opts.createSigner(`${identity.userId}:${opts.appSalt}`)
      : await WebCryptoSigner.loadOrCreate({ keyId: `${identity.userId}:${opts.appSalt}` });
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

    // Returning user? The registry knows their wallet (address is device-bound,
    // so it isn't derivable from identity alone). Default to the hosted
    // HttpWalletRegistry when appId is provided, else an in-memory map.
    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : defaultRegistry);
    const recovery =
      opts.recovery ?? (opts.appId ? new HttpRecoveryClient({ baseUrl: backendUrl, appId: opts.appId }) : null);
    const existing = await registry.lookup(identity.userId);

    if (existing) {
      const account = makeAccount(existing.address);
      const isSigner = await adapter.isAuthorizedSigner(existing.address, devicePubkey);
      const cavos = new Cavos(
        identity,
        existing.address,
        isSigner ? "ready" : "needs-device-approval",
        account,
        adapter,
        devicePubkey,
      );

      // New device on an existing wallet: ask the backend to email the owner an
      // approval link. The approving device signs add_signer on-chain; this device
      // becomes "ready" after that. Best-effort: never blocks the connect result.
      //
      // De-duplicate within a short window so a page refresh, reconnect, or
      // rapid retry doesn't spam the owner with one email per attempt. The
      // backend already dedups by request id within its 24h TTL, but that still
      // re-sends the email on each fresh request id — this client-side guard
      // collapses the burst. We keep the last requestId and reuse it.
      if (!isSigner && recovery) {
        const dedup = lastDeviceRequest.get(identity.userId);
        const fresh = dedup && Date.now() - dedup.requestedAt < DEVICE_REQUEST_DEDUP_MS;
        try {
          if (fresh) {
            cavos.pendingRequestId = dedup!.requestId;
          } else {
            const { requestId } = await recovery.requestDeviceAddition({
              userId: identity.userId,
              accountAddress: existing.address,
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

    // Compute the deterministic address for (identity, this device). The address
    // is device-bound, so it's NOT in the registry for a new device — but it may
    // already be deployed on-chain (same device reconnecting, or a re-run after a
    // deploy that succeeded before a timeout). Ask the chain before deploying:
    // re-deploying an existing account reverts ("contract already deployed").
    const address = adapter.computeAddress({ addressSeed, initialSigner: devicePubkey });
    const account = makeAccount(address);
    const alreadyDeployed = await isDeployed(provider, address);

    if (!alreadyDeployed) {
      const deploymentData = {
        address,
        class_hash: classHash,
        salt: num.toHex(addressSeed),
        calldata: adapter.constructorCalldata(addressSeed, devicePubkey),
        version: 1 as const,
      };
      const deployRes = await account.executePaymasterTransaction([], {
        feeMode: { mode: "sponsored" },
        deploymentData,
      });
      // Wait for the deploy to land before declaring the device "ready". Assuming
      // readiness here would report "ready" if the tx silently failed or hadn't
      // indexed yet — and the user would hit a confusing error on their first tx.
      try {
        await provider.waitForTransaction(deployRes.transaction_hash);
      } catch (e) {
        console.warn("[Cavos] deploy receipt wait failed:", e);
      }
    }

    // Record the wallet (idempotent for reconnects) and resolve readiness from
    // the chain: this device is "ready" iff its pubkey is an authorized signer.
    // We re-read even right after a fresh deploy, so a deploy that failed to
    // index (or silently reverted) surfaces as needs-device-approval rather than
    // a false "ready".
    await registry.register({ userId: identity.userId, address, initialSigner: devicePubkey });
    let isSigner: boolean;
    try {
      isSigner = await adapter.isAuthorizedSigner(address, devicePubkey);
    } catch (e) {
      // Fall back to the deploy assumption only if the chain read itself errors
      // (e.g. node hiccup right after indexing) — the deploy did submit.
      console.warn("[Cavos] isAuthorizedSigner read failed:", e);
      isSigner = !alreadyDeployed;
    }

    return new Cavos(
      identity,
      address,
      isSigner ? "ready" : "needs-device-approval",
      account,
      adapter,
      devicePubkey,
    );
  }

  /** This device's public key (e.g. to request addition to an existing wallet). */
  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  /** Execute a sponsored (gasless) multicall, signed silently by the device. */
  async execute(calls: ChainCall[]): Promise<{ transactionHash: string }> {
    if (this.status !== "ready") {
      throw new Error("kit: this device is not yet an authorized signer of the wallet");
    }
    const res = await this.account.executePaymasterTransaction(calls as Call[], {
      feeMode: { mode: "sponsored" },
    });
    return { transactionHash: res.transaction_hash };
  }

  /** Authorize an additional device signer (sponsored). Self-submitted. */
  async addSigner(pubkey: DevicePublicKey): Promise<{ transactionHash: string }> {
    return this.execute([this.adapter.buildAddSigner(this.address, pubkey)]);
  }

  /**
   * Register a self-custodial backup signer derived from `code`, so the account
   * can be recovered after the user loses every device. Idempotent: if the
   * derived backup key is already an authorised signer, this is a no-op.
   *
   * The code never leaves the device — only its deterministic public key is
   * added on-chain as an ordinary signer. Sponsor this like any other
   * add_signer (gasless). Returns the transaction hash (or undefined when the
   * backup was already set up).
   */
  async setupRecovery(code: string): Promise<{ transactionHash: string } | undefined> {
    const { publicKey: backupPubkey } = deriveBackupKey(code);
    // Skip the on-chain call if the backup signer is already registered.
    const already = await this.adapter.isAuthorizedSigner(this.address, backupPubkey);
    if (already) return undefined;
    return this.addSigner(backupPubkey);
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
      : await WebCryptoSigner.loadOrCreate({ keyId: `${opts.identity.userId}:${opts.appSalt}` });
    const devicePubkey = await signer.getPublicKey();

    // The backup key drives THIS transaction: it's the only signer that can
    // authorise adding the new device after all device keys are lost.
    const backup = BackupSigner.fromCode(opts.code);
    const backupAdapter = new StarknetAdapter({ classHash, signer: backup, provider });

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({ baseUrl: backendUrl, appId: opts.appId, network })
        : defaultRegistry);
    const existing = await registry.lookup(opts.identity.userId);
    if (!existing) {
      throw new Error("kit: no account found for this identity — nothing to recover");
    }

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
    return new Cavos(opts.identity, existing.address, "ready", account, adapter, devicePubkey);
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
