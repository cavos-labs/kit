import { CavosSolana } from "./chains/solana/CavosSolana";
import { CavosStarknet } from "./chains/starknet/CavosStarknet";
import type { SolanaRelayer } from "./chains/solana/SolanaRelayer";
import { TollClient } from "./chains/solana/TollClient";
import type { SolanaNetwork } from "./chains/solana/constants";
import { CavosStellar } from "./chains/stellar/CavosStellar";
import type { StellarRelayer } from "./chains/stellar/StellarRelayer";
import type { DeviceUnwrapKey } from "./chains/stellar/DeviceUnwrapKey";
import type { StellarNetwork } from "./chains/stellar/constants";
import type { StarknetNetwork } from "./chains/starknet/constants";
import type { Keypair as StellarKeypair } from "@stellar/stellar-sdk";
import type { AuthProvider, Identity } from "./auth/AuthProvider";
import type { WalletRegistry } from "./registry/WalletRegistry";
import { deviceFactorFromUnwrapKey } from "./secret/factor";
import type { SocialRecoveryClient } from "./recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "./recovery/SocialRecoveryCredential";
import type { PasskeyPrfProvider } from "./signer/PasskeyProvider";
import { VaultClient } from "./vault/VaultClient";

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
 * Chain status indicates whether an account is deployed, ready, or needs restoring.
 * - `undeployed`: Address derived but no on-chain account exists yet.
 * - `ready`: This device holds the spend key (and the account exists, where it has to be deployed).
 * - `needs-device-approval`: This device holds no spend key yet; restore it with the enclave or a passkey.
 */
export type ChainStatus = "undeployed" | "ready" | "needs-device-approval";

/** A connected wallet: discriminated by `chain`, so `execute()` stays native. */
export type CavosWallet = CavosStarknet | CavosSolana | CavosStellar;

/**
 * Multi-chain session returned by `Cavos.connect` when multiple chains are configured.
 * The session IS the default chain's wallet, augmented with methods
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
   * WalletRegistry by default for real multi-device support.
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
  rpcUrl?: string;
  /**
   * Per-chain RPC overrides. With more than one configured chain a single
   * `rpcUrl` cannot be right — pointing Starknet at a Solana node answers
   * `starknet_call` with "Method not found" — so this wins over `rpcUrl` for
   * the chain it names.
   */
  rpcUrls?: Partial<Record<Chain, string>>;

  // --- Starknet-only ---
  /** Cavos paymaster API key (sponsors deploy + execute). Required for Starknet. */
  paymasterApiKey?: string;
  paymasterUrl?: string;

  // --- Solana-only ---
  /** Gasless sponsorship relayer (defaults to the hosted one when `appId` set). */
  relayer?: SolanaRelayer;
  /**
   * Where Toll lives, for `fee: { token }` — the user pays their own fee, in a
   * token they already hold. Omit it and that route is simply unavailable.
   */
  /**
   * Overrides where the token fee route settles. Defaults to the hosted
   * service, so `fee: { token }` needs no configuration.
   */
  tollUrl?: string;
  socialRecovery?: SocialRecoveryClient;
  socialRecoveryCredential?: SocialRecoveryCredential;
  /**
   * When the app is not using the enclave, a synced passkey derives the
   * MasterDEK. The same credential on a new device produces the same address.
   */
  passkeyPrf?: PasskeyPrfProvider;

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

  /**
   * Keep the signing keys in the Cavos vault, an iframe on a Cavos origin,
   * instead of this page's storage. Needs `appId`.
   */
  vault?: boolean | { url?: string };
}

/**
 * Whether this device can already operate the wallet, or needs it restored.
 * - `undeployed`: Address derived but no on-chain account exists yet. First execute will deploy.
 * - `ready`: This device holds the spend key.
 * - `needs-device-approval`: This device holds no spend key yet.
 */
export type ConnectStatus = "undeployed" | "ready" | "needs-device-approval";

/**
 * The RPC to use for `chain`.
 *
 * `rpcUrls` names the chain, so it is always safe. The older single `rpcUrl` is
 * only unambiguous when one chain is configured; applied across a multi-chain
 * session it sends every chain's calls to one node, and the node that is wrong
 * answers "Method not found" rather than failing usefully.
 */
function rpcFor(chain: Chain, opts: ConnectOptions): string | undefined {
  const named = opts.rpcUrls?.[chain];
  if (named) return named;
  const configured = opts.chains ?? (opts.chain ? [opts.chain] : []);
  return configured.length > 1 ? undefined : opts.rpcUrl;
}

/**
 * Unified entry point. Pick a `chain` (or `chains` + `defaultChain`) and a
 * `network` environment; the kit resolves the concrete network and returns
 * a chain-native wallet. The result is a discriminated union (`wallet.chain`),
 * so `execute()` keeps each chain's native signature.
 *
 * Every chain is native: the account key is derived from a MasterDEK, recovery
 * is off-chain (enclave or passkey), and there is no on-chain device list.
 *
 * **Lazy deploy**: Connect NEVER deploys on connect. The first `execute` call
 * on an undeployed chain triggers deployment + the user operation atomically.
 *
 *   const wallet = await Cavos.connect({ chain: "solana", network: "testnet", identity, appSalt, appId });
 *   if (wallet.chain === "starknet") await wallet.execute(calls); // deploys here if needed
 *   else                              await wallet.execute(amount, dest);
 *
 * **Multi-chain**:
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
async function connect(opts: ConnectOptions): Promise<CavosWallet & CavosSession> {
  const configuredChains = opts.chains ?? (opts.chain ? [opts.chain] : ["starknet" as Chain]);
  const defaultChain = opts.defaultChain ?? configuredChains[0];

  if (configuredChains.length === 0) {
    throw new Error("kit: at least one chain must be configured");
  }
  if (!configuredChains.includes(defaultChain)) {
    throw new Error(`kit: defaultChain "${defaultChain}" must be in chains [${configuredChains.join(", ")}]`);
  }

  const identity = opts.identity ?? (opts.auth ? await opts.auth.authenticate() : undefined);
  if (!identity) throw new Error("kit: connect requires `identity` or `auth`");

  const wallets = await Promise.all(
    configuredChains.map((chain) => connectSingleChain(chain, { ...opts, identity })),
  );

  const walletMap = new Map<Chain, CavosWallet>();
  for (let i = 0; i < configuredChains.length; i++) {
    walletMap.set(configuredChains[i], wallets[i]);
  }

  const defaultWallet = walletMap.get(defaultChain)!;

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
      return session.wallet(chain).status;
    },
    chainAddress(chain: Chain): string {
      return session.wallet(chain).address;
    },
  };

  return Object.assign(defaultWallet, session);
}

async function connectSingleChain(
  chain: Chain,
  opts: ConnectOptions & { identity: Identity },
): Promise<CavosWallet> {
  if (chain === "solana") {
    const keyId = `${opts.identity.userId}:${opts.appSalt}`;
    const vault = vaultFor(opts);
    const unwrapKey = vault
      ? undefined
      : opts.stellarDeviceKey ?? (opts.createStellarDeviceKey ? await opts.createStellarDeviceKey(keyId) : undefined);
    return CavosSolana.connect({
      network: SOLANA_ENV[opts.network],
      identity: opts.identity,
      appSalt: opts.appSalt,
      ...(opts.auth ? { auth: opts.auth } : {}),
      ...(opts.appId ? { appId: opts.appId } : {}),
      ...(opts.environment ? { environment: opts.environment } : {}),
      ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
      ...(opts.registry ? { registry: opts.registry } : {}),
      ...(rpcFor('solana', opts) ? { rpcUrl: rpcFor('solana', opts)! } : {}),
      ...(opts.relayer ? { relayer: opts.relayer } : {}),
      toll: new TollClient(opts.tollUrl ? { baseUrl: opts.tollUrl } : {}),
      ...(opts.socialRecovery ? { socialRecovery: opts.socialRecovery } : {}),
      ...(opts.socialRecoveryCredential ? { credential: opts.socialRecoveryCredential } : {}),
      ...(opts.passkeyPrf ? { passkey: opts.passkeyPrf } : {}),
      ...(unwrapKey ? { factor: deviceFactorFromUnwrapKey(unwrapKey) } : {}),
      ...(vault ? { vault } : {}),
    });
  }
  if (chain === "stellar") {
    const keyId = `${opts.identity.userId}:${opts.appSalt}`;
    const vault = vaultFor(opts);
    const deviceKey = vault
      ? undefined
      : opts.stellarDeviceKey
        ?? (opts.createStellarDeviceKey
          ? await opts.createStellarDeviceKey(keyId)
          : await loadDefaultWebDeviceKey(keyId));
    return CavosStellar.connect({
      network: STELLAR_ENV[opts.network],
      identity: opts.identity,
      appSalt: opts.appSalt,
      deviceKey,
      ...(opts.auth ? { auth: opts.auth } : {}),
      ...(opts.appId ? { appId: opts.appId } : {}),
      ...(opts.environment ? { environment: opts.environment } : {}),
      ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
      ...(opts.stellarRelayer ? { relayer: opts.stellarRelayer } : {}),
      ...(opts.stellarSourceKeypair ? { sourceKeypair: opts.stellarSourceKeypair } : {}),
      ...(opts.socialRecovery ? { socialRecovery: opts.socialRecovery } : {}),
      ...(opts.socialRecoveryCredential ? { credential: opts.socialRecoveryCredential } : {}),
      ...(opts.passkeyPrf ? { passkey: opts.passkeyPrf } : {}),
      ...(vault ? { vault } : {}),
    });
  }
  if (!opts.paymasterApiKey) {
    throw new Error("kit: `paymasterApiKey` is required for Starknet connections");
  }
  const keyId = `${opts.identity.userId}:${opts.appSalt}`;
  const vault = vaultFor(opts);
  const unwrapKey = vault
    ? undefined
    : opts.stellarDeviceKey ?? (opts.createStellarDeviceKey ? await opts.createStellarDeviceKey(keyId) : undefined);
  return CavosStarknet.connect({
    network: STARKNET_ENV[opts.network],
    identity: opts.identity,
    appSalt: opts.appSalt,
    paymasterApiKey: opts.paymasterApiKey,
    ...(opts.auth ? { auth: opts.auth } : {}),
    ...(opts.appId ? { appId: opts.appId } : {}),
    ...(opts.environment ? { environment: opts.environment } : {}),
    ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
    ...(opts.registry ? { registry: opts.registry } : {}),
    ...(opts.paymasterUrl ? { paymasterUrl: opts.paymasterUrl } : {}),
    ...(rpcFor('starknet', opts) ? { rpcUrl: rpcFor('starknet', opts)! } : {}),
    ...(opts.socialRecovery ? { socialRecovery: opts.socialRecovery } : {}),
    ...(opts.socialRecoveryCredential ? { credential: opts.socialRecoveryCredential } : {}),
    ...(opts.passkeyPrf ? { passkey: opts.passkeyPrf } : {}),
    ...(unwrapKey ? { factor: deviceFactorFromUnwrapKey(unwrapKey) } : {}),
    ...(vault ? { vault } : {}),
  });
}

/** The unified entry point: `Cavos.connect` returns the chain-native wallet for each configured chain. */
export const Cavos = { connect };

function vaultFor(opts: ConnectOptions): VaultClient | undefined {
  if (!opts.vault) return undefined;
  if (!opts.appId) throw new Error("kit: the vault needs `appId`");
  return VaultClient.attach({
    appId: opts.appId,
    ...(typeof opts.vault === "object" && opts.vault.url ? { url: opts.vault.url } : {}),
  });
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
