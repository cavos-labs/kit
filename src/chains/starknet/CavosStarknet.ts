import {
  Account,
  ETransactionVersion3,
  PaymasterRpc,
  hash,
  RpcProvider,
  Signer,
  stark,
  type Call,
  type SignerInterface,
  type TypedData,
} from "starknet";
import type { ConnectStatus } from "../../Cavos";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import { bigIntTo32Bytes, bytesToHex } from "../../crypto/encoding";
import type { SocialRecoveryClient } from "../../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { InMemoryWalletRegistry, type WalletRegistry } from "../../registry/WalletRegistry";
import type { Ed25519Seed } from "../../secret/dek";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import { passkeyRestoreInput } from "../../secret/nativeAccount";
import type { PasskeyPrfProvider } from "../../signer/PasskeyProvider";
import type { MessageSignature, StarknetSignedTransaction } from "../../signing";
import { connectThroughVault, vaultConnectParams, type VaultClient } from "../../vault/VaultClient";
import { resolveFeeMode, type ChainCall, type ExecuteOptions } from "../ChainAdapter";
import {
  CAVOS_PAYMASTER_URL,
  OZ_ACCOUNT_CLASS_HASH,
  STARKNET_NETWORKS,
  type StarknetNetwork,
} from "./constants";
import { resolveNativeStarknet, type StarknetSpend } from "./nativeConnect";

export interface ConnectStarknetOptions {
  network: StarknetNetwork;
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  environment?: "development" | "production";
  backendUrl?: string;
  registry?: WalletRegistry;
  /** Cavos paymaster API key. Sponsors the deploy and every sponsored execute. */
  paymasterApiKey: string;
  paymasterUrl?: string;
  rpcUrl?: string;
  credential?: SocialRecoveryCredential;
  socialRecovery?: SocialRecoveryClient;
  recovery?: EnclaveDekPort;
  factor?: DeviceFactor;
  wrapStore?: WrapStore;
  importSpend?: (seed: Ed25519Seed, keyId: string) => Promise<StarknetSpend>;
  passkey?: PasskeyPrfProvider;
  /** Keep the key in the Cavos vault instead of this page's storage. */
  vault?: VaultClient;
}

const MESSAGE_TYPES = {
  StarknetDomain: [
    { name: "name", type: "shortstring" },
    { name: "version", type: "shortstring" },
    { name: "chainId", type: "shortstring" },
    { name: "revision", type: "shortstring" },
  ],
  Message: [{ name: "content", type: "string" }],
};

const KEY_ROTATIONS = new Set(["set_public_key", "setPublicKey"].map((name) => BigInt(hash.getSelectorFromName(name))));

/**
 * Native Starknet account: the standard OpenZeppelin `AccountUpgradeable`, whose
 * stark key is HKDF of the MasterDEK. There is no on-chain device list; a new
 * device restores the DEK off-chain and derives the same key.
 *
 * Connect never deploys. The first `execute` deploys the account and runs the
 * calls in one sponsored transaction.
 */
export class CavosStarknet {
  readonly chain = "starknet" as const;
  readonly identity: Identity;
  readonly address: string;
  readonly network: StarknetNetwork;
  isNewAccount = false;
  onAuthorizationNeeded?: () => Promise<void>;
  private statusValue: ConnectStatus;
  private deployed: boolean;
  private readonly provider: RpcProvider;
  private readonly accountValue?: Account;
  private readonly starkPublicKey?: string;
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
    network: StarknetNetwork;
    status: ConnectStatus;
    deployed: boolean;
    provider: RpcProvider;
    account?: Account;
    publicKey?: string;
    restoredWithPasskey?: boolean;
  }) {
    this.identity = init.identity;
    this.address = init.address;
    this.network = init.network;
    this.statusValue = init.status;
    this.deployed = init.deployed;
    this.provider = init.provider;
    this.accountValue = init.account;
    this.starkPublicKey = init.publicKey;
    this.passkeyRestore = init.restoredWithPasskey ?? false;
  }

  get status(): ConnectStatus {
    return this.statusValue;
  }

  get isDeployed(): boolean {
    return this.deployed;
  }

  /** The starknet.js account. Throws on a device that holds no key. */
  get account(): Account {
    if (!this.accountValue) throw new Error("kit/starknet: this device holds no key for the wallet");
    return this.accountValue;
  }

  /** The stark public key (hex) the account was deployed with. */
  get publicKey(): string {
    if (!this.starkPublicKey) throw new Error("kit/starknet: this device holds no key for the wallet");
    return this.starkPublicKey;
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
        continue;
      }
    }
  }

  static async connect(opts: ConnectStarknetOptions): Promise<CavosStarknet> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/starknet: connect requires `identity` or `auth`");

    const provider = new RpcProvider({ nodeUrl: opts.rpcUrl ?? STARKNET_NETWORKS[opts.network].rpcUrl });
    const paymasterUrl = opts.paymasterUrl ?? CAVOS_PAYMASTER_URL[opts.network];
    const paymaster = new PaymasterRpc({
      nodeUrl: paymasterUrl,
      headers: { "x-paymaster-api-key": opts.paymasterApiKey },
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

    let signer: SignerInterface | null;
    let address: string;
    let isNewAccount: boolean;
    let passkey: boolean;
    if (opts.vault) {
      const native = await connectThroughVault("starknet", identity, opts.appSalt, () =>
        opts.vault!.connectStarknet(vaultConnectParams({ ...opts, identity })),
      );
      ({ signer, address, isNewAccount } = native);
      passkey = native.passkey;
    } else {
      const native = await resolveNativeStarknet({
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
      signer = native.spend ? new Signer(native.spend.privateKey()) : null;
      ({ address, isNewAccount } = native);
      passkey = Boolean(opts.passkey);
    }

    const deployed = await isDeployed(provider, address);
    const wallet = new CavosStarknet({
      identity,
      address,
      network: opts.network,
      status: !signer ? "needs-device-approval" : deployed ? "ready" : "undeployed",
      deployed,
      provider,
      ...(signer
        ? {
            account: new Account({ provider, address, signer, paymaster, cairoVersion: "1" }),
            publicKey: await signer.getPubKey(),
          }
        : {}),
      restoredWithPasskey: passkey,
    });
    wallet.isNewAccount = isNewAccount;
    return wallet;
  }

  async hasPasskey(): Promise<boolean> {
    return this.passkeyRestore;
  }

  /** Ready means one thing here: this device holds the stark key. There is no on-chain signer set to wait for. */
  async isReady(): Promise<boolean> {
    return this.accountValue !== undefined;
  }

  /**
   * Execute a multicall, signed silently by the account key. Sponsored by
   * default; `fee: 'self'` pays from the account's own balance.
   *
   * **Lazy deploy**: on an undeployed account the first execute deploys it and
   * runs the calls in one sponsored transaction, then the status becomes
   * `ready`. A self-funded first execute is refused, because the account has no
   * balance to deploy itself with.
   */
  async execute(calls: ChainCall[], opts?: ExecuteOptions): Promise<{ transactionHash: string }> {
    this.refuseKeyRotation(calls);
    const fee = resolveFeeMode(opts, "sponsored");
    if (this.statusValue === "undeployed") {
      if (fee === "self") {
        throw new Error(
          "kit/starknet: self-funded deploy is not supported. The first execute on an undeployed account requires sponsored mode.",
        );
      }
      return this.deployAndExecute(calls);
    }
    if (fee === "self") {
      const res = await this.account.execute(calls as Call[]);
      return { transactionHash: res.transaction_hash };
    }
    const res = await this.account.executePaymasterTransaction(calls as Call[], {
      feeMode: { mode: "sponsored" },
    });
    return { transactionHash: res.transaction_hash };
  }

  private async deployAndExecute(calls: ChainCall[]): Promise<{ transactionHash: string }> {
    const res = await this.account.executePaymasterTransaction(calls as Call[], {
      feeMode: { mode: "sponsored" },
      deploymentData: {
        address: this.address,
        class_hash: OZ_ACCOUNT_CLASS_HASH,
        salt: this.publicKey,
        calldata: [this.publicKey],
        version: 1,
      },
    });
    try {
      await this.provider.waitForTransaction(res.transaction_hash);
    } catch (e) {
      console.warn("[Cavos] deploy+execute receipt wait failed:", e);
    }
    this.deployed = true;
    this.setStatus("ready");
    this.isNewAccount = true;
    return { transactionHash: res.transaction_hash };
  }

  /**
   * Sign an arbitrary message off-chain as SNIP-12 revision 1 typed data. Nothing
   * is submitted and no gas is paid, so it works before the account is deployed.
   * A verifier recomputes the message hash from `typedData` and the account
   * address, then checks the stark signature, or calls the deployed account's
   * `is_valid_signature`.
   */
  async signMessage(message: string | Uint8Array): Promise<MessageSignature> {
    const typedData: TypedData = {
      types: MESSAGE_TYPES,
      primaryType: "Message",
      domain: {
        name: "Cavos",
        version: "1",
        chainId: STARKNET_NETWORKS[this.network].chainId,
        revision: "1",
      },
      message: { content: typeof message === "string" ? message : bytesToHex(message) },
    };
    const [r, s] = stark.formatSignature(await this.account.signMessage(typedData));
    const out = new Uint8Array(64);
    out.set(bigIntTo32Bytes(BigInt(r)), 0);
    out.set(bigIntTo32Bytes(BigInt(s)), 32);
    return { signature: out, publicKey: this.publicKey, curve: "stark", typedData };
  }

  /**
   * Build + sign a multicall WITHOUT submitting it. Returns the signed invoke
   * (calldata + 2-felt stark signature + nonce + resource bounds). A relayer
   * can broadcast it later via the account's `invokeFunction`.
   *
   * The signature binds to the nonce and resource bounds at sign time — if any
   * other transaction from this account is submitted first, this signature is
   * invalid. Broadcast promptly.
   */
  async signTransaction(calls: ChainCall[]): Promise<StarknetSignedTransaction> {
    this.refuseKeyRotation(calls);
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

  /** Upgrade this account to a reviewed class. The address and storage are kept; the account authorizes it as a self-call. */
  async upgrade(newClassHash: string, opts?: ExecuteOptions): Promise<{ transactionHash: string }> {
    return this.execute(
      [{ contractAddress: this.address, entrypoint: "upgrade", calldata: [newClassHash] }],
      opts,
    );
  }

  private refuseKeyRotation(calls: ChainCall[]): void {
    const self = BigInt(this.address);
    for (const call of calls) {
      if (BigInt(call.contractAddress) === self && KEY_ROTATIONS.has(selectorOf(call.entrypoint))) {
        throw new Error(
          "kit/starknet: rotating the account key is refused. The wallet key is derived from the DEK, so a rotated key would no longer be controlled by it.",
        );
      }
    }
  }
}

const defaultRegistry = new InMemoryWalletRegistry();

function selectorOf(entrypoint: string): bigint {
  return BigInt(/^0x[0-9a-f]+$/i.test(entrypoint) ? entrypoint : hash.getSelectorFromName(entrypoint));
}

async function isDeployed(provider: RpcProvider, address: string): Promise<boolean> {
  try {
    const classHash = await provider.getClassHashAt(address);
    return !!classHash && classHash !== "0x0";
  } catch {
    return false;
  }
}
