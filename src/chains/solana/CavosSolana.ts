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
import { SolanaRelayer } from "./SolanaRelayer";
import { SOLANA_NETWORKS, type SolanaNetwork } from "./constants";

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

    const address = adapter.computeAddress(addressSeed, devicePubkey);
    const deployed = (await connection.getAccountInfo(new PublicKey(address))) !== null;

    if (!deployed) {
      // Whoever pays must be the `initialize` payer/fee payer: the relayer (when
      // sponsoring) or the self-funded feePayer.
      if (relayer) {
        const payer = await relayer.getFeePayer();
        const ix = adapter.buildInitialize(addressSeed, payer.toBase58(), devicePubkey);
        await relayer.send([ix]);
      } else if (opts.feePayer) {
        const ix = adapter.buildInitialize(addressSeed, opts.feePayer.publicKey.toBase58(), devicePubkey);
        await sendAndConfirmTransaction(connection, new Transaction().add(ix), [opts.feePayer]);
      } else {
        throw new Error("kit/solana: a relayer (appId) or feePayer is required to initialize a new account");
      }
    }

    await registry.register({ userId: identity.userId, address, initialSigner: devicePubkey });
    const isSigner = await adapter.isAuthorizedSigner(address, devicePubkey);
    return new CavosSolana(
      identity,
      address,
      isSigner ? "ready" : "needs-device-approval",
      connection,
      adapter,
      devicePubkey,
      relayer,
      opts.feePayer,
    );
  }

  /** Authorize an additional device signer (device-signed via precompile). */
  async addSigner(pubkey: DevicePublicKey): Promise<string> {
    const ixs = await this.adapter.buildAddSigner(this.address, pubkey);
    return this.send(ixs);
  }

  /** Move `amount` lamports out of the account to `destination` (device-signed). */
  async execute(amount: bigint, destination: string): Promise<string> {
    if (this.status !== "ready") {
      throw new Error("kit/solana: this device is not yet an authorized signer of the wallet");
    }
    const ixs = await this.adapter.buildExecuteTransfer(this.address, destination, amount);
    return this.send(ixs);
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
