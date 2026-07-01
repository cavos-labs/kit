import {
  Account,
  Address,
  BASE_FEE,
  Operation,
  TransactionBuilder,
  rpc,
  xdr,
  type Keypair,
  type Transaction,
} from "@stellar/stellar-sdk";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { WebCryptoSigner } from "../../signer/WebCryptoSigner";
import type { WalletRegistry } from "../../registry/WalletRegistry";
import { InMemoryWalletRegistry } from "../../registry/WalletRegistry";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { deriveAddressSeedStellar } from "../../identity";
import { BackupSigner, deriveBackupKey } from "../../recovery/BackupSigner";
import type { PasskeySigner, PasskeyEnrollParams } from "../../signer/PasskeySigner";
import { webauthnDigest, recoverCandidatePublicKeys, batchChallenge } from "../../crypto/webauthn";
import type { PasskeyAssertion } from "../../crypto/webauthn";
import { StellarAdapter } from "./StellarAdapter";
import { StellarRelayer } from "./StellarRelayer";
import { NATIVE_SAC_ID, type StellarNetwork } from "./constants";

export interface ConnectStellarOptions {
  network: StellarNetwork;
  /** Authenticated user (pass `identity` directly, or an `auth` provider). */
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  appId?: string;
  backendUrl?: string;
  registry?: WalletRegistry;
  /** RPC override (else the network default). */
  rpcUrl?: string;
  /** Factory contract id override (else the per-network default). */
  factoryId?: string;
  /** Override the device signer factory (native / tests); default WebCrypto. */
  createSigner?: (keyId: string) => Promise<DeviceSigner>;
  /**
   * Gasless sponsorship via the Cavos relayer. When set (or when `appId` +
   * `backendUrl` are given) the relayer is the transaction source + fee payer, so
   * the integrator needs NO Stellar keypair — the silent device key (which holds
   * no XLM) gets a seedless, gasless experience.
   */
  relayer?: StellarRelayer;
  /**
   * Self-funded fallback: a Stellar `Keypair` that is the transaction source +
   * fee payer. Used only when no `relayer` is configured (tests / advanced).
   */
  sourceKeypair?: Keypair;
}

export interface RecoverStellarOptions extends Omit<ConnectStellarOptions, "auth"> {
  /** The recovery code the user stored when they ran setupRecovery. */
  code: string;
  /** Authenticated identity (same user who owns the account). */
  identity: Identity;
}

export type ConnectStatus = "ready" | "needs-device-approval";

/**
 * High-level Stellar entry — the Soroban analogue of `Cavos.connect` /
 * `CavosSolana.connect`. One call derives the deterministic device-bound account,
 * deploys it via the factory if needed, registers it for cross-device
 * recognition, and returns a ready handle whose silent P-256 device key
 * authorizes every action through the account's `__check_auth`.
 *
 *   const cavos = await CavosStellar.connect({ network: "stellar-testnet", identity, appSalt, relayer });
 *   if (cavos.status === "ready") await cavos.execute(10_000_000n, dest); // 1 XLM
 *
 * Gasless by default: with an `appId` the Cavos relayer is the tx source + fee
 * payer. `sourceKeypair` is the self-funded fallback.
 */
export class CavosStellar {
  /** Discriminant for the `CavosWallet` union — narrows `execute()` per chain. */
  readonly chain = "stellar" as const;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    readonly status: ConnectStatus,
    readonly network: StellarNetwork,
    private readonly adapter: StellarAdapter,
    private readonly devicePubkey: DevicePublicKey,
    private readonly relayer?: StellarRelayer,
    private readonly sourceKeypair?: Keypair,
  ) {}

  get publicKey(): DevicePublicKey {
    return this.devicePubkey;
  }

  static async connect(opts: ConnectStellarOptions): Promise<CavosStellar> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/stellar: connect requires `identity` or `auth`");

    const signer = opts.createSigner
      ? await opts.createSigner(`${identity.userId}:${opts.appSalt}`)
      : await WebCryptoSigner.loadOrCreate({ keyId: `${identity.userId}:${opts.appSalt}` });
    const devicePubkey = await signer.getPublicKey();

    const adapter = new StellarAdapter({
      network: opts.network,
      rpcUrl: opts.rpcUrl,
      factoryId: opts.factoryId,
      signer,
    });
    const addressSeed = deriveAddressSeedStellar({ userId: identity.userId, appSalt: opts.appSalt });

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const registry =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : defaultRegistry);
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new StellarRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : undefined);

    const build = (
      address: string,
      status: ConnectStatus,
    ): CavosStellar =>
      new CavosStellar(identity, address, status, opts.network, adapter, devicePubkey, relayer, opts.sourceKeypair);

    const self = build("", "needs-device-approval");
    const readSource = await self.resolveSource();

    // Returning user on another device? The address is device-bound, so the
    // registry (not identity alone) recognizes it. A new device is flagged
    // needs-device-approval — same model as Starknet/Solana.
    const existing = await registry.lookup(identity.userId);
    if (existing) {
      const isSigner = await adapter.isAuthorizedSigner(existing.address, devicePubkey, readSource);
      return build(existing.address, isSigner ? "ready" : "needs-device-approval");
    }

    const address = adapter.computeAddress(addressSeed, devicePubkey);
    if (!(await adapter.isDeployed(address))) {
      const func = adapter.buildDeploy(addressSeed, devicePubkey);
      // Deploy needs NO device auth (factory deploys; account doesn't exist yet),
      // so `authAccount` is undefined — nothing to sign, just the relayer/self pays.
      await self.submitHostFunction(func, undefined);
    }

    await registry.register({ userId: identity.userId, address, initialSigner: devicePubkey });
    const isSigner = await adapter.isAuthorizedSigner(address, devicePubkey, readSource);
    return build(address, isSigner ? "ready" : "needs-device-approval");
  }

  /** Authorize an additional device signer (device-signed via `__check_auth`). */
  async addSigner(pubkey: DevicePublicKey): Promise<string> {
    const func = this.adapter.buildAddSigner(this.address, pubkey);
    return this.submitHostFunction(func, this.address);
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
      throw new Error("kit/stellar: addApprover requires a ready, authorized device");
    }
    const readSource = await this.resolveSource();
    if (await this.adapter.isApprover(this.address, pubkey, readSource)) return {};
    const func = this.adapter.buildAddApprover(this.address, pubkey);
    const transactionHash = await this.submitHostFunction(func, this.address);
    return { transactionHash };
  }

  /**
   * From a fresh browser (status `needs-device-approval`), approve adding THIS
   * device using the user's synced passkey. Gasless via the relayer — the call
   * carries the WebAuthn assertion, so no device signature is needed. Returns the
   * tx hash. No trip back to an already-authorized device.
   */
  async approveThisDeviceWithPasskey(passkey: PasskeySigner): Promise<string> {
    if (this.status === "ready") {
      throw new Error("kit/stellar: this device is already an authorized signer");
    }
    const { leaf, nonce } = await this.passkeyLeafForThisDevice();
    const leaves = [leaf];
    const assertion = await passkey.assert(batchChallenge(leaves));
    const { transactionHash } = await this.submitPasskeyApproval(assertion, leaves, 0, nonce);
    return transactionHash;
  }

  /** This device's leaf + passkey nonce for a (possibly multi-chain) batch. */
  async passkeyLeafForThisDevice(): Promise<{ leaf: Uint8Array; nonce: bigint }> {
    const readSource = await this.resolveSource();
    const nonce = await this.adapter.passkeyNonce(this.address, readSource);
    return { leaf: this.adapter.passkeyLeaf(this.devicePubkey, nonce), nonce };
  }

  /** Submit `add_signer_via_passkey` given a shared assertion + batch position.
   * No device auth entry — authorized purely by the passkey assertion. */
  async submitPasskeyApproval(
    assertion: PasskeyAssertion,
    leaves: Uint8Array[],
    leafIndex: number,
    nonce: bigint,
  ): Promise<{ transactionHash: string }> {
    const readSource = await this.resolveSource();
    const digest = webauthnDigest(assertion.authenticatorData, assertion.clientDataJSON);
    const candidates = recoverCandidatePublicKeys(assertion.r, assertion.s, digest);
    let approver: DevicePublicKey | null = null;
    for (const cand of candidates) {
      if (await this.adapter.isApprover(this.address, cand.publicKey, readSource)) {
        approver = cand.publicKey;
        break;
      }
    }
    if (!approver) throw new Error("kit/stellar: this passkey is not a registered approver");
    const func = this.adapter.buildAddSignerViaPasskey(
      this.address, this.devicePubkey, approver, nonce, leaves, leafIndex, assertion,
    );
    return { transactionHash: await this.submitHostFunction(func, undefined) };
  }

  /** Move `amount` stroops of native XLM to `destination` (device-signed). */
  async execute(amount: bigint, destination: string): Promise<string> {
    return this.executeTransfer(NATIVE_SAC_ID[this.network], amount, destination);
  }

  /** Read this account's balance of `tokenId` (defaults to native XLM), in stroops. */
  async balance(tokenId: string = NATIVE_SAC_ID[this.network]): Promise<bigint> {
    const readSource = await this.resolveSource();
    return this.adapter.readBalance(tokenId, this.address, readSource);
  }

  /** Transfer `amount` of any SEP-41 token out of the account (device-signed). */
  async executeTransfer(tokenId: string, amount: bigint, destination: string): Promise<string> {
    if (this.status !== "ready") {
      throw new Error("kit/stellar: this device is not yet an authorized signer of the wallet");
    }
    const func = this.adapter.buildTransfer(tokenId, this.address, destination, amount);
    return this.submitHostFunction(func, this.address);
  }

  /**
   * Register the backup signer derived from `code` as an authorized signer of
   * this account (device-signed). Idempotent. The code never leaves the device —
   * only the derived public key travels on-chain. Mirrors the other chains.
   */
  async setupRecovery(code: string): Promise<string | undefined> {
    if (this.status !== "ready") {
      throw new Error("kit/stellar: setupRecovery requires a ready, registered device");
    }
    const { publicKey: backupPubkey } = deriveBackupKey(code);
    const readSource = await this.resolveSource();
    if (await this.adapter.isAuthorizedSigner(this.address, backupPubkey, readSource)) return undefined;
    return this.addSigner(backupPubkey);
  }

  /**
   * Recover an account after losing every device signer: derive the backup key
   * from `code`, use it (not the new device) to authorize `add_signer(newDevice)`,
   * and return a ready handle bound to the new device. The address is unchanged.
   */
  static async recover(opts: RecoverStellarOptions): Promise<CavosStellar> {
    const signer = opts.createSigner
      ? await opts.createSigner(`${opts.identity.userId}:${opts.appSalt}`)
      : await WebCryptoSigner.loadOrCreate({ keyId: `${opts.identity.userId}:${opts.appSalt}` });
    const devicePubkey = await signer.getPublicKey();

    // The backup key drives this tx: it's the only signer that can authorize
    // adding the new device after all device keys are lost. Build an adapter
    // whose signer IS the backup key so the auth entry is backup-signed.
    const backup = BackupSigner.fromCode(opts.code);
    const backupAdapter = new StellarAdapter({
      network: opts.network,
      rpcUrl: opts.rpcUrl,
      factoryId: opts.factoryId,
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
      throw new Error("kit/stellar: no account found for this identity — nothing to recover");
    }
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new StellarRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network })
        : undefined);

    // A CavosStellar bound to the backup adapter, used only to authorize add_signer.
    const backupHandle = new CavosStellar(
      opts.identity,
      existing.address,
      "ready",
      opts.network,
      backupAdapter,
      devicePubkey,
      relayer,
      opts.sourceKeypair,
    );
    const readSource = await backupHandle.resolveSource();
    if (!(await backupAdapter.isAuthorizedSigner(existing.address, devicePubkey, readSource))) {
      await backupHandle.addSigner(devicePubkey);
    }

    // Hand control to the new device's signer for all future operations.
    const adapter = new StellarAdapter({
      network: opts.network,
      rpcUrl: opts.rpcUrl,
      factoryId: opts.factoryId,
      signer,
    });
    return new CavosStellar(
      opts.identity,
      existing.address,
      "ready",
      opts.network,
      adapter,
      devicePubkey,
      relayer,
      opts.sourceKeypair,
    );
  }

  /** The transaction source/fee-payer G-address (relayer or self-funded). */
  private async resolveSource(): Promise<string> {
    if (this.relayer) return this.relayer.getSource();
    if (this.sourceKeypair) return this.sourceKeypair.publicKey();
    throw new Error("kit/stellar: a relayer (appId) or sourceKeypair is required");
  }

  /**
   * Build → simulate → device-sign auth → assemble → submit an invoke-contract
   * host function. `authAccount` is the account whose `__check_auth` must sign the
   * operation's Soroban auth entry (undefined for a plain factory deploy).
   */
  private async submitHostFunction(
    func: xdr.HostFunction,
    authAccount: string | undefined,
  ): Promise<string> {
    const server = this.adapter.server();
    const sourceAddr = await this.resolveSource();

    // Simulation ignores the source sequence, so a throwaway seq is fine here —
    // this avoids double-incrementing the real relayer sequence between builds.
    const simSource = new Account(sourceAddr, "0");
    const unsignedOp = Operation.invokeHostFunction({ func, auth: [] });
    const simTx = new TransactionBuilder(simSource, {
      fee: BASE_FEE,
      networkPassphrase: this.adapter.passphrase,
    })
      .addOperation(unsignedOp)
      .setTimeout(180)
      .build();

    const sim = await server.simulateTransaction(simTx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`kit/stellar: simulation failed: ${sim.error}`);
    }

    const validUntil = (await server.getLatestLedger()).sequence + 100;
    const entries = sim.result?.auth ?? [];
    const signedAuth: xdr.SorobanAuthorizationEntry[] = [];
    for (const entry of entries) {
      if (authAccount && isAddressCredentialFor(entry, authAccount)) {
        signedAuth.push(await this.adapter.signAuthEntry(entry, validUntil));
      } else {
        signedAuth.push(entry);
      }
    }

    // Final tx: real sequence + the device-signed auth entries. assembleTransaction
    // preserves the op's existing auth (only fills sorobanData + resource fee).
    const account = await server.getAccount(sourceAddr);
    const finalOp = Operation.invokeHostFunction({ func, auth: signedAuth });
    const built = new TransactionBuilder(account, {
      fee: BASE_FEE,
      networkPassphrase: this.adapter.passphrase,
    })
      .addOperation(finalOp)
      .setTimeout(180)
      .build();

    // Re-simulate WITH the signed auth so the resource estimate includes the cost
    // of running `__check_auth` (secp256r1_verify + sha256). The first simulation
    // ran in recording mode with no signatures, so it under-counted CPU and the
    // tx would fail on-chain with RESOURCE_LIMIT_EXCEEDED.
    const authSim = await server.simulateTransaction(built);
    if (rpc.Api.isSimulationError(authSim)) {
      throw new Error(`kit/stellar: auth simulation failed: ${authSim.error}`);
    }
    const assembled = rpc.assembleTransaction(built, authSim).build();

    // Relayer signs the envelope + submits (gasless). Self-funded signs locally.
    if (this.relayer) {
      return this.relayer.submit(assembled.toXDR());
    }
    if (this.sourceKeypair) {
      assembled.sign(this.sourceKeypair);
      return this.sendAndConfirm(assembled);
    }
    throw new Error("kit/stellar: no relayer or sourceKeypair configured to submit");
  }

  /** Submit a signed tx via RPC and poll to confirmation. Returns the hash. */
  private async sendAndConfirm(tx: Transaction): Promise<string> {
    const server = this.adapter.server();
    const sent = await server.sendTransaction(tx);
    if (sent.status === "ERROR") {
      throw new Error(`kit/stellar: submit rejected: ${JSON.stringify(sent.errorResult)}`);
    }
    const hash = sent.hash;
    for (let i = 0; i < 30; i++) {
      const got = await server.getTransaction(hash);
      if (got.status === rpc.Api.GetTransactionStatus.SUCCESS) return hash;
      if (got.status === rpc.Api.GetTransactionStatus.FAILED) {
        throw new Error(`kit/stellar: tx ${hash} failed`);
      }
      await new Promise((r) => setTimeout(r, 1000));
    }
    throw new Error(`kit/stellar: tx ${hash} not confirmed in time`);
  }
}

/** Whether an auth entry is an Address credential for `accountAddress`. */
function isAddressCredentialFor(entry: xdr.SorobanAuthorizationEntry, accountAddress: string): boolean {
  const creds = entry.credentials();
  if (creds.switch() !== xdr.SorobanCredentialsType.sorobanCredentialsAddress()) return false;
  return Address.fromScAddress(creds.address().address()).toString() === accountAddress;
}

const defaultRegistry = new InMemoryWalletRegistry();
