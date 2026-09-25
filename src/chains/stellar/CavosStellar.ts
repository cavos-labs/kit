import { Keypair, TransactionBuilder, authorizeEntry, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import {
  StellarAdapter,
  type ControlRotation,
  type DataEntryWrites,
} from "./StellarAdapter";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { resolveAddress } from "../../registry/resolveAddress";
import type { DeviceUnwrapKey } from "./DeviceUnwrapKey";
import { StellarRelayer } from "./StellarRelayer";
import {
  STELLAR_MODEL_DATA_KEY,
  STELLAR_PASSKEY_DATA_KEY,
  type StellarNetwork,
} from "./constants";
import type { Transaction } from "@stellar/stellar-sdk";
import { utf8ToBytes } from "../../crypto/encoding";
import { resolveFeeMode, type ExecuteOptions } from "../../chains/ChainAdapter";
import type { SocialRecoveryClient } from "../../recovery/SocialRecoveryClient";
import type { SocialRecoveryCredential } from "../../recovery/SocialRecoveryCredential";
import type { DeviceFactor, EnclaveDekPort, WrapStore } from "../../secret/DeviceSecret";
import { InMemoryWalletRegistry, type WalletRegistry } from "../../registry/WalletRegistry";
import { resolveNativeStellar } from "./nativeConnect";
import { passkeyRestoreInput } from "../../secret/nativeAccount";
import { connectThroughVault, vaultConnectParams, type VaultClient } from "../../vault/VaultClient";
import type { MessageSignature, StellarSignedTransaction } from "../../signing";
import {
  WebCryptoControlKey,
  type ControlKey,
  signTransactionWithControlKey,
  createSorobanSigner,
} from "./WebCryptoControlKey";
import type { PasskeyPrfProvider } from "../../signer/PasskeyProvider";
import { importPasskeySigner, importRecoverySigner } from "./derivedSigner";

/** Default starting balance (stroops) for a new account: covers the 1 XLM base
 *  reserve + ~0.5 XLM per subentry (data entries + control signer) with headroom
 *  for fees and future factor entries. ~5 XLM, recoverable when merged.
 *  Sponsorship (Phase 3) will move this cost to the relayer. */
const DEFAULT_STARTING_BALANCE = 50_000_000n;

/** How many ledgers a signed Soroban auth entry stays valid (~1h at 5s/ledger).
 *  Bounds replay of the authorization; the tx timeout is separate and shorter. */
const AUTH_VALIDITY_LEDGERS = 720;

export interface ConnectStellarOptions {
  network: StellarNetwork;
  /** Authenticated user (pass `identity` directly, or an `auth` provider). */
  auth?: AuthProvider;
  identity?: Identity;
  appSalt: string;
  /** This device's P-256 ECDH unwrap key (provisioned + persisted per device). */
  deviceKey?: DeviceUnwrapKey;
  /**
   * Gasless sponsorship via the Cavos classic relayer. When set (or when `appId` +
   * `backendUrl` are given) the relayer is the tx source + fee payer AND sponsors
   * the account's reserves — the user locks no XLM and pays no fees.
   */
  relayer?: StellarRelayer;
  /** Cavos App ID — enables the default relayer when no `relayer` is passed. */
  appId?: string;
  /** Cavos console environment. Defaults to production when omitted. */
  environment?: "development" | "production";
  /** Cavos backend base URL (default https://cavos.xyz). */
  backendUrl?: string;
  /**
   * Self-funded funder + fee payer: creates + submits classic transactions
   * directly (the account pays its own reserves + fees). The advanced /
   * self-hosted fallback used when no relayer is configured.
   */
  sourceKeypair?: Keypair;
  /** Horizon URL override. */
  horizonUrl?: string;
  /** Starting balance for a fresh account, in stroops. */
  startingBalance?: bigint;
  credential?: SocialRecoveryCredential;
  socialRecovery?: SocialRecoveryClient;
  recovery?: EnclaveDekPort;
  factor?: DeviceFactor;
  wrapStore?: WrapStore;
  registry?: WalletRegistry;
  passkey?: PasskeyPrfProvider;
  /** Keep the key in the Cavos vault instead of this page's storage. */
  vault?: VaultClient;
}

/**
 * Chain status for Stellar accounts.
 * - `undeployed`: Address derived but no on-chain account exists yet. First execute will create.
 * - `ready`: Account exists and this device can sign (control key unlocked).
 * - `needs-device-approval`: Account exists but this device is not yet authorized.
 */
export type StellarConnectStatus = "undeployed" | "ready" | "needs-device-approval";

/** The local ed25519 signer recovered on this device. */
interface Unlocked {
  control: ControlKey;
}

/**
 * High-level entry for the classic-Stellar (`G…`) multisig account — the classic
 * analogue of `CavosStellar` (Soroban). One `connect` derives the deterministic
 * `G…` address and on a known device unlocks the control key from the on-chain
 * envelope so `execute` signs silently.
 *
 * **Lazy deploy**: Connect NEVER creates the account. The first `execute` call
 * on an undeployed account creates the account + performs the operation.
 *
 * Multiple unlock **factors** all wrap the same DEK, so opening any one yields the
 * control key:
 *   - **device** (P-256 ECIES): silent daily signing, per-device, non-syncable;
 *   - **passkey** (WebAuthn PRF): synced anchor to approve a new device / recover;
 *   - **recovery code**: offline backup (optional).
 *
 * Self-custodial: the address is a pure function of identity and the control key
 * lives only in the account's own data entries. Creation needs neither an org API
 * key nor a relayer, and the optional relayer is only a fee payer + reserve sponsor
 * (never a custodian or identity authority), so a bad/absent relayer can cost fees
 * but can never move funds or squat an address. When an `appId` is provided we also
 * record the created address in the Cavos backend `wallets` table (best-effort) so
 * it counts toward billing — this is pure bookkeeping and never drives address
 * resolution, custody, or signing.
 */
export class CavosStellar {
  // Discriminant for the `CavosWallet` union. Classic `G…` IS the Stellar chain
  // now (the Soroban `C…` path was removed), so this is "stellar".
  readonly chain = "stellar" as const;
  isNewAccount = false;
  /**
   * Native MasterDEK wallet. A synced passkey unwraps the DEK onto this device;
   * it is not added as a Horizon extra signer.
   */
  nativeDek = false;
  /** Native accounts only: a passkey the user added can restore this account. */
  passkeyRestore = false;
  private statusValue: StellarConnectStatus;

  /** Track whether account is created on-chain (for lazy deploy). */
  private _isDeployed: boolean;
  /** Pending passkey PRF output to include in first create. */
  private _pendingPasskeyPrf: Uint8Array | null = null;
  /**
   * Asked for the passkey secret that wraps this account's DEK, while creating
   * the account.
   *
   * The same shape as `Cavos.approverForDeploy`, and here it is not merely
   * tidier: this secret opens the account, so it must never be written down.
   * Deriving it from the passkey at the moment of the create is the only
   * handling that leaves no copy behind.
   */
  passkeyFactorForCreate?: () => Promise<Uint8Array | null>;
  /** Pending recovery code to include in first create. */
  private _pendingRecoveryCode: string | null = null;
  /** Starting balance for account creation. */
  private readonly startingBalance: bigint;
  /** Source keypair for self-funded creation. */
  private readonly sourceKeypair?: Keypair;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    status: StellarConnectStatus,
    readonly network: StellarNetwork,
    private readonly adapter: StellarAdapter,
    _deviceKey: DeviceUnwrapKey | undefined,
    private control: ControlKey | undefined,
    _dek: Uint8Array | undefined,
    private readonly relayer: StellarRelayer | undefined,
    opts: {
      appId?: string;
      appSalt: string;
      backendUrl: string;
      environment?: "development" | "production";
      startingBalance: bigint;
      sourceKeypair?: Keypair;
    },
  ) {
    this.statusValue = status;
    this._isDeployed = status !== "undeployed";
    this.startingBalance = opts.startingBalance;
    this.sourceKeypair = opts.sourceKeypair;
  }

  get status(): StellarConnectStatus {
    return this.statusValue;
  }

  /** Whether this account is deployed/created on-chain. */
  get isDeployed(): boolean {
    return this._isDeployed;
  }

  static async connect(opts: ConnectStellarOptions): Promise<CavosStellar> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/stellar: connect requires `identity` or `auth`");

    const adapter = new StellarAdapter({ network: opts.network, horizonUrl: opts.horizonUrl });
    const startingBalance = opts.startingBalance ?? DEFAULT_STARTING_BALANCE;

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new StellarRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, environment: opts.environment })
        : undefined);

    const buildOpts = {
      appId: opts.appId,
      appSalt: opts.appSalt,
      backendUrl,
      environment: opts.environment,
      startingBalance,
      sourceKeypair: opts.sourceKeypair,
    };

    const registry: WalletRegistry | null =
      opts.registry ??
      (opts.appId
        ? new HttpWalletRegistry({
            baseUrl: backendUrl,
            appId: opts.appId,
            network: opts.network,
            ...(opts.environment ? { environment: opts.environment } : {}),
            authToken: () => opts.auth?.getAuthToken?.() ?? null,
          })
        : null);

    if (opts.vault || opts.recovery || opts.socialRecovery || opts.passkey) {
      const native = opts.vault
        ? await connectThroughVault("stellar", identity, opts.appSalt, () =>
            opts.vault!.connectStellar(vaultConnectParams({ ...opts, identity })),
          )
        : await resolveNativeStellar({
            identity,
            appSalt: opts.appSalt,
            registry: registry ?? new InMemoryWalletRegistry(),
            credential: opts.credential,
            socialRecovery: opts.socialRecovery,
            recovery: opts.recovery,
            factor: opts.factor,
            store: opts.wrapStore,
            ...passkeyRestoreInput({
              passkey: opts.passkey,
              appId: opts.appId,
              backendUrl,
              environment: opts.environment,
              authToken: () => opts.auth?.getAuthToken?.() ?? null,
            }),
          });
      const deployed = await adapter.isDeployed(native.address);
      const wallet = new CavosStellar(
        identity,
        native.address,
        native.control ? (deployed ? "ready" : "undeployed") : "needs-device-approval",
        opts.network,
        adapter,
        opts.deviceKey,
        native.control,
        undefined,
        relayer,
        buildOpts,
      );
      wallet.isNewAccount = native.isNewAccount;
      wallet.nativeDek = true;
      wallet.passkeyRestore = "passkey" in native && native.passkey === true;
      return wallet;
    }

    // Grandfathered path. First device named a random G that cannot be sealed
    // into the enclave after the fact. A new device still needs a passkey or
    // recovery code for those accounts.
    type FreshKey = { address: string; control: WebCryptoControlKey };
    const candidate = await WebCryptoControlKey.create();
    const generated: FreshKey = { address: candidate.publicAddress(), control: candidate };
    const { address, existing } = await resolveAddress({
      key: { userId: identity.userId, appId: opts.appId ?? "local", chain: "stellar", network: opts.network },
      registry,
      initialSigner: { x: 0n, y: 0n },
      compute: () => generated.address,
    });

    const build = (
      status: StellarConnectStatus,
      unlocked?: Unlocked,
    ): CavosStellar =>
      new CavosStellar(
        identity,
        address,
        status,
        opts.network,
        adapter,
        opts.deviceKey,
        unlocked?.control,
        undefined,
        relayer,
        buildOpts,
      );

    // LAZY DEPLOY: Check if account exists but DO NOT create here.
    // Account creation happens on first execute() call.
    if (await adapter.isDeployed(address)) {
      const unlocked = await unlockViaDevice(address);
      return build(unlocked ? "ready" : "needs-device-approval", unlocked ?? undefined);
    }

    if (existing) {
      const pending = await WebCryptoControlKey.load({ keyId: address });
      if (!pending) return build("needs-device-approval");
      return build("undeployed", { control: pending });
    }

    await generated.control.persist(address);
    const wallet = build("undeployed", { control: generated.control });
    wallet.isNewAccount = false;
    return wallet;
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

  private setStatus(next: StellarConnectStatus): void {
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


  /**
   * Called when an action needs this device to hold the control key and it does
   * not. The refusal lives here, where the action is, because integrators call
   * `wallet.execute` directly — a wrapper in the React provider never sees it.
   */
  onAuthorizationNeeded?: () => Promise<void>;

  /** Native XLM balance of the account, in stroops. */
  async balance(): Promise<bigint> {
    return this.adapter.balance(this.address);
  }

  /**
   * True if the account has a passkey factor enrolled (`cv:wp`), so a new device
   * can be approved with the passkey instead of a recovery code. Mirrors the
   * other chains' `hasPasskey()` for the React provider.
   *
   * Returns true for undeployed accounts if a passkey is pending enrollment.
   */
  async hasPasskey(): Promise<boolean> {
    if (this.nativeDek && this.passkeyRestore) return true;
    if (this.statusValue === "undeployed") {
      return this._pendingPasskeyPrf !== null;
    }
    try {
      const entries = await this.adapter.loadDataEntries(this.address);
      return STELLAR_PASSKEY_DATA_KEY in entries;
    } catch {
      return false;
    }
  }

  /**
   * Whether the control key is unlocked on this device (status ready). Classic
   * approvals land synchronously via Horizon, so this reflects state immediately
   * (no indexing delay to poll for).
   *
   * For undeployed accounts, returns false (not yet on-chain).
   */
  async isReady(): Promise<boolean> {
    if (this.statusValue === "undeployed") {
      return false;
    }
    return this.statusValue === "ready";
  }

  /**
   * Move `amount` stroops of native XLM to `destination`, signed by the control
   * key.
   *
   * **Lazy deploy**: If the account is undeployed, the first execute creates the
   * account first (sponsored, 0 XLM cost), then performs the payment in a follow-up
   * transaction. Native XLM cannot ride the create tx (the account needs to exist
   * to send FROM it).
   *
   * Sponsored by default (the relayer fee-bumps and pays the fee); pass
   * `{ sponsored: false }` to submit directly — the account pays its own (tiny)
   * fee from its XLM balance. The control key signs identically in both modes;
   * only the fee payer differs.
   */
  async execute(amount: bigint, destination: string, opts?: ExecuteOptions): Promise<string> {
    // Handle lazy deploy: first execute on undeployed account
    if (this.statusValue === "undeployed") {
      return this._createAndExecute(amount, destination, opts);
    }

    // Authorization is part of the send, not a precondition that aborts it —
    // the same shape as the first execute creating the account and paying in
    // one go.
    if (this.statusValue === "needs-device-approval" && this.onAuthorizationNeeded) {
      await this.onAuthorizationNeeded();
    }

    const control = this.requireControl();
    const inner = await this.adapter.buildPaymentTx({ from: this.address, to: destination, amount });
    return this.submitInner(inner, control, opts);
  }

  /**
   * Create the account first (sponsored), then perform the payment.
   * Called by execute() when status is "undeployed".
   */
  private async _createAndExecute(
    amount: bigint,
    destination: string,
    opts?: ExecuteOptions,
  ): Promise<string> {
    // Create the account first
    const { control } = await this._createAccount();

    // Now the account exists — perform the payment
    const inner = await this.adapter.buildPaymentTx({ from: this.address, to: destination, amount });
    return this.submitInner(inner, control, opts);
  }

  /**
   * Create the Stellar account on-chain. Returns the control key and DEK.
   * Uses the pre-generated control key from connect() if available, otherwise
   * generates a new one.
   *
   * The control seed is loaded from pendingControl at the moment of creation,
   * used only to write the encrypted cv:ct entry, then wiped immediately. The
   * signing is done via the non-extractable WebCryptoControlKey, so the seed
   * never sits in memory on the hot spend path.
   */
  private async _createAccount(): Promise<Unlocked> {
    if (!this.relayer && !this.sourceKeypair) {
      throw new Error("kit/stellar: a relayer (appId) or sourceKeypair is required to create the account");
    }

    if (!this.control) {
      throw new Error(
        "kit/stellar: the control key for this address is not held by this device — approve this device first",
      );
    }

    const control = this.control;
    const controlAddress = control.publicAddress();
    const extraSigners: string[] = [];
    let passkeyEntry: Uint8Array | undefined;

    if (!this.nativeDek) {
      const passkeyPrf = this._pendingPasskeyPrf ?? (await this.passkeyFactorForCreate?.()) ?? null;
      if (passkeyPrf) {
        const passkey = await importPasskeySigner(passkeyPrf);
        extraSigners.push(passkey.publicAddress());
        passkeyEntry = utf8ToBytes(passkey.publicAddress());
      }

      if (this._pendingRecoveryCode) {
        const recovery = await importRecoverySigner(this._pendingRecoveryCode);
        extraSigners.push(recovery.publicAddress());
      }
    }

    const alreadyExists = await this.adapter.isDeployed(this.address);

    if (this.relayer) {
      const relayerSource = await this.relayer.getSource();
      if (alreadyExists) {
        const entries: DataEntryWrites = { [STELLAR_MODEL_DATA_KEY]: utf8ToBytes("1") };
        if (passkeyEntry) entries[STELLAR_PASSKEY_DATA_KEY] = passkeyEntry;
        const rotation = extraSigners[0] ? { newControl: extraSigners[0] } : undefined;
        await this.submitDataWrite(entries, control, undefined, rotation);
        for (const signer of extraSigners.slice(1)) {
          await this.submitDataWrite({}, control, undefined, { newControl: signer });
        }
      } else {
        const tx = await this.adapter.buildSponsoredCreateTx({
          relayer: relayerSource,
          controlAddress,
          extraSigners,
        });
        await signTransactionWithControlKey(tx, control);
        await this.relayer.submit("create", tx.toXDR());
        const afterCreate: DataEntryWrites = {};
        if (passkeyEntry) afterCreate[STELLAR_PASSKEY_DATA_KEY] = passkeyEntry;
        if (Object.keys(afterCreate).length > 0) {
          await this.submitDataWrite(afterCreate, control);
        }
      }
    } else {
      const funder = this.sourceKeypair!;
      if (alreadyExists) {
        const entries: DataEntryWrites = { [STELLAR_MODEL_DATA_KEY]: utf8ToBytes("1") };
        if (passkeyEntry) entries[STELLAR_PASSKEY_DATA_KEY] = passkeyEntry;
        await this.submitDataWrite(entries, control, { sponsored: false }, extraSigners[0] ? { newControl: extraSigners[0] } : undefined);
      } else {
        const tx = await this.adapter.buildCreateTx({
          funder: funder.publicKey(),
          controlAddress,
          extraSigners,
          startingBalance: this.startingBalance,
        });
        await signTransactionWithControlKey(tx, control);
        tx.sign(funder);
        await this.adapter.submit(tx);
      }
    }

    this._isDeployed = true;
    this.setStatus("ready");
    this.isNewAccount = true;
    this.control = control;
    this._pendingPasskeyPrf = null;
    this._pendingRecoveryCode = null;

    return { control };
  }

  /**
   * Invoke a Soroban contract method, authorized by this account's control key.
   *
   * The full flow: build + simulate the invocation (footprint, resource fees, and
   * the required `SorobanAuthorizationEntry`s come back from the RPC), then for
   * every auth entry whose credential address is THIS account's `G…`, re-sign it
   * with the control key (`authorizeEntry`). Finally sign the tx envelope and
   * submit via the Soroban RPC (or, when sponsored, fee-bump through the relayer).
   *
   * This is what lets a Cavos account act as a `require_auth(role)` signer in
   * contracts like Trustless Work's escrow (approve/release/dispute/…). `args`
   * accepts native JS values (converted via `nativeToScVal`) or ready `xdr.ScVal`s.
   */
  async invokeContract(params: {
    contractId: string;
    method: string;
    args?: (xdr.ScVal | unknown)[];
    opts?: ExecuteOptions;
  }): Promise<string> {
    if (this.statusValue === "undeployed") {
      throw new Error("kit/stellar: invokeContract requires a deployed account. Call execute() first to create the account.");
    }
    const control = this.requireReadyControl();
    const scArgs = (params.args ?? []).map((a) =>
      a instanceof xdr.ScVal ? a : nativeToScVal(a),
    );
    const prepared = await this.adapter.buildInvokeTx({
      from: this.address,
      contractId: params.contractId,
      method: params.method,
      args: scArgs,
    });
    const signed = await this.signSorobanAuth(prepared, control);
    return this.submitSoroban(signed, control, params.opts);
  }

  /**
   * Open a trustline to a classic asset (e.g. USDC) so the account can hold /
   * receive it — required before funding a Trustless Work escrow in USDC. A
   * trustline creates a new subentry (reserve), so when sponsored the relayer
   * pays it (begin/endSponsoringFutureReserves); `{ sponsored: false }` makes the
   * account pay its own reserve. Returns the confirmed tx hash.
   */
  async addTrustline(
    asset: { code: string; issuer: string },
    opts?: ExecuteOptions & { limit?: string },
  ): Promise<string> {
    if (this.statusValue === "undeployed") {
      throw new Error("kit/stellar: addTrustline requires a deployed account. Call execute() first to create the account.");
    }
    const control = this.requireReadyControl();
    const sponsored = resolveFeeMode(opts, 'sponsored') === 'sponsored';
    if (sponsored && this.relayer) {
      const relayerSource = await this.relayer.getSource();
      const tx = await this.adapter.buildSponsoredChangeTrustTx({
        relayer: relayerSource,
        account: this.address,
        asset,
        limit: opts?.limit,
      });
      await signTransactionWithControlKey(tx, control);
      return this.relayer.submit("trustline", tx.toXDR());
    }
    const tx = await this.adapter.buildChangeTrustTx({ account: this.address, asset, limit: opts?.limit });
    await signTransactionWithControlKey(tx, control);
    return this.adapter.submit(tx);
  }

  /** This account's balance of a classic token (e.g. USDC) as a 7-dp string, or
   *  "0" if no trustline exists. Read-only; needs no unlock. */
  async tokenBalance(asset: { code: string; issuer: string }): Promise<string> {
    return this.adapter.tokenBalance(this.address, asset);
  }

  /**
   * Sign an externally-built transaction XDR with the control key and return the
   * signed XDR (does NOT submit). This is the wallet-adapter seam: it mirrors a
   * classic wallet's `signTransaction(unsignedXdr) → signedXdr`, so apps that
   * build the tx server-side (e.g. Trustless Work's REST API returns an unsigned
   * XDR) can use a Cavos account as a drop-in signer.
   *
   * Handles both auth models: for Soroban invocations whose auth entries name
   * THIS account it re-signs those entries (`authorizeEntry`); for source-account
   * auth (and classic txs) the control-key envelope signature is what satisfies
   * the account. Entries authorizing other addresses are left untouched.
   */
  async signXdr(unsignedXdr: string): Promise<string> {
    const control = this.requireControl();
    const tx = TransactionBuilder.fromXDR(unsignedXdr, this.adapter.passphrase) as Transaction;
    const withAuth = await this.signSorobanAuth(tx, control);
    await signTransactionWithControlKey(withAuth, control);
    return withAuth.toXDR();
  }

  /**
   * Sign an arbitrary message off-chain with the control key. Nothing is
   * submitted. Stellar's model differs from Starknet/Solana: the signing key is
   * the ed25519 **control key** (not a P-256 device key), so `curve` is
   * `"ed25519"` and `publicKey` is the control key's `G…` address.
   *
   * A verifier calls `Keypair.fromPublicKey(controlAddress).verify(messageBytes,
   * signature)` — standard ed25519 math. The message is prefixed with the Cavos
   * domain prefix (`"Cavos Signed Message:\n<len>\n"`) before signing.
   */
  async signMessage(message: string | Uint8Array): Promise<MessageSignature> {
    const control = this.requireControl();
    const msgBytes = typeof message === "string" ? utf8ToBytes(message) : message;
    const sig = await control.signMessage(msgBytes);
    return {
      signature: sig,
      publicKey: control.publicAddress(),
      curve: "ed25519",
    };
  }

  /**
   * Build + sign a native XLM payment WITHOUT submitting it. Returns the signed
   * inner Transaction as base64 XDR. A relayer can fee-bump it (the control
   * signature stays valid through the fee-bump wrap); or the caller can submit
   * it directly via Horizon.
   *
   * The signature binds to the account's sequence number and the tx has a 180s
   * timeout, so it is single-use — submit (or fee-bump) promptly.
   */
  async signTransaction(amount: bigint, destination: string): Promise<StellarSignedTransaction> {
    const control = this.requireControl();
    const inner = await this.adapter.buildPaymentTx({ from: this.address, to: destination, amount });
    await signTransactionWithControlKey(inner, control);
    return { chain: "stellar", xdr: inner.toXDR() };
  }

  /**
   * Enroll a passkey as an unlock factor: wrap the DEK under the passkey's PRF
   * output and write the `cv:wp` entry. This is the synced anchor used to approve
   * a new device or recover — it survives device loss. Idempotent-ish: writing it
   * again just overwrites the wrap of the same DEK.
   *
   * **Undeployed accounts**: The passkey PRF output is stored pending and will be
   * included in the first account creation. No on-chain write happens until execute().
   */
  async enrollPasskey(prfOutput: Uint8Array): Promise<string> {
    if (this.nativeDek) return this.address; // PRF is the KDF; not a Horizon extra.
    if (this.statusValue === "undeployed") {
      this._pendingPasskeyPrf = prfOutput;
      await this._createAccount();
      this.setStatus("ready");
      return this.address;
    }

    const passkey = await importPasskeySigner(prfOutput);
    const control = this.requireUnlocked().control;
    return this.submitDataWrite(
      { [STELLAR_PASSKEY_DATA_KEY]: utf8ToBytes(passkey.publicAddress()) },
      control,
      undefined,
      { newControl: passkey.publicAddress() },
    );
  }

  /**
   * Set up a recovery code as an unlock factor: wrap the DEK under the code's KEK
   * and write the `cv:wr` entry. Optional in v1 — the integrating app decides when
   * to surface it. The code never leaves the device; only the wrap goes on-chain.
   *
   * **Undeployed accounts**: The recovery code is stored pending and will be
   * included in the first account creation. No on-chain write happens until execute().
   */
  async setupRecovery(code: string): Promise<string> {
    if (this.nativeDek) return this.address;
    if (this.statusValue === "undeployed") {
      this._pendingRecoveryCode = code;
      return "";
    }

    const recovery = await importRecoverySigner(code);
    return this.submitDataWrite({}, this.requireUnlocked().control, undefined, {
      newControl: recovery.publicAddress(),
    });
  }

  /**
   * From a new browser/device (`needs-device-approval`), approve THIS device using
   * the user's synced passkey. Reconstructs the passkey extra signer, then
   * `setOptions` adds this device. Flips status to `ready`.
   */
  async approveThisDeviceWithPasskey(prfOutput: Uint8Array): Promise<string> {
    if (this.nativeDek) {
      throw new Error("kit/stellar: restore this device by connecting with your passkey");
    }
    return this.addThisDeviceWith(await importPasskeySigner(prfOutput), "passkey");
  }

  /** Approve THIS device using the recovery code (same as the passkey path, for
   *  the backup factor). */
  async approveThisDeviceWithRecovery(code: string): Promise<string> {
    if (this.nativeDek) {
      throw new Error("kit/stellar: native accounts restore by connecting with the enclave or a passkey");
    }
    return this.addThisDeviceWith(await importRecoverySigner(code), "recovery code");
  }

  /**
   * Slot ids of every device currently able to unlock this account, newest-first
   * order not guaranteed. This device's slot is `deviceKey.slotId()`. Feed these
   * to `removeDevice` to build a device-management UI.
   */
  async listDevices(): Promise<string[]> {
    return this.adapter.signerKeys(this.address);
  }

  async removeDevice(params: {
    slotId: string;
    passkeyPrfOutput?: Uint8Array;
    recoveryCode?: string;
    opts?: ExecuteOptions;
  }): Promise<{ transactionHash: string; controlAddress: string; evictedSlots: string[] }> {
    const control = this.requireUnlocked().control;
    if (params.slotId === this.address || params.slotId === control.publicAddress()) {
      throw new Error("kit/stellar: cannot revoke the signer you are using");
    }
    const transactionHash = await this.submitDataWrite({}, control, params.opts, {
      oldControl: params.slotId,
    });
    return {
      transactionHash,
      controlAddress: control.publicAddress(),
      evictedSlots: [params.slotId],
    };
  }

  /** The control key's public G address (the weight-1 real signer), for display. */
  get controlAddress(): string | undefined {
    return this.control?.publicAddress();
  }

  // --- internals ----------------------------------------------------------

  private async addThisDeviceWith(factor: ControlKey, name: string): Promise<string> {
    if (this.statusValue === "ready") {
      throw new Error("kit/stellar: this device is already authorized");
    }
    const device = await WebCryptoControlKey.create();
    await device.persist(this.address);
    try {
      const hash = await this.submitDataWrite({}, factor, undefined, {
        newControl: device.publicAddress(),
      });
      this.control = device;
      this.setStatus("ready");
      return hash;
    } catch {
      throw new Error(`kit/stellar: could not add this device with the ${name} — wrong factor or not enrolled`);
    }
  }

  /**
   * Sign an inner (account-sourced) payment tx with the control key and submit it:
   *   - sponsored (default) → with a relayer, wrap in a fee-bump (relayer pays
   *     the fee) and POST; falls back to self-funded if no relayer;
   *   - `{ sponsored: false }` → submit directly (the account pays its own fee).
   * Payments add no subentries, so no reserve sponsorship is needed here.
   */
  /**
   * Re-sign every Soroban auth entry whose credential address is this account
   * with the control key, then re-assemble the tx. Entries authorizing OTHER
   * addresses (e.g. a different escrow role) are left untouched — each party
   * signs their own. Requires rebuilding the invoke op with the signed entries.
   */
  private async signSorobanAuth(prepared: Transaction, control: ControlKey): Promise<Transaction> {
    // A Soroban invocation carries its auth entries on the (invokeHostFunction)
    // operation. Scan every op so an externally-built XDR isn't assumed op-0.
    const authOps = (prepared.operations as unknown as { auth?: xdr.SorobanAuthorizationEntry[] }[])
      .filter((o) => Array.isArray(o.auth) && o.auth.length > 0) as {
      auth: xdr.SorobanAuthorizationEntry[];
    }[];
    if (authOps.length === 0) return prepared;

    const g = Keypair.fromPublicKey(this.address).xdrPublicKey();
    const validUntil = (await this.adapter.latestLedger()) + AUTH_VALIDITY_LEDGERS;
    const signer = createSorobanSigner(control);
    for (const op of authOps) {
      op.auth = await Promise.all(
        op.auth.map(async (entry) => {
          const creds = entry.credentials();
          // Only address credentials that name THIS account need our signature;
          // source-account creds and other addresses are left as-is.
          if (creds.switch().name !== "sorobanCredentialsAddress") return entry;
          const addr = creds.address().address();
          if (addr.switch().name !== "scAddressTypeAccount") return entry;
          if (addr.accountId().toXDR("base64") !== g.toXDR("base64")) return entry;
          return authorizeEntry(entry, signer, validUntil, this.adapter.passphrase);
        }),
      );
    }
    return prepared;
  }

  /** Sign the tx envelope with the control key and submit the Soroban tx: sponsored
   *  (default) → fee-bump through the relayer; else submit directly via the RPC. */
  private async submitSoroban(
    tx: Transaction,
    control: ControlKey,
    opts?: ExecuteOptions,
  ): Promise<string> {
    await signTransactionWithControlKey(tx, control);
    const sponsored = resolveFeeMode(opts, 'sponsored') === 'sponsored';
    if (sponsored && this.relayer) {
      const feeSource = await this.relayer.getSource();
      const bump = this.adapter.wrapFeeBump(tx, feeSource);
      return this.relayer.submit("soroban", bump.toXDR());
    }
    return this.adapter.submitSoroban(tx);
  }

  private async submitInner(
    inner: Transaction,
    control: ControlKey,
    opts?: ExecuteOptions,
  ): Promise<string> {
    await signTransactionWithControlKey(inner, control);
    const sponsored = resolveFeeMode(opts, 'sponsored') === 'sponsored';
    if (sponsored && this.relayer) {
      const feeSource = await this.relayer.getSource();
      const bump = this.adapter.wrapFeeBump(inner, feeSource);
      return this.relayer.submit("fee-bump", bump.toXDR());
    }
    // Self-funded: submit the account-sourced inner tx directly; the account pays
    // the (tiny) fee out of its own balance.
    return this.adapter.submit(inner);
  }

  /**
   * Write data entries (add a factor / device slot) — which create NEW subentries
   * that each need ~0.5 XLM of reserve. A relayer-sponsored account holds no XLM,
   * so the write must be sponsored by the relayer (source + sponsor), exactly like
   * account creation — a plain fee-bump would fail with `op_low_reserve`.
   *   - sponsored (default) → with a relayer, build a sponsored write (relayer
   *     source + begin/end sponsoring), control-sign the account ops, relay
   *     co-signs + submits; falls back to self-funded if no relayer;
   *   - `{ sponsored: false }` → the account writes directly (it must hold its
   *     own reserve for the new subentries).
   */
  private async submitDataWrite(
    entries: DataEntryWrites,
    control: ControlKey,
    opts?: ExecuteOptions,
    rotation?: ControlRotation,
  ): Promise<string> {
    const sponsored = resolveFeeMode(opts, 'sponsored') === 'sponsored';
    if (sponsored && this.relayer) {
      // The relayer account is the tx source, and EVERY sponsored write from
      // every user of this app consumes one of its sequence numbers. Two writes
      // landing in the same ledger therefore collide, and the loser is rejected
      // with `tx_bad_seq`. Changing the sequence changes the tx hash, so the
      // relay cannot fix it up for us — the control signature would no longer
      // match — which means the retry has to rebuild and re-sign here.
      let lastError: unknown;
      for (let attempt = 0; attempt < 3; attempt++) {
        const { address, sequence } = await this.relayer.fetchSourceAccount();
        const tx = await this.adapter.buildSponsoredDataTx({
          relayer: address,
          account: this.address,
          entries,
          rotation,
          ...(sequence !== undefined ? { relayerSequence: sequence } : {}),
        });
        await signTransactionWithControlKey(tx, control); // account-sourced manageData + endSponsoring
        try {
          return await this.relayer.submit("sponsored-data", tx.toXDR());
        } catch (e) {
          lastError = e;
          if (!isBadSequence(e)) throw e;
          // Someone else took the sequence. Back off briefly — Stellar closes a
          // ledger every ~5s, and retrying inside the same one just collides
          // again — then rebuild against a fresh one.
          await new Promise((resolve) => setTimeout(resolve, 1_500 * (attempt + 1)));
        }
      }
      throw lastError;
    }
    const tx = await this.adapter.buildDataTx({ account: this.address, entries, rotation });
    await signTransactionWithControlKey(tx, control);
    return this.adapter.submit(tx);
  }

  /**
   * Get the control key for signing operations. Works for both ready AND
   * undeployed accounts (undeployed accounts have a pre-generated control key).
   * Only throws for needs-device-approval status where no control key exists.
   */
  private requireControl(): ControlKey {
    if (!this.control) {
      throw new Error("kit/stellar: this device is not an authorized signer of the wallet");
    }
    return this.control;
  }

  /**
   * Get the control key, but only for on-chain operations that require ready status.
   * Use requireControl() for off-chain signing that can work while undeployed.
   */
  private requireReadyControl(): ControlKey {
    if (this.statusValue !== "ready" || !this.control) {
      throw new Error("kit/stellar: this device is not an authorized signer of the wallet");
    }
    return this.control;
  }

  private requireUnlocked(): Unlocked {
    return { control: this.requireControl() };
  }
}

async function unlockViaDevice(address: string): Promise<Unlocked | null> {
  const cached = await WebCryptoControlKey.load({ keyId: address });
  return cached ? { control: cached } : null;
}

/**
 * Whether a relay rejection was a sequence-number collision. The relay returns
 * the network's `result_codes` in its error text, so match on the code rather
 * than on prose that may be reworded.
 */
function isBadSequence(error: unknown): boolean {
  const message = error instanceof Error ? error.message : String(error);
  return message.includes("tx_bad_seq");
}
