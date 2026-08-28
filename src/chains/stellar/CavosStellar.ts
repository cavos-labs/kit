import { Keypair, TransactionBuilder, authorizeEntry, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import {
  StellarAdapter,
  type ControlRotation,
  type DataEntryWrites,
} from "./StellarAdapter";
import {
  controlKeypairFromSeed,
  generateControlKey,
} from "./keys";
import {
  generateDEK,
  sealControlSeed,
  openControlSeed,
  wrapDEK,
  eciesWrapDEK,
  deriveRecoveryKEK,
  derivePasskeyKEK,
  unwrapDEK,
} from "./envelope";
import {
  fromDataEntries,
  toDataEntries,
  deviceWrapEntries,
  PASSKEY_BASE,
  RECOVERY_BASE,
  type AccountEnvelope,
} from "./datamap";
import { chunkTo64 } from "./envelope";
import { HttpWalletRegistry } from "../../registry/HttpWalletRegistry";
import { resolveAddress } from "../../registry/resolveAddress";
import {
  savePendingControl,
  loadPendingControl,
  clearPendingControl,
} from "./pendingControl";
import type { DeviceUnwrapKey } from "./DeviceUnwrapKey";
import { StellarRelayer } from "./StellarRelayer";
import type { StellarNetwork } from "./constants";
import type { Transaction } from "@stellar/stellar-sdk";
import { utf8ToBytes } from "../../crypto/encoding";
import type { ExecuteOptions } from "../../chains/ChainAdapter";
import {
  prefixedMessageBytes,
  type MessageSignature,
  type StellarSignedTransaction,
} from "../../signing";
import {
  WebCryptoControlKey,
  type ControlKey,
  signTransactionWithControlKey,
  createSorobanSigner,
} from "./WebCryptoControlKey";

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
  deviceKey: DeviceUnwrapKey;
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
}

/**
 * Chain status for Stellar accounts.
 * - `undeployed`: Address derived but no on-chain account exists yet. First execute will create.
 * - `ready`: Account exists and this device can sign (control key unlocked).
 * - `needs-device-approval`: Account exists but this device is not yet authorized.
 */
export type StellarConnectStatus = "undeployed" | "ready" | "needs-device-approval";

/** The DEK + control key recovered by opening any single unlock factor. */
interface Unlocked {
  control: ControlKey;
  dek: Uint8Array;
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
  private statusValue: StellarConnectStatus;

  /** Track whether account is created on-chain (for lazy deploy). */
  private _isDeployed: boolean;
  /** Pending passkey PRF output to include in first create. */
  private _pendingPasskeyPrf: Uint8Array | null = null;
  /** Pending recovery code to include in first create. */
  private _pendingRecoveryCode: string | null = null;
  /** Pre-generated control seed for first create (not persisted on-chain until execute). */
  private _controlSeed: Uint8Array | null = null;
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
    private readonly deviceKey: DeviceUnwrapKey,
    private control: ControlKey | undefined,
    private dek: Uint8Array | undefined,
    private readonly relayer: StellarRelayer | undefined,
    opts: {
      appId?: string;
      appSalt: string;
      backendUrl: string;
      environment?: "development" | "production";
      startingBalance: bigint;
      sourceKeypair?: Keypair;
      controlSeed?: Uint8Array;
    },
  ) {
    this.statusValue = status;
    this._isDeployed = status !== "undeployed";
    this.startingBalance = opts.startingBalance;
    this.sourceKeypair = opts.sourceKeypair;
    this._controlSeed = opts.controlSeed ?? null;
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

    // The registry names the wallet. On a miss this device generates the control
    // key and its public key BECOMES the `G…` — the first device names the
    // account here exactly as the constructor does on Starknet.
    const registry = opts.appId
      ? new HttpWalletRegistry({
          baseUrl: backendUrl,
          appId: opts.appId,
          network: opts.network,
          ...(opts.environment ? { environment: opts.environment } : {}),
          authToken: () => opts.auth?.getAuthToken?.() ?? null,
        })
      : null;

    type ControlSeed = { address: string; seed: Uint8Array };
    let generated: ControlSeed | null = null;
    const { address, existing } = await resolveAddress({
      key: { userId: identity.userId, appId: opts.appId ?? "local", chain: "stellar", network: opts.network },
      registry,
      // Stellar has no secp256r1 signer in its address; the registry only needs
      // an initial signer for the chains that record device keys.
      initialSigner: { x: 0n, y: 0n },
      compute: () => {
        generated = newControlKey();
        return generated.address;
      },
    });
    // TS cannot see that `compute` ran, so re-read it through its own type.
    const fresh = generated as ControlSeed | null;

    const build = (
      status: StellarConnectStatus,
      unlocked?: Unlocked & { controlSeed?: Uint8Array },
    ): CavosStellar =>
      new CavosStellar(
        identity,
        address,
        status,
        opts.network,
        adapter,
        opts.deviceKey,
        unlocked?.control,
        unlocked?.dek,
        relayer,
        { ...buildOpts, controlSeed: unlocked?.controlSeed },
      );

    // LAZY DEPLOY: Check if account exists but DO NOT create here.
    // Account creation happens on first execute() call.
    if (await adapter.isDeployed(address)) {
      // Returning user: first try to load the non-extractable control key from
      // IndexedDB (no unwrap needed). If not found, unwrap from on-chain envelope,
      // import into WebCrypto (non-extractable), and wipe the seed from JS memory.
      const unlocked = await unlockViaDevice(adapter, address, opts.deviceKey);
      return build(unlocked ? "ready" : "needs-device-approval", unlocked ?? undefined);
    }

    // The address was already the user's, so the key this device may have just
    // generated lost the race and is worthless under someone else's address.
    if (existing) {
      if (fresh) wipeSeed(fresh.seed);
      // But THIS device may be the one that claimed it a moment ago and simply
      // has not created the account yet — a reload, a remount, a second connect.
      // Its seed is still here, so it is the owner, not a stranger.
      const pending = await loadPendingControl(address, opts.deviceKey);
      if (!pending) return build("needs-device-approval");
      return build("undeployed", await persistControlKey(address, { seed: pending }));
    }

    // This device named the address. Persist its control key now so off-chain
    // signing (signMessage, signXdr) works before the first execute, and keep
    // the sealed seed until creation writes the envelope on-chain.
    await savePendingControl(address, fresh!.seed, opts.deviceKey);
    const unlocked = await persistControlKey(address, fresh!);
    const wallet = build("undeployed", unlocked);
    wallet.isNewAccount = false; // Will be set to true after first deploy
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
    if (this.statusValue === "undeployed") {
      return this._pendingPasskeyPrf !== null;
    }
    try {
      const env = fromDataEntries(await this.adapter.loadDataEntries(this.address));
      return !!env.passkeyWrap;
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
   */
  private async _createAccount(): Promise<Unlocked> {
    if (!this.relayer && !this.sourceKeypair) {
      throw new Error("kit/stellar: a relayer (appId) or sourceKeypair is required to create the account");
    }

    // The control key IS the account, so it must be the exact one generated at
    // connect — a fresh key here would create a DIFFERENT account.
    if (!this._controlSeed || !this.control || !this.dek) {
      throw new Error(
        "kit/stellar: the control key for this address is not held by this device — approve this device first",
      );
    }
    const controlSeed = this._controlSeed;
    const controlAddress = this.control.publicAddress();
    const dek = this.dek;
    const controlKeypair = controlKeypairFromSeed(controlSeed);

    // Build envelope with device wrap and any pending factors
    const envelope: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [this.deviceKey.slotId()]: eciesWrapDEK(dek, this.deviceKey.publicKeySec1()) },
    };

    // Add pending passkey wrap if enrolled before first create
    if (this._pendingPasskeyPrf) {
      envelope.passkeyWrap = wrapDEK(dek, derivePasskeyKEK(this._pendingPasskeyPrf));
    }

    // Add pending recovery wrap if set up before first create
    if (this._pendingRecoveryCode) {
      envelope.recoveryWrap = wrapDEK(dek, deriveRecoveryKEK(this._pendingRecoveryCode));
    }

    // The account can already exist without ever having been ours to create:
    // funding a testnet address with friendbot creates it, and the demo tells
    // people to do exactly that before their first send. Creating it again is
    // `op_already_exists` and takes the whole transaction down with it.
    //
    // What still has to happen either way is the envelope. Without those `cv:`
    // entries the control key exists only on this device, and no other device —
    // and no recovery — can ever reach the wallet again.
    const alreadyExists = await this.adapter.isDeployed(this.address);

    if (this.relayer) {
      // Gasless + sponsored: the relayer is source + fee payer + reserve sponsor.
      const relayerSource = await this.relayer.getSource();
      if (alreadyExists) {
        const tx = await this.adapter.buildSponsoredDataTx({
          relayer: relayerSource,
          account: this.address,
          entries: toDataEntries(envelope),
        });
        tx.sign(controlKeypair);
        await this.relayer.submit("sponsored-data", tx.toXDR());
      } else {
        const tx = await this.adapter.buildSponsoredCreateTx({
          relayer: relayerSource,
          controlAddress,
          envelope,
        });
        tx.sign(controlKeypair);
        await this.relayer.submit("create", tx.toXDR());
      }
    } else {
      const funder = this.sourceKeypair!;
      if (alreadyExists) {
        const tx = await this.adapter.buildDataTx({
          account: this.address,
          entries: toDataEntries(envelope),
        });
        tx.sign(controlKeypair);
        await this.adapter.submit(tx);
      } else {
        const tx = await this.adapter.buildCreateTx({
          funder: funder.publicKey(),
          controlAddress,
          envelope,
          startingBalance: this.startingBalance,
        });
        tx.sign(controlKeypair, funder);
        await this.adapter.submit(tx);
      }
    }

    // If we didn't have a pre-generated control key, import now
    let control = this.control;
    if (!control) {
      control = await WebCryptoControlKey.importFromSeed(controlSeed, {
        keyId: this.address,
      });
    }

    // The envelope is on-chain now; the local claim copy has done its job.
    await clearPendingControl(this.address);

    // Wipe the control seed from memory
    wipeSeed(controlSeed);
    this._controlSeed = null;

    // Update status to ready
    this._isDeployed = true;
    this.setStatus("ready");
    this.isNewAccount = true;

    // Store the control key and DEK on this instance
    this.control = control;
    this.dek = dek;

    // Clear pending factors
    this._pendingPasskeyPrf = null;
    this._pendingRecoveryCode = null;

    return { control, dek };
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
    const sponsored = opts?.sponsored !== false;
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
    const prefixed = prefixedMessageBytes(msgBytes);
    const sig = await control.sign(prefixed);
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
    // For undeployed accounts, store the pending passkey PRF for first create
    if (this.statusValue === "undeployed") {
      this._pendingPasskeyPrf = prfOutput;
      return ""; // No tx yet — will be included in first create
    }

    const { control, dek } = this.requireUnlocked();
    const wrap = wrapDEK(dek, derivePasskeyKEK(prfOutput));
    return this.writeFactor(PASSKEY_BASE, wrap, control);
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
    // For undeployed accounts, store the pending recovery code for first create
    if (this.statusValue === "undeployed") {
      this._pendingRecoveryCode = code;
      return ""; // No tx yet — will be included in first create
    }

    const { control, dek } = this.requireUnlocked();
    const wrap = wrapDEK(dek, deriveRecoveryKEK(code));
    return this.writeFactor(RECOVERY_BASE, wrap, control);
  }

  /**
   * Export a short-lived copy of the Stellar DEK for social-recovery enrolment.
   * The caller must send it only through `SocialRecoveryClient`, which encrypts
   * it to the attested enclave before it leaves this device. The Ed25519 control
   * seed is never exported.
   */
  socialRecoveryDek(): Uint8Array {
    const { dek } = this.requireUnlocked();
    return Uint8Array.from(dek);
  }

  /**
   * Public ECIES recipient for a social-recovery wrap addressed to this exact
   * browser/device. Safe to disclose; the corresponding private key remains
   * non-extractable in IndexedDB/Keychain.
   */
  socialRecoveryRecipientPublicKey(): Uint8Array {
    return Uint8Array.from(this.deviceKey.publicKeySec1());
  }

  /**
   * From a new browser/device (`needs-device-approval`), approve THIS device using
   * the user's synced passkey: unlock the DEK via the passkey factor, then wrap it
   * to this device's slot so future sessions unlock silently. Flips status to
   * `ready`. No trip back to an already-authorized device.
   */
  async approveThisDeviceWithPasskey(prfOutput: Uint8Array): Promise<string> {
    return this.approveThisDevice(
      await unlockViaPasskey(this.adapter, this.address, prfOutput),
      "passkey",
    );
  }

  /** Approve THIS device using the recovery code (same as the passkey path, for
   *  the backup factor). */
  async approveThisDeviceWithRecovery(code: string): Promise<string> {
    return this.approveThisDevice(
      await unlockViaRecovery(this.adapter, this.address, code),
      "recovery code",
    );
  }

  /**
   * Complete a TEE social recovery on a new device. `deviceWrap` is ECIES
   * ciphertext addressed to this device's non-extractable P-256 unwrap key.
   * Cavos/Google may relay it, but only this device can recover the DEK.
   */
  async approveThisDeviceWithSocialWrap(deviceWrap: Uint8Array): Promise<string> {
    if (this.statusValue === "ready") {
      throw new Error("kit/stellar: this device is already authorized");
    }
    try {
      const dek = await this.deviceKey.unwrap(deviceWrap);
      const env = fromDataEntries(await this.adapter.loadDataEntries(this.address));
      const controlSeed = openControlSeed(env.ct, dek);
      const control = await WebCryptoControlKey.importFromSeed(controlSeed, {
        keyId: this.address,
      });
      wipeSeed(controlSeed);
      return this.approveThisDevice({ control, dek }, "social recovery");
    } catch {
      throw new Error(
        "kit/stellar: social recovery wrap is invalid for this device",
      );
    }
  }

  /**
   * Slot ids of every device currently able to unlock this account, newest-first
   * order not guaranteed. This device's slot is `deviceKey.slotId()`. Feed these
   * to `removeDevice` to build a device-management UI.
   */
  async listDevices(): Promise<string[]> {
    const env = fromDataEntries(await this.adapter.loadDataEntries(this.address));
    return Object.keys(env.deviceWraps);
  }

  /**
   * Revoke a device — the escape hatch behind the "this wasn't me" link in the
   * device-added email, and the way out if a device was authorized through a
   * path that bypassed you (a leaked recovery code, or a social-recovery wrap
   * relayed by the enclave).
   *
   * Classic Stellar has no `remove_signer`: a "device" here is an ECIES wrap of
   * the DEK in the account's data entries, and the evicted device may already
   * have cached the control seed. Erasing its wrap alone would therefore revoke
   * nothing. So this rotates, in a single tx signed by the current control key:
   *
   *   1. deletes EVERY existing `cv:` envelope entry;
   *   2. writes a fresh DEK-sealed control seed and a wrap for THIS device;
   *   3. adds the new control key as the weight-1 signer and zeroes the old one.
   *
   * Consequence, and the reason this is deliberate rather than surgical: device
   * wraps are ECIES to each device's public key, which is never stored on-chain,
   * so no other device's wrap can be re-created here. **Every other device is
   * evicted**, not just the revoked one, and must be approved again. The passkey
   * and recovery factors are KEK-derived, so they survive only if the user
   * presents them now — pass `passkeyPrfOutput` / `recoveryCode` to carry them
   * over. Prompt for the passkey before calling; otherwise the user loses their
   * synced anchor and this device becomes the only way in.
   */
  async removeDevice(params: {
    /** Slot to revoke. Must not be this device's own slot. */
    slotId: string;
    /** Fresh WebAuthn PRF output, to keep the passkey factor working. */
    passkeyPrfOutput?: Uint8Array;
    /** The user's recovery code, to keep the recovery factor working. */
    recoveryCode?: string;
    opts?: ExecuteOptions;
  }): Promise<{ transactionHash: string; controlAddress: string; evictedSlots: string[] }> {
    const { control: oldControl } = this.requireUnlocked();
    const mySlot = this.deviceKey.slotId();
    if (params.slotId === mySlot) {
      throw new Error(
        "kit/stellar: cannot revoke the device you are using — revoke it from another authorized device",
      );
    }

    const existing = await this.adapter.loadDataEntries(this.address);
    const env = fromDataEntries(existing);
    if (!env.deviceWraps[params.slotId]) {
      throw new Error(`kit/stellar: no device is enrolled in slot ${params.slotId}`);
    }

    const dek = generateDEK();
    const { keypair: controlKeypair, seed: controlSeed } = generateControlKey();
    const newControlAddress = controlKeypair.publicKey();
    const next = toDataEntries({
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [mySlot]: eciesWrapDEK(dek, this.deviceKey.publicKeySec1()) },
      passkeyWrap: params.passkeyPrfOutput
        ? wrapDEK(dek, derivePasskeyKEK(params.passkeyPrfOutput))
        : undefined,
      recoveryWrap: params.recoveryCode
        ? wrapDEK(dek, deriveRecoveryKEK(params.recoveryCode))
        : undefined,
    });

    // Clear every old `cv:` entry, then lay the new envelope over it. Entries
    // present in both maps end up as a plain overwrite (one op), and entries only
    // in the old map are deleted — which also refunds their reserve.
    const writes: DataEntryWrites = {};
    for (const name of Object.keys(existing)) {
      if (name.startsWith("cv:")) writes[name] = null;
    }
    Object.assign(writes, next);

    const transactionHash = await this.submitDataWrite(writes, oldControl, params.opts, {
      newControl: newControlAddress,
      oldControl: oldControl.publicAddress(),
    });

    // Import the new control seed into WebCrypto as non-extractable, then wipe.
    const control = await WebCryptoControlKey.importFromSeed(controlSeed, {
      keyId: this.address,
    });
    wipeSeed(controlSeed);

    // The account is now signed by the new key; keep this session usable.
    this.control = control;
    this.dek = dek;
    const evictedSlots = Object.keys(env.deviceWraps).filter((s) => s !== mySlot);
    return { transactionHash, controlAddress: newControlAddress, evictedSlots };
  }

  /** The control key's public G address (the weight-1 real signer), for display. */
  get controlAddress(): string | undefined {
    return this.control?.publicAddress();
  }

  // --- internals ----------------------------------------------------------

  private async approveThisDevice(unlocked: Unlocked | null, factor: string): Promise<string> {
    if (this.statusValue === "ready") {
      throw new Error("kit/stellar: this device is already authorized");
    }
    if (!unlocked) {
      throw new Error(`kit/stellar: could not unlock the account with the ${factor} — wrong factor or not enrolled`);
    }
    const slot = this.deviceKey.slotId();
    const wrap = eciesWrapDEK(unlocked.dek, this.deviceKey.publicKeySec1());
    const hash = await this.submitDataWrite(deviceWrapEntries(slot, wrap), unlocked.control);
    // This device is now a silent-unlock factor.
    this.control = unlocked.control;
    this.dek = unlocked.dek;
    this.setStatus("ready");
    return hash;
  }

  /** Write a single-factor wrap (passkey/recovery) into the account data entries,
   *  signed by the control key. Overwrites cleanly if the base already existed and
   *  the new blob has the same chunk count. */
  private async writeFactor(base: string, wrap: Uint8Array, control: ControlKey): Promise<string> {
    const entries: Record<string, Uint8Array> = {};
    chunkTo64(wrap).forEach((chunk, i) => {
      entries[`${base}/${i}`] = chunk;
    });
    return this.submitDataWrite(entries, control);
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
    const sponsored = opts?.sponsored !== false;
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
    const sponsored = opts?.sponsored !== false;
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
    const sponsored = opts?.sponsored !== false;
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
    const control = this.requireControl();
    if (!this.dek) throw new Error("kit/stellar: DEK unavailable on this device");
    return { control, dek: this.dek };
  }
}

/**
 * Rebuild the control key from the on-chain envelope using this device's ECIES
 * wrap. Returns null if this device has no slot or the wrap can't open.
 *
 * **Non-extractable flow**: First tries to load the control key from IndexedDB
 * (returning session on a known device). If found, no unwrap is needed — the
 * non-extractable key is already persisted. Only if IDB misses do we unwrap the
 * DEK, open the control seed, import it into WebCrypto as non-extractable, and
 * wipe the seed from JS memory.
 */
async function unlockViaDevice(
  adapter: StellarAdapter,
  address: string,
  deviceKey: DeviceUnwrapKey,
): Promise<Unlocked | null> {
  // Fast path: non-extractable control key already cached in IndexedDB.
  const cached = await WebCryptoControlKey.load({ keyId: address });
  if (cached) {
    const env = await loadEnvelope(adapter, address);
    const wrap = env.deviceWraps[deviceKey.slotId()];
    if (!wrap) return null;
    try {
      const dek = await deviceKey.unwrap(wrap);
      return { control: cached, dek };
    } catch {
      return null;
    }
  }

  // Slow path: unwrap the control seed from the on-chain envelope, import into
  // WebCrypto as non-extractable, and wipe the seed from JS memory.
  const env = await loadEnvelope(adapter, address);
  const wrap = env.deviceWraps[deviceKey.slotId()];
  if (!wrap) return null;
  try {
    const dek = await deviceKey.unwrap(wrap);
    return openControlAndImport(env, dek, address);
  } catch {
    return null;
  }
}

/** Unlock via the passkey PRF factor (`cv:wp`). */
async function unlockViaPasskey(
  adapter: StellarAdapter,
  address: string,
  prfOutput: Uint8Array,
): Promise<Unlocked | null> {
  const env = await loadEnvelope(adapter, address);
  if (!env.passkeyWrap) return null;
  try {
    const dek = unwrapDEK(env.passkeyWrap, derivePasskeyKEK(prfOutput));
    return openControlAndImport(env, dek, address);
  } catch {
    return null;
  }
}

/** Unlock via the recovery-code factor (`cv:wr`). */
async function unlockViaRecovery(
  adapter: StellarAdapter,
  address: string,
  code: string,
): Promise<Unlocked | null> {
  const env = await loadEnvelope(adapter, address);
  if (!env.recoveryWrap) return null;
  try {
    const dek = unwrapDEK(env.recoveryWrap, deriveRecoveryKEK(code));
    return openControlAndImport(env, dek, address);
  } catch {
    return null;
  }
}

async function loadEnvelope(adapter: StellarAdapter, address: string): Promise<AccountEnvelope> {
  return fromDataEntries(await adapter.loadDataEntries(address));
}

/**
 * Open the control seed from the envelope, import it into WebCrypto as a
 * non-extractable Ed25519 key, then wipe the seed from JS memory. The key is
 * persisted in IndexedDB so subsequent sessions load it without unwrapping.
 */
async function openControlAndImport(
  env: AccountEnvelope,
  dek: Uint8Array,
  address: string,
): Promise<Unlocked> {
  const controlSeed = openControlSeed(env.ct, dek);
  const control = await WebCryptoControlKey.importFromSeed(controlSeed, { keyId: address });
  wipeSeed(controlSeed);
  return { control, dek };
}

/** Overwrite a seed buffer with zeros. Best-effort memory wipe in JS. */
function wipeSeed(seed: Uint8Array): void {
  seed.fill(0);
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

/**
 * A brand-new control key. Its public key IS the account's `G…` address: this
 * is where a Stellar wallet gets named, and only the device that generated it
 * holds the seed.
 */
function newControlKey(): { address: string; seed: Uint8Array } {
  const { keypair, seed } = generateControlKey();
  return { address: keypair.publicKey(), seed };
}

/**
 * Store the freshly generated control key for an account that does not exist
 * on-chain yet, so this device can sign messages before the first execute. The
 * seed is imported as a non-extractable WebCrypto key; the on-chain envelope is
 * written when the account is created.
 */
async function persistControlKey(
  address: string,
  fresh: { seed: Uint8Array },
): Promise<Unlocked & { controlSeed: Uint8Array }> {
  const cached = await WebCryptoControlKey.load({ keyId: address });
  const control = cached ?? (await WebCryptoControlKey.importFromSeed(fresh.seed, { keyId: address }));
  return { control, dek: generateDEK(), controlSeed: fresh.seed };
}
