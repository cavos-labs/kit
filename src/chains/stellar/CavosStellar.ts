import { Keypair, TransactionBuilder, authorizeEntry, nativeToScVal, xdr } from "@stellar/stellar-sdk";
import { Buffer } from "buffer";
import type { AuthProvider, Identity } from "../../auth/AuthProvider";
import { StellarAdapter } from "./StellarAdapter";
import {
  deriveStellarMasterKeypair,
  generateControlKey,
  controlKeypairFromSeed,
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
  deviceWrapEntries,
  PASSKEY_BASE,
  RECOVERY_BASE,
  type AccountEnvelope,
} from "./datamap";
import { chunkTo64 } from "./envelope";
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

export type StellarConnectStatus = "ready" | "needs-device-approval";

/** The DEK + control keypair recovered by opening any single unlock factor. */
interface Unlocked {
  control: Keypair;
  dek: Uint8Array;
}

/**
 * High-level entry for the classic-Stellar (`G…`) multisig account — the classic
 * analogue of `CavosStellar` (Soroban). One `connect` derives the deterministic
 * `G…` address, creates the account if needed, and on a known device unlocks the
 * control key from the on-chain envelope so `execute` signs silently.
 *
 * Multiple unlock **factors** all wrap the same DEK, so opening any one yields the
 * control key:
 *   - **device** (P-256 ECIES): silent daily signing, per-device, non-syncable;
 *   - **passkey** (WebAuthn PRF): synced anchor to approve a new device / recover;
 *   - **recovery code**: offline backup (optional).
 *
 * Self-custodial, no backend, no registry: the address is a pure function of
 * identity and the control key lives only in the account's own data entries.
 * Unlike the Soroban `CavosStellar`, this path uses NO wallet registry —
 * creation needs neither an org API key nor a relayer. The optional relayer is
 * only a fee payer + reserve sponsor (never a custodian or identity authority),
 * so a bad/absent relayer can cost fees but can never move funds or squat an
 * address.
 */
export class CavosStellar {
  // Discriminant for the `CavosWallet` union. Classic `G…` IS the Stellar chain
  // now (the Soroban `C…` path was removed), so this is "stellar".
  readonly chain = "stellar" as const;
  isNewAccount = false;
  private statusValue: StellarConnectStatus;

  private constructor(
    readonly identity: Identity,
    readonly address: string,
    status: StellarConnectStatus,
    readonly network: StellarNetwork,
    private readonly adapter: StellarAdapter,
    private readonly deviceKey: DeviceUnwrapKey,
    private control: Keypair | undefined,
    private dek: Uint8Array | undefined,
    private readonly relayer: StellarRelayer | undefined,
  ) {
    this.statusValue = status;
  }

  get status(): StellarConnectStatus {
    return this.statusValue;
  }

  static async connect(opts: ConnectStellarOptions): Promise<CavosStellar> {
    const identity = opts.identity ?? (await opts.auth?.authenticate());
    if (!identity) throw new Error("kit/stellar: connect requires `identity` or `auth`");

    const adapter = new StellarAdapter({ network: opts.network, horizonUrl: opts.horizonUrl });
    const master = deriveStellarMasterKeypair({ userId: identity.userId, appSalt: opts.appSalt });
    const address = master.publicKey();
    const startingBalance = opts.startingBalance ?? DEFAULT_STARTING_BALANCE;

    const backendUrl = opts.backendUrl ?? "https://cavos.xyz";
    const relayer =
      opts.relayer ??
      (opts.appId
        ? new StellarRelayer({ baseUrl: backendUrl, appId: opts.appId, network: opts.network, environment: opts.environment })
        : undefined);

    const build = (status: StellarConnectStatus, unlocked?: Unlocked): CavosStellar =>
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
      );

    if (await adapter.isDeployed(address)) {
      // Returning user: rebuild the control key from the on-chain envelope if this
      // device has a wrap slot; otherwise this is a new device awaiting approval.
      const unlocked = await unlockViaDevice(adapter, address, opts.deviceKey);
      return build(unlocked ? "ready" : "needs-device-approval", unlocked ?? undefined);
    }

    // First sign-up on this identity: create the account.
    if (!relayer && !opts.sourceKeypair) {
      throw new Error("kit/stellar: a relayer (appId) or sourceKeypair is required to create the account");
    }
    const { keypair: control, seed: controlSeed } = generateControlKey();
    const dek = generateDEK();
    const envelope: AccountEnvelope = {
      ct: sealControlSeed(controlSeed, dek),
      deviceWraps: { [opts.deviceKey.slotId()]: eciesWrapDEK(dek, opts.deviceKey.publicKeySec1()) },
    };

    if (relayer) {
      // Gasless + sponsored: the relayer is source + fee payer + reserve sponsor.
      // Master signs its own account ops; the relayer co-signs the envelope.
      const relayerSource = await relayer.getSource();
      const tx = await adapter.buildSponsoredCreateTx({
        relayer: relayerSource,
        masterAddress: address,
        controlAddress: control.publicKey(),
        envelope,
      });
      tx.sign(master);
      await relayer.submit("create", tx.toXDR());
    } else {
      const funder = opts.sourceKeypair!;
      const tx = await adapter.buildCreateTx({
        funder: funder.publicKey(),
        masterAddress: address,
        controlAddress: control.publicKey(),
        envelope,
        startingBalance,
      });
      // Master authorizes its own account ops (while still weight 1); funder is the
      // source + fee payer. After this tx the master is permanently weight 0.
      tx.sign(master, funder);
      await adapter.submit(tx);
    }

    const wallet = build("ready", { control, dek });
    wallet.isNewAccount = true;
    return wallet;
  }

  /** Native XLM balance of the account, in stroops. */
  async balance(): Promise<bigint> {
    return this.adapter.balance(this.address);
  }

  /** True if the account has a passkey factor enrolled (`cv:wp`), so a new device
   *  can be approved with the passkey instead of a recovery code. Mirrors the
   *  other chains' `hasPasskey()` for the React provider. */
  async hasPasskey(): Promise<boolean> {
    try {
      const env = fromDataEntries(await this.adapter.loadDataEntries(this.address));
      return !!env.passkeyWrap;
    } catch {
      return false;
    }
  }

  /** Whether the control key is unlocked on this device (status ready). Classic
   *  approvals land synchronously via Horizon, so this reflects state immediately
   *  (no indexing delay to poll for). */
  async isReady(): Promise<boolean> {
    return this.statusValue === "ready";
  }

  /**
   * Move `amount` stroops of native XLM to `destination`, signed by the control
   * key. Sponsored by default (the relayer fee-bumps and pays the fee); pass
   * `{ sponsored: false }` to submit directly — the account pays its own (tiny)
   * fee from its XLM balance. The control key signs identically in both modes;
   * only the fee payer differs.
   */
  async execute(amount: bigint, destination: string, opts?: ExecuteOptions): Promise<string> {
    const control = this.requireControl();
    const inner = await this.adapter.buildPaymentTx({ from: this.address, to: destination, amount });
    return this.submitInner(inner, control, opts);
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
    const control = this.requireControl();
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
    const control = this.requireControl();
    const sponsored = opts?.sponsored !== false;
    if (sponsored && this.relayer) {
      const relayerSource = await this.relayer.getSource();
      const tx = await this.adapter.buildSponsoredChangeTrustTx({
        relayer: relayerSource,
        account: this.address,
        asset,
        limit: opts?.limit,
      });
      tx.sign(control);
      return this.relayer.submit("sponsored-data", tx.toXDR());
    }
    const tx = await this.adapter.buildChangeTrustTx({ account: this.address, asset, limit: opts?.limit });
    tx.sign(control);
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
    withAuth.sign(control);
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
    // stellar-sdk Keypair.sign expects a Buffer and returns a 64-byte Buffer.
    const sig = control.sign(Buffer.from(prefixed));
    return {
      signature: new Uint8Array(sig),
      publicKey: control.publicKey(),
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
    inner.sign(control);
    return { chain: "stellar", xdr: inner.toXDR() };
  }

  /**
   * Enroll a passkey as an unlock factor: wrap the DEK under the passkey's PRF
   * output and write the `cv:wp` entry. This is the synced anchor used to approve
   * a new device or recover — it survives device loss. Idempotent-ish: writing it
   * again just overwrites the wrap of the same DEK. Requires a ready device.
   */
  async enrollPasskey(prfOutput: Uint8Array): Promise<string> {
    const { control, dek } = this.requireUnlocked();
    const wrap = wrapDEK(dek, derivePasskeyKEK(prfOutput));
    return this.writeFactor(PASSKEY_BASE, wrap, control);
  }

  /**
   * Set up a recovery code as an unlock factor: wrap the DEK under the code's KEK
   * and write the `cv:wr` entry. Optional in v1 — the integrating app decides when
   * to surface it. The code never leaves the device; only the wrap goes on-chain.
   * Requires a ready device.
   */
  async setupRecovery(code: string): Promise<string> {
    const { control, dek } = this.requireUnlocked();
    const wrap = wrapDEK(dek, deriveRecoveryKEK(code));
    return this.writeFactor(RECOVERY_BASE, wrap, control);
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

  /** The control key's public G address (the weight-1 real signer), for display. */
  get controlAddress(): string | undefined {
    return this.control?.publicKey();
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
    this.statusValue = "ready";
    return hash;
  }

  /** Write a single-factor wrap (passkey/recovery) into the account data entries,
   *  signed by the control key. Overwrites cleanly if the base already existed and
   *  the new blob has the same chunk count. */
  private async writeFactor(base: string, wrap: Uint8Array, control: Keypair): Promise<string> {
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
  private async signSorobanAuth(prepared: Transaction, control: Keypair): Promise<Transaction> {
    // A Soroban invocation carries its auth entries on the (invokeHostFunction)
    // operation. Scan every op so an externally-built XDR isn't assumed op-0.
    const authOps = (prepared.operations as unknown as { auth?: xdr.SorobanAuthorizationEntry[] }[])
      .filter((o) => Array.isArray(o.auth) && o.auth.length > 0) as {
      auth: xdr.SorobanAuthorizationEntry[];
    }[];
    if (authOps.length === 0) return prepared;

    const g = Keypair.fromPublicKey(this.address).xdrPublicKey();
    const validUntil = (await this.adapter.latestLedger()) + AUTH_VALIDITY_LEDGERS;
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
          return authorizeEntry(entry, control, validUntil, this.adapter.passphrase);
        }),
      );
    }
    return prepared;
  }

  /** Sign the tx envelope with the control key and submit the Soroban tx: sponsored
   *  (default) → fee-bump through the relayer; else submit directly via the RPC. */
  private async submitSoroban(
    tx: Transaction,
    control: Keypair,
    opts?: ExecuteOptions,
  ): Promise<string> {
    tx.sign(control);
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
    control: Keypair,
    opts?: ExecuteOptions,
  ): Promise<string> {
    inner.sign(control);
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
    entries: Record<string, Uint8Array>,
    control: Keypair,
    opts?: ExecuteOptions,
  ): Promise<string> {
    const sponsored = opts?.sponsored !== false;
    if (sponsored && this.relayer) {
      const relayerSource = await this.relayer.getSource();
      const tx = await this.adapter.buildSponsoredDataTx({
        relayer: relayerSource,
        account: this.address,
        entries,
      });
      tx.sign(control); // account-sourced manageData + endSponsoring
      return this.relayer.submit("sponsored-data", tx.toXDR());
    }
    const tx = await this.adapter.buildDataTx({ account: this.address, entries });
    tx.sign(control);
    return this.adapter.submit(tx);
  }

  private requireControl(): Keypair {
    if (this.statusValue !== "ready" || !this.control) {
      throw new Error("kit/stellar: control key not unlocked on this device (needs approval)");
    }
    return this.control;
  }

  private requireUnlocked(): Unlocked {
    const control = this.requireControl();
    if (!this.dek) throw new Error("kit/stellar: DEK unavailable on this device");
    return { control, dek: this.dek };
  }
}

/** Rebuild the control keypair from the on-chain envelope using this device's
 *  ECIES wrap. Returns null if this device has no slot or the wrap can't open. */
async function unlockViaDevice(
  adapter: StellarAdapter,
  address: string,
  deviceKey: DeviceUnwrapKey,
): Promise<Unlocked | null> {
  const env = await loadEnvelope(adapter, address);
  const wrap = env.deviceWraps[deviceKey.slotId()];
  if (!wrap) return null;
  try {
    const dek = await deviceKey.unwrap(wrap);
    return openControl(env, dek);
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
    return openControl(env, dek);
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
    return openControl(env, dek);
  } catch {
    return null;
  }
}

async function loadEnvelope(adapter: StellarAdapter, address: string): Promise<AccountEnvelope> {
  return fromDataEntries(await adapter.loadDataEntries(address));
}

function openControl(env: AccountEnvelope, dek: Uint8Array): Unlocked {
  const controlSeed = openControlSeed(env.ct, dek);
  return { control: controlKeypairFromSeed(controlSeed), dek };
}
