import type { ControlKey } from "../chains/stellar/WebCryptoControlKey";
import { STARKNET_NETWORKS, type StarknetNetwork } from "../chains/starknet/constants";
import { resolveNativeStarknet, type StarknetSpend } from "../chains/starknet/nativeConnect";
import { parseStarknetPrivacyConfig, type StarknetPrivacyConfig } from "../chains/starknet/privacy/config";
import { PrivacySession, type PrivacySessionDeps } from "../chains/starknet/privacy/session";
import { resolveNativeSolana } from "../chains/solana/nativeConnect";
import { resolveNativeStellar } from "../chains/stellar/nativeConnect";
import { DEFAULT_SOCIAL_RECOVERY_ATTESTATION } from "../recovery/attestationDefaults";
import { SocialRecoveryClient, type AttestationPolicy } from "../recovery/SocialRecoveryClient";
import { HttpWalletRegistry } from "../registry/HttpWalletRegistry";
import type { ResolveNativeInput } from "../secret/nativeAccount";
import { zeroize, type MasterDEK } from "../secret/dek";
import { readLocalDek, type LocalDekInput } from "../secret/localDek";
import { addPasskey } from "../secret/PasskeyDekPort";
import { HttpPasskeyWrapStore, type PasskeyWrapStore } from "../registry/PasskeyWrapStore";
import type { Ed25519SpendSigner } from "../signer/Ed25519SpendSigner";
import type { PasskeyPrfProvider } from "../signer/PasskeyProvider";
import { bigIntTo32Bytes } from "../crypto/encoding";
import { solanaNetworkName, starknetNetworkName, stellarNetworkName, stellarNetworkNameFromId } from "./network";
import { VersionedMessage } from "@solana/web3.js";
import { Signer, stark, type Signature } from "starknet";
import { xdr } from "@stellar/stellar-sdk";
import {
  isQueryVersion,
  parseStarknetCalls,
  parseStarknetPrivacy,
  parseStarknetTypedData,
  selectorOf,
  type StarknetPrivacyOperation,
} from "./parseStarknet";
import { idbLedger, type SpendLedger } from "./ledger";
import { VaultModal } from "./modal";
import { parseSolanaMessage } from "./parseSolana";
import { parseStellarAuthEntry, parseStellarTransaction } from "./parseStellar";
import { STRICT_POLICY, type VaultPolicy } from "./limits";
import { evaluate, totals, type Line, type ParsedTx } from "./policy";
import {
  VAULT_HELLO,
  VAULT_READY,
  type ConnectParams,
  type ConnectResult,
  type VaultMethod,
  type VaultParams,
  type VaultRequest,
} from "./protocol";

type NativeBase = Omit<ResolveNativeInput, "chain" | "importSpend" | "loadPersisted">;

export interface VaultHandlerDeps {
  appId: string;
  backendUrl: string;
  attestation?: AttestationPolicy;
  policy: VaultPolicy;
  ledger: SpendLedger;
  confirm(lines: Line[], context: { network: string }): Promise<boolean>;
  passkey(user: { userId: string; userName: string }): PasskeyPrfProvider;
  passkeyWraps?: (auth: { environment?: "development" | "production"; authToken?: string | null }) => PasskeyWrapStore;
  readDek?: (input: LocalDekInput) => Promise<MasterDEK>;
  resolveSolana?: (input: NativeBase) => Promise<{ address: string; spend: Ed25519SpendSigner | null; isNewAccount: boolean }>;
  resolveStellar?: (input: NativeBase) => Promise<{ address: string; control?: ControlKey; isNewAccount: boolean }>;
  resolveStarknet?: (input: NativeBase) => Promise<{ address: string; spend: StarknetSpend | null; isNewAccount: boolean }>;
  solanaNetwork?: (recentBlockhash: string) => Promise<string>;
  /** Private transfer settings of the app for a network ("sepolia", "mainnet"), from the Cavos dashboard. Throws on an invalid one. */
  privacy?: (network: string) => StarknetPrivacyConfig | undefined;
  privacyDeps?: PrivacySessionDeps;
}

interface Account {
  userId: string;
  address: string;
  network: string;
  solana?: Ed25519SpendSigner;
  stellar?: ControlKey;
  starknet?: StarknetSpend;
  privacy?: PrivacySession;
  paymasterApiKey?: string;
}

export function createVaultHandler(deps: VaultHandlerDeps): (request: VaultRequest) => Promise<unknown> {
  const accounts = new Map<string, Account>();
  const resolveSolana = deps.resolveSolana ?? resolveNativeSolana;
  const resolveStellar = deps.resolveStellar ?? resolveNativeStellar;
  const resolveStarknet = deps.resolveStarknet ?? resolveNativeStarknet;
  const readDek = deps.readDek ?? readLocalDek;
  const passkeyWraps =
    deps.passkeyWraps ??
    ((auth) =>
      new HttpPasskeyWrapStore({
        baseUrl: deps.backendUrl,
        appId: deps.appId,
        ...(auth.environment ? { environment: auth.environment } : {}),
        authToken: () => auth.authToken ?? null,
      }));
  const solanaNetwork = deps.solanaNetwork ?? ((blockhash: string) => solanaNetworkName(blockhash));
  // Every key, wrap and counter is filed under the app that embedded the vault,
  // so a second app on the same site cannot reach them with its own policy.
  const scope = deps.appId;
  const queues = new Map<string, Promise<unknown>>();

  async function connect(params: ConnectParams): Promise<ConnectResult> {
    const handle = `${params.chain}:${params.userId}:${params.appSalt}`;
    const wraps = params.recovery === "passkey" ? passkeyWraps(params) : undefined;
    const input: NativeBase = {
      identity: { userId: params.userId, ...(params.userName ? { email: params.userName } : {}) },
      appSalt: params.appSalt,
      keyScope: scope,
      registry: new HttpWalletRegistry({
        baseUrl: deps.backendUrl,
        appId: deps.appId,
        network: params.network,
        ...(params.environment ? { environment: params.environment } : {}),
        authToken: () => params.authToken ?? null,
      }),
      ...(params.credential ? { credential: params.credential } : {}),
      ...(params.recovery === "enclave"
        ? {
            socialRecovery: new SocialRecoveryClient({
              baseUrl: deps.backendUrl,
              appId: deps.appId,
              environment: params.environment,
              attestation: deps.attestation ?? DEFAULT_SOCIAL_RECOVERY_ATTESTATION,
            }),
          }
        : {}),
      ...(wraps
        ? {
            passkey: deps.passkey({ userId: params.userId, userName: params.userName ?? params.userId }),
            passkeyWraps: wraps,
            appId: scope,
          }
        : {}),
    };
    // Read after connect, so a device that just restored from a passkey says so.
    const hasPasskey = async () => {
      if (!wraps) return false;
      try {
        return (await wraps.list(params.userId)).length > 0;
      } catch {
        return false;
      }
    };
    if (params.chain === "solana") {
      const native = await resolveSolana(input);
      accounts.set(handle, { userId: params.userId, address: native.address, network: params.network, solana: native.spend ?? undefined });
      return {
        handle,
        address: native.address,
        publicKey: native.spend?.publicKeyRaw() ?? null,
        isNewAccount: native.isNewAccount,
        passkey: await hasPasskey(),
      };
    }
    if (params.chain === "starknet") {
      const native = await resolveStarknet(input);
      accounts.set(handle, { userId: params.userId, address: native.address, network: params.network, starknet: native.spend ?? undefined });
      return {
        handle,
        address: native.address,
        publicKey: native.spend ? bigIntTo32Bytes(BigInt(native.spend.publicKey())) : null,
        isNewAccount: native.isNewAccount,
        passkey: await hasPasskey(),
      };
    }
    const native = await resolveStellar(input);
    accounts.set(handle, { userId: params.userId, address: native.address, network: params.network, stellar: native.control });
    return {
      handle,
      address: native.address,
      publicKey: native.control?.publicKeyRaw() ?? null,
      isNewAccount: native.isNewAccount,
      passkey: await hasPasskey(),
    };
  }

  function account(handle: string): Account {
    const found = accounts.get(handle);
    if (!found) throw new Error("kit/vault: unknown account, connect first");
    return found;
  }

  /** One signature per user at a time: the daily total is read, checked and recorded as one step. */
  function exclusive<T>(key: string, run: () => Promise<T>): Promise<T> {
    const next = (queues.get(key) ?? Promise.resolve()).then(run, run);
    queues.set(key, next.catch(() => undefined));
    return next;
  }

  function authorizeAndSign<T>(
    acct: Account,
    parsed: ParsedTx,
    network: () => Promise<string>,
    sign: () => Promise<T>,
  ): Promise<T> {
    const ledgerKey = `${scope}|${acct.userId}`;
    return exclusive(ledgerKey, async () => {
      const spent = new Map<string, bigint>();
      for (const asset of totals(parsed.spends).keys()) {
        spent.set(asset, await deps.ledger.spentToday(ledgerKey, asset));
      }
      const decision = evaluate(parsed, spent, deps.policy);
      if (decision === "block") throw new Error("kit/vault: this app's policy does not allow this transaction");
      if (decision === "confirm" && !(await deps.confirm(parsed.lines, { network: await network() }))) {
        throw new Error("kit/vault: the user rejected this transaction");
      }
      const signature = await sign();
      // The daily limit caps what is signed without asking; what the user approved does not use it up.
      if (decision === "sign") await deps.ledger.record(ledgerKey, parsed.spends);
      return signature;
    });
  }

  function privacySession(acct: Account, paymasterApiKey: string | undefined): { session: PrivacySession; config: StarknetPrivacyConfig; chainId: string } {
    const spend = requireKey(acct.starknet);
    const network = STARKNET_NETWORKS[acct.network as StarknetNetwork];
    if (!network) throw new Error("kit/vault: private transfers are only available on Starknet");
    const config = deps.privacy?.(acct.network);
    if (!config) {
      throw new Error(`kit/vault: add private transfer settings for ${acct.network} to this app in the Cavos dashboard`);
    }
    if (paymasterApiKey !== undefined) acct.paymasterApiKey = paymasterApiKey;
    acct.privacy ??= new PrivacySession({
      config,
      chainId: network.chainId,
      rpcUrl: network.rpcUrl,
      account: { address: acct.address, spend },
      paymasterApiKey: () => {
        if (!acct.paymasterApiKey) throw new Error("kit/vault: private transfers need the paymaster API key");
        return acct.paymasterApiKey;
      },
      ...(deps.privacyDeps ? { deps: deps.privacyDeps } : {}),
    });
    return { session: acct.privacy, config, chainId: network.chainId };
  }

  async function privacyOperation(
    params: { handle: string; token: string; amount: string; paymasterApiKey: string; recipient?: string },
    kind: StarknetPrivacyOperation["kind"],
    run: (session: PrivacySession, amount: bigint) => Promise<unknown>,
  ): Promise<unknown> {
    const acct = account(params.handle);
    const { session, config, chainId } = privacySession(acct, params.paymasterApiKey);
    const amount = baseUnits(params.amount);
    const to = kind === "deposit" ? config.pool : params.recipient;
    const parsed = parseStarknetPrivacy({ kind, token: address(params.token, "token"), amount, to: address(to, "recipient") });
    const start = await authorizeAndSign(acct, parsed, async () => starknetNetworkName(chainId), async () => () => run(session, amount));
    return start();
  }

  const methods: { [M in VaultMethod]: (params: VaultParams<M>) => Promise<unknown> } = {
    connect,
    async signSolanaTransaction({ handle, message }) {
      const acct = account(handle);
      const signer = requireKey(acct.solana);
      const parsed = parseSolanaMessage(message, acct.address);
      return authorizeAndSign(acct, parsed, () => solanaNetwork(recentBlockhash(message)), () =>
        signer.signTransaction(message),
      );
    },
    async signStellarTransaction({ handle, xdr, networkPassphrase }) {
      const acct = account(handle);
      const signer = requireKey(acct.stellar);
      const network = stellarNetworkName(networkPassphrase);
      const parsed = parseStellarTransaction(xdr, networkPassphrase, acct.address);
      return authorizeAndSign(acct, parsed, async () => network, () => signer.signTransaction(xdr, networkPassphrase));
    },
    async signStellarAuthEntry({ handle, preimage }) {
      const acct = account(handle);
      const signer = requireKey(acct.stellar);
      const parsed = parseStellarAuthEntry(preimage);
      const network = stellarNetworkNameFromId(stellarAuthNetworkId(preimage));
      return authorizeAndSign(acct, parsed, async () => network, () => signer.signAuthEntry(preimage));
    },
    async signMessage({ handle, message }) {
      const acct = account(handle);
      return requireKey(acct.solana ?? acct.stellar).signMessage(message);
    },
    async signStarknetTypedData({ handle, typedData, accountAddress }) {
      const acct = account(handle);
      const signer = new Signer(requireKey(acct.starknet).privateKey());
      const network = starknetNetworkName(typedData.domain.chainId);
      return authorizeAndSign(acct, parseStarknetTypedData(typedData, accountAddress), async () => network, async () =>
        toFelts(await signer.signMessage(typedData, accountAddress)),
      );
    },
    async signStarknetInvoke({ handle, calls, details }) {
      const acct = account(handle);
      const signer = new Signer(requireKey(acct.starknet).privateKey());
      const sign = async () => toFelts(await signer.signTransaction(calls, details));
      if (isQueryVersion(details.version)) return sign();
      const network = starknetNetworkName(details.chainId);
      const parsed = parseStarknetCalls(
        calls.map((call) => ({
          to: call.contractAddress,
          selector: selectorOf(call.entrypoint),
          calldata: ((call.calldata ?? []) as unknown[]).map(String),
        })),
        details.walletAddress,
      );
      return authorizeAndSign(acct, parsed, async () => network, sign);
    },
    async privacyStatus({ handle, token }) {
      return privacySession(account(handle), undefined).session.status(token);
    },
    async privacyBalance({ handle, token }) {
      return (await privacySession(account(handle), undefined).session.balance(token)).toString();
    },
    async privacyRegister({ handle, paymasterApiKey }) {
      return privacySession(account(handle), paymasterApiKey).session.register();
    },
    async privacyDeposit(params) {
      return privacyOperation(params, "deposit", (session, amount) => session.deposit(params.token, amount));
    },
    async privacyTransfer(params) {
      return privacyOperation(params, "transfer", (session, amount) => session.transfer(params.token, params.recipient, amount));
    },
    async privacyWithdraw(params) {
      return privacyOperation(params, "withdraw", (session, amount) => session.withdraw(params.token, params.recipient, amount));
    },
    async forget({ userId, appSalt }) {
      // Only lets go of the unlocked keys. Deleting stored ones is not the app's
      // call: without a recovery factor it would destroy the wallet.
      for (const chain of ["solana", "stellar", "starknet"]) accounts.delete(`${chain}:${userId}:${appSalt}`);
    },
    async enrollPasskey({ userId, appSalt, userName, environment, authToken }) {
      const chain = (["solana", "stellar", "starknet"] as const).find((c) => accounts.get(`${c}:${userId}:${appSalt}`)?.address);
      if (!chain) throw new Error("kit/vault: connect a wallet before adding a passkey");
      const { address } = accounts.get(`${chain}:${userId}:${appSalt}`)!;
      const dek = await readDek({ chain, userId, appSalt, address, keyScope: scope });
      const user = { userId, userName: userName ?? userId };
      try {
        await addPasskey({
          passkey: deps.passkey(user),
          wraps: passkeyWraps({ environment, authToken }),
          owner: { appId: scope, userId },
          dek,
          user,
        });
      } finally {
        zeroize(dek);
      }
    },
  };

  return (request) => (methods[request.method] as (params: unknown) => Promise<unknown>)(request.params);
}

function recentBlockhash(message: Uint8Array): string {
  return VersionedMessage.deserialize(message).recentBlockhash;
}

function stellarAuthNetworkId(preimage: Uint8Array): Uint8Array {
  return new Uint8Array(xdr.HashIdPreimage.fromXDR(Buffer.from(preimage)).sorobanAuthorization().networkId());
}

function baseUnits(value: unknown): bigint {
  if (typeof value !== "string" || !/^\d+$/.test(value) || BigInt(value) === 0n) {
    throw new Error("kit/vault: amount must be a positive decimal string of base units");
  }
  return BigInt(value);
}

function address(value: unknown, field: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value) || BigInt(value) === 0n) {
    throw new Error(`kit/vault: ${field} must be a 0x-prefixed Starknet address`);
  }
  return value;
}

function toFelts(signature: Signature): string[] {
  return stark.formatSignature(signature);
}

function requireKey<T>(key: T | undefined): T {
  if (!key) throw new Error("kit/vault: this browser holds no key for the account");
  return key;
}

export function serveVault(port: MessagePort, handle: (request: VaultRequest) => Promise<unknown>): void {
  port.onmessage = async ({ data }: MessageEvent<VaultRequest>) => {
    try {
      port.postMessage({ id: data.id, ok: true, result: await handle(data) });
    } catch (error) {
      port.postMessage({ id: data.id, ok: false, error: error instanceof Error ? error.message : String(error) });
    }
  };
}

export interface VaultHostOptions {
  /** Cavos backend for the registry and the enclave. Never taken from the app. */
  backendUrl: string;
  attestation?: AttestationPolicy;
  /** Defaults to `/vault/confirm` on this origin. */
  confirmUrl?: string;
  /** Defaults to `/api/vault/policy` on this origin. */
  policyUrl?: string;
}

/** Runs inside the vault iframe. One embedding app per iframe. */
export function startVaultHost(opts: VaultHostOptions): void {
  const confirmUrl = opts.confirmUrl ?? `${location.origin}/vault/confirm`;
  const policyUrl = opts.policyUrl ?? `${location.origin}/api/vault/policy`;
  let claimed = false;

  window.addEventListener("message", async (event) => {
    if (event.source !== window.parent || event.data?.type !== VAULT_HELLO || claimed) return;
    const port = event.ports[0];
    if (!port) return;
    claimed = true;
    const appId = String(event.data.appId ?? "");
    const app = await loadApp(policyUrl, appId);
    if (!originAllowed(app.origins, event.origin)) {
      port.postMessage({
        id: 0,
        ok: false,
        error: `kit/vault: add ${event.origin} to this app's allowed web origins in the Cavos dashboard`,
      });
      port.close();
      return;
    }

    const modal = new VaultModal(event.origin, confirmUrl, (visible) =>
      port.postMessage({ event: visible ? "show" : "hide" }),
    );
    const handle = createVaultHandler({
      appId,
      backendUrl: opts.backendUrl,
      attestation: opts.attestation,
      policy: app.policy,
      privacy: app.privacy,
      ledger: idbLedger(),
      confirm: (lines, context) => modal.review(lines, context.network),
      passkey: (user) => modal.passkey(user),
    });
    serveVault(port, handle);
    port.postMessage({ id: 0, ok: true, result: null });
  });

  window.parent.postMessage({ type: VAULT_READY }, "*");
}

interface AppSettings {
  /** Null when the app registered none. */
  origins: string[] | null;
  policy: VaultPolicy;
  privacy: (network: string) => StarknetPrivacyConfig | undefined;
}

const NO_PRIVACY = () => undefined;

async function loadApp(policyUrl: string, appId: string): Promise<AppSettings> {
  if (!appId) return { origins: [], policy: STRICT_POLICY, privacy: NO_PRIVACY };
  try {
    const res = await fetch(`${policyUrl}?app_id=${encodeURIComponent(appId)}`);
    if (!res.ok) return { origins: [], policy: STRICT_POLICY, privacy: NO_PRIVACY };
    const body = (await res.json()) as { origins?: string[] | null; policy?: VaultPolicy; privacy?: unknown };
    return { origins: body.origins ?? null, policy: body.policy ?? STRICT_POLICY, privacy: privacySettings(body.privacy) };
  } catch {
    return { origins: [], policy: STRICT_POLICY, privacy: NO_PRIVACY };
  }
}

/** The dashboard keys private transfer settings by Starknet network name. */
function privacySettings(raw: unknown): (network: string) => StarknetPrivacyConfig | undefined {
  const byNetwork = typeof raw === "object" && raw !== null ? (raw as Record<string, unknown>) : {};
  return (network) => {
    if (!Object.prototype.hasOwnProperty.call(byNetwork, network)) return undefined;
    try {
      return parseStarknetPrivacyConfig(byNetwork[network]);
    } catch (error) {
      throw new Error(`kit/vault: the private transfer settings for ${network} are invalid. ${error instanceof Error ? error.message : ""}`);
    }
  };
}

/** An app with no registered origins cannot embed the vault at all. */
function originAllowed(origins: string[] | null, origin: string): boolean {
  return origins !== null && origins.includes(origin);
}
