import { PublicKey } from "@solana/web3.js";
import { StrKey } from "@stellar/stellar-sdk";
import {
  CallData,
  SignerInterface,
  type Call,
  type DeclareSignerDetails,
  type DeployAccountSignerDetails,
  type InvocationsSignerDetails,
  type Signature,
  type TypedData,
} from "starknet";
import type { AuthProvider, Identity } from "../auth/AuthProvider";
import type { ControlKey } from "../chains/stellar/WebCryptoControlKey";
import type { SocialRecoveryCredential } from "../recovery/SocialRecoveryCredential";
import type { Ed25519SpendSigner } from "../signer/Ed25519SpendSigner";
import type { DevicePublicKey, DeviceSignature } from "../signer/DeviceSigner";
import { bytesToBigInt } from "../crypto/encoding";
import { dropLegacyCopies } from "../secret/legacy";
import {
  VAULT_HELLO,
  VAULT_READY,
  type ConnectParams,
  type ConnectResult,
  type VaultEvent,
  type VaultMethod,
  type VaultParams,
  type VaultReply,
  type VaultResult,
} from "./protocol";

export const DEFAULT_VAULT_URL = "https://vault.cavos.xyz/vault";

const LOAD_TIMEOUT_MS = 15_000;

export interface VaultClientOptions {
  appId: string;
  url?: string;
}

/**
 * The app's side of the vault. Keys live in the vault's origin; this only
 * asks for signatures, and the vault decides whether to ask the user.
 */
export class VaultClient {
  private static readonly attached = new Map<string, VaultClient>();
  private nextId = 1;
  private readonly pending = new Map<number, { resolve(value: unknown): void; reject(error: Error): void }>();

  private constructor(private readonly port: Promise<MessagePort>) {
    void port.then((p) => {
      p.onmessage = ({ data }: MessageEvent<VaultReply>) => this.settle(data);
    });
  }

  /** One iframe per vault URL and app, shared by every wallet on the page. */
  static attach(opts: VaultClientOptions): VaultClient {
    const url = opts.url ?? DEFAULT_VAULT_URL;
    const key = `${url}|${opts.appId}`;
    let client = VaultClient.attached.get(key);
    if (!client) {
      client = new VaultClient(mountIframe(url, opts.appId));
      VaultClient.attached.set(key, client);
    }
    return client;
  }

  /** Talk to a host over an existing port. For tests and custom transports. */
  static fromPort(port: MessagePort): VaultClient {
    return new VaultClient(Promise.resolve(port));
  }

  async connectSolana(params: Omit<ConnectParams, "chain">): Promise<{
    address: string;
    isNewAccount: boolean;
    spend: Ed25519SpendSigner | null;
    passkey: boolean;
  }> {
    const result = await this.call("connect", { ...params, chain: "solana" });
    return {
      address: result.address,
      isNewAccount: result.isNewAccount,
      spend: this.solanaSigner(result),
      passkey: result.passkey === true,
    };
  }

  async connectStellar(params: Omit<ConnectParams, "chain">): Promise<{
    address: string;
    isNewAccount: boolean;
    control?: ControlKey;
    passkey: boolean;
  }> {
    const result = await this.call("connect", { ...params, chain: "stellar" });
    return {
      address: result.address,
      isNewAccount: result.isNewAccount,
      control: this.stellarSigner(result),
      passkey: result.passkey === true,
    };
  }

  async connectStarknet(params: Omit<ConnectParams, "chain">): Promise<{
    publicKey: DevicePublicKey;
    accountSigner: SignerInterface;
    signMessage(message: Uint8Array): Promise<DeviceSignature>;
  }> {
    const result = await this.call("connect", { ...params, chain: "starknet" });
    if (!result.publicKey) throw new Error("kit/vault: the vault returned no Starknet key");
    const { handle } = result;
    return {
      publicKey: {
        x: bytesToBigInt(result.publicKey.subarray(1, 33)),
        y: bytesToBigInt(result.publicKey.subarray(33, 65)),
      },
      accountSigner: new VaultStarknetSigner(
        (typedData, accountAddress) => this.call("signStarknetTypedData", { handle, typedData, accountAddress }),
        (calls, details) => this.call("signStarknetInvoke", { handle, calls, details }),
      ),
      signMessage: (message) => this.call("signStarknetMessage", { handle, message }),
    };
  }

  forget(userId: string, appSalt: string): Promise<void> {
    return this.call("forget", { userId, appSalt });
  }

  /** Create a passkey, in the vault's own origin, that can restore the connected account on another device. */
  enrollPasskey(params: VaultParams<"enrollPasskey">): Promise<void> {
    return this.call("enrollPasskey", params);
  }

  private solanaSigner({ handle, publicKey }: ConnectResult): Ed25519SpendSigner | null {
    if (!publicKey) return null;
    return {
      address: () => new PublicKey(publicKey).toBase58(),
      publicKeyRaw: () => publicKey,
      signTransaction: (message) => this.call("signSolanaTransaction", { handle, message }),
      signMessage: (message) => this.call("signMessage", { handle, message }),
    };
  }

  private stellarSigner({ handle, publicKey }: ConnectResult): ControlKey | undefined {
    if (!publicKey) return undefined;
    return {
      publicAddress: () => StrKey.encodeEd25519PublicKey(Buffer.from(publicKey)),
      publicKeyRaw: () => publicKey,
      signTransaction: (xdr, networkPassphrase) => this.call("signStellarTransaction", { handle, xdr, networkPassphrase }),
      signAuthEntry: (preimage) => this.call("signStellarAuthEntry", { handle, preimage }),
      signMessage: (message) => this.call("signMessage", { handle, message }),
    };
  }

  private async call<M extends VaultMethod>(method: M, params: VaultParams<M>): Promise<VaultResult<M>> {
    const port = await this.port;
    const id = this.nextId++;
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve: resolve as (value: unknown) => void, reject });
      port.postMessage({ id, method, params });
    });
  }

  private settle(reply: VaultReply | VaultEvent): void {
    if ("event" in reply) return;
    const waiter = this.pending.get(reply.id);
    if (!waiter) return;
    this.pending.delete(reply.id);
    if (reply.ok) waiter.resolve(reply.result);
    else waiter.reject(new Error(reply.error));
  }
}

/**
 * A starknet.js signer that never sees a key. It hands the vault what is being
 * signed, typed data or calls, and the vault computes the hash itself.
 */
class VaultStarknetSigner extends SignerInterface {
  constructor(
    private readonly signTypedData: (typedData: TypedData, accountAddress: string) => Promise<string[]>,
    private readonly signInvoke: (calls: Call[], details: InvocationsSignerDetails) => Promise<string[]>,
  ) {
    super();
  }

  async getPubKey(): Promise<string> {
    return "0x0";
  }

  signMessage(typedData: TypedData, accountAddress: string): Promise<Signature> {
    return this.signTypedData(typedData, accountAddress);
  }

  signTransaction(transactions: Call[], details: InvocationsSignerDetails): Promise<Signature> {
    const calls = transactions.map((call) => ({ ...call, calldata: CallData.toCalldata(call.calldata) }));
    return this.signInvoke(calls, details);
  }

  async signDeployAccountTransaction(_details: DeployAccountSignerDetails): Promise<Signature> {
    throw new Error("kit/vault: deploy-account signing is not supported; Cavos deploys through the paymaster");
  }

  async signDeclareTransaction(_details: DeclareSignerDetails): Promise<Signature> {
    throw new Error("kit/vault: declaring classes is not supported");
  }
}

/** Connect through the vault, then retire any copy of the same keys this page stored before it. */
export async function connectThroughVault<R extends { address: string; spend?: unknown; control?: unknown }>(
  chain: "solana" | "stellar",
  identity: Identity,
  appSalt: string,
  connect: () => Promise<R>,
): Promise<R> {
  const result = await connect();
  if (result.spend || result.control) {
    await dropLegacyCopies(chain, identity.userId, appSalt, result.address).catch(() => undefined);
  }
  return result;
}

export function vaultConnectParams(input: {
  identity: Identity;
  appSalt: string;
  network: string;
  environment?: "development" | "production";
  auth?: AuthProvider;
  credential?: SocialRecoveryCredential;
  socialRecovery?: unknown;
  passkey?: unknown;
}): Omit<ConnectParams, "chain"> {
  return {
    network: input.network,
    ...(input.environment ? { environment: input.environment } : {}),
    appSalt: input.appSalt,
    userId: input.identity.userId,
    ...(input.identity.email ? { userName: input.identity.email } : {}),
    recovery: input.socialRecovery ? "enclave" : input.passkey ? "passkey" : "none",
    ...(input.credential ? { credential: input.credential } : {}),
    authToken: input.auth?.getAuthToken?.() ?? null,
  };
}

function mountIframe(url: string, appId: string): Promise<MessagePort> {
  if (typeof document === "undefined") {
    return Promise.reject(new Error("kit/vault: the vault needs a browser"));
  }
  const origin = new URL(url).origin;
  const iframe = document.createElement("iframe");
  iframe.src = url;
  // aria-label, not title: Safari shows a title as a tooltip over the whole page.
  iframe.setAttribute("aria-label", "Cavos");
  iframe.allow = `publickey-credentials-get ${origin}; publickey-credentials-create ${origin}`;
  iframe.style.cssText =
    "display:none;position:fixed;inset:0;width:100%;height:100%;border:0;z-index:2147483647;background:transparent;color-scheme:normal";
  document.body.append(iframe);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      window.removeEventListener("message", onReady);
      reject(new Error(`kit/vault: ${origin} did not load`));
    }, LOAD_TIMEOUT_MS);

    const onReady = (event: MessageEvent) => {
      if (event.source !== iframe.contentWindow || event.origin !== origin || event.data?.type !== VAULT_READY) return;
      window.removeEventListener("message", onReady);
      const channel = new MessageChannel();
      channel.port1.onmessage = ({ data }: MessageEvent<VaultReply>) => {
        clearTimeout(timeout);
        if (data.id !== 0) return;
        if (!data.ok) {
          reject(new Error(data.error));
          return;
        }
        channel.port1.onmessage = null;
        channel.port1.addEventListener("message", ({ data: message }: MessageEvent<VaultEvent>) => {
          if (message && "event" in message) iframe.style.display = message.event === "show" ? "block" : "none";
        });
        channel.port1.start();
        resolve(channel.port1);
      };
      iframe.contentWindow?.postMessage({ type: VAULT_HELLO, appId }, origin, [channel.port2]);
    };
    window.addEventListener("message", onReady);
  });
}
