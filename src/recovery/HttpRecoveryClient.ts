import type { DevicePublicKey } from "../signer/DeviceSigner";
import type {
  RecoveryClient,
  PendingDeviceRequest,
  DeviceRemovalRequest,
} from "./RecoveryClient";

export interface HttpRecoveryClientOptions {
  /** Cavos backend base URL (e.g. https://cavos.xyz). */
  baseUrl: string;
  /** The Cavos App ID — authenticates SDK calls. */
  appId: string;
  /** Optional Cavos console environment. Omitted means production. */
  environment?: "development" | "production";
  /**
   * The provider id_token from login. The device routes act on a wallet named
   * by a client-supplied address, so the backend checks the caller owns it.
   * Unrelated to social recovery, whose credential goes only to the enclave.
   */
  authToken?: () => string | null;
}

function toHex(n: bigint): string {
  return "0x" + n.toString(16);
}
function fromHex(s: string): bigint {
  return BigInt(s);
}

function deviceLabel(): string {
  if (typeof navigator !== "undefined") {
    return navigator.userAgent || "a new device";
  }
  return "a new device";
}

/**
 * RecoveryClient backed by the Cavos backend's device-approval relay
 * (`/api/devices/request`). The relay holds NO keys — it stores the pending
 * request, emails the wallet owner, and mirrors the on-chain `add_signer` once a
 * registered device confirms.
 */
export class HttpRecoveryClient implements RecoveryClient {
  constructor(private readonly opts: HttpRecoveryClientOptions) {}

  private headers(): Record<string, string> {
    const token = this.opts.authToken?.() ?? null;
    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  async requestDeviceAddition(params: {
    userId: string;
    accountAddress: string;
    newSigner: DevicePublicKey;
    email?: string;
    deviceLabel?: string;
  }): Promise<{ requestId: string }> {
    const res = await fetch(new URL("/api/devices/request", this.opts.baseUrl), {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        wallet_address: params.accountAddress,
        new_pub_x: toHex(params.newSigner.x),
        new_pub_y: toHex(params.newSigner.y),
        device_label: params.deviceLabel ?? deviceLabel(),
        ...(params.email ? { email: params.email } : {}),
      }),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`requestDeviceAddition failed: ${res.status} ${t}`);
    }
    const data = await res.json();
    return { requestId: data.request_id };
  }

  async getPendingRequest(requestId: string): Promise<PendingDeviceRequest | null> {
    const url = new URL("/api/devices/request", this.opts.baseUrl);
    url.searchParams.set("id", requestId);
    const res = await fetch(url, { headers: { "Content-Type": "application/json" } });
    if (!res.ok) throw new Error(`getPendingRequest failed: ${res.status}`);
    const data = await res.json();
    if (!data.found) return null;

    const status = data.status as PendingDeviceRequest["status"];
    return {
      requestId: data.request_id,
      appId: data.app_id,
      userId: "", // the approving device already knows its own identity
      accountAddress: data.wallet_address,
      network: data.network,
      newSigner: { x: fromHex(data.new_pub_x), y: fromHex(data.new_pub_y) },
      createdAt: data.created_at,
      status,
    };
  }

  async confirmDeviceAddition(params: {
    requestId: string;
    txHash: string;
    email?: string;
  }): Promise<void> {
    const res = await fetch(
      new URL(`/api/devices/request/${params.requestId}/confirm`, this.opts.baseUrl),
      {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({
          tx_hash: params.txHash,
          ...(params.email ? { email: params.email } : {}),
        }),
      },
    );
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`confirmDeviceAddition failed: ${res.status} ${t}`);
    }
  }

  /**
   * Report that a device just became an authorized signer, so the owner gets the
   * "a new device was added" notice with its revocation link. Call this after
   * ANY successful addition — the TEE social-recovery path in particular never
   * goes through the approval relay, so nothing else would report it.
   *
   * Best-effort by contract: the signer is already authorized on-chain by the
   * time this runs, so callers must not fail a recovery because the notice did.
   */
  async notifyDeviceAdded(params: {
    accountAddress: string;
    signer: DevicePublicKey;
    email?: string;
    deviceLabel?: string;
    txHash?: string;
  }): Promise<void> {
    const res = await fetch(new URL('/api/devices/added', this.opts.baseUrl), {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        wallet_address: params.accountAddress,
        pub_x: toHex(params.signer.x),
        pub_y: toHex(params.signer.y),
        device_label: params.deviceLabel ?? deviceLabel(),
        ...(params.email ? { email: params.email } : {}),
        ...(params.txHash ? { tx_hash: params.txHash } : {}),
      }),
    });
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`notifyDeviceAdded failed: ${res.status} ${t}`);
    }
  }

  async getRemovalRequest(requestId: string): Promise<DeviceRemovalRequest | null> {
    const url = new URL(`/api/devices/removal/${requestId}`, this.opts.baseUrl);
    const res = await fetch(url, { headers: { "Content-Type": "application/json" } });
    if (!res.ok) throw new Error(`getRemovalRequest failed: ${res.status}`);
    const data = await res.json();
    if (!data.found) return null;
    return {
      requestId: data.request_id,
      appId: data.app_id,
      accountAddress: data.wallet_address,
      network: data.network,
      appSalt: data.app_salt,
      target: { x: fromHex(data.target_pub_x), y: fromHex(data.target_pub_y) },
      deviceLabel: data.device_label ?? undefined,
      createdAt: data.created_at,
      status: data.status as DeviceRemovalRequest["status"],
    };
  }

  async confirmDeviceRemoval(params: { requestId: string; txHash: string }): Promise<void> {
    const res = await fetch(
      new URL(`/api/devices/removal/${params.requestId}/confirm`, this.opts.baseUrl),
      {
        method: "POST",
        headers: this.headers(),
        body: JSON.stringify({ tx_hash: params.txHash }),
      },
    );
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`confirmDeviceRemoval failed: ${res.status} ${t}`);
    }
  }
}
