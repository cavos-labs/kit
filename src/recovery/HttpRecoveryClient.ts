import type { DevicePublicKey } from "../signer/DeviceSigner";
import type { RecoveryClient, PendingDeviceRequest } from "./RecoveryClient";

export interface HttpRecoveryClientOptions {
  /** Cavos backend base URL (e.g. https://cavos.xyz). */
  baseUrl: string;
  /** The Cavos App ID — authenticates SDK calls. */
  appId: string;
  /** Optional Cavos console environment. Omitted means production. */
  environment?: "development" | "production";
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

  async requestDeviceAddition(params: {
    userId: string;
    accountAddress: string;
    newSigner: DevicePublicKey;
    email?: string;
    deviceLabel?: string;
  }): Promise<{ requestId: string }> {
    const res = await fetch(new URL("/api/devices/request", this.opts.baseUrl), {
      method: "POST",
      headers: { "Content-Type": "application/json" },
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
      newSigner: { x: fromHex(data.new_pub_x), y: fromHex(data.new_pub_y) },
      createdAt: data.created_at,
      status,
    };
  }

  async confirmDeviceAddition(params: {
    requestId: string;
    txHash: string;
  }): Promise<void> {
    const res = await fetch(
      new URL(`/api/devices/request/${params.requestId}/confirm`, this.opts.baseUrl),
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tx_hash: params.txHash }),
      },
    );
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`confirmDeviceAddition failed: ${res.status} ${t}`);
    }
  }
}
