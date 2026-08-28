import type { DevicePublicKey } from "../signer/DeviceSigner";
import type { WalletRegistry, RegisteredWallet, RegisterResult } from "./WalletRegistry";

export interface HttpWalletRegistryOptions {
  /** Cavos backend base URL (e.g. https://cavos.xyz). */
  baseUrl: string;
  /** The Cavos App ID — authenticates the SDK calls (verifyAppId). */
  appId: string;
  /** Optional Cavos console environment. Omitted means production. */
  environment?: "development" | "production";
  /** Network the wallet lives on (e.g. "sepolia"). */
  network: string;
  /**
   * The provider id_token from login (Google / Apple / Cavos). The registry
   * decides who owns an address, so it authenticates the end user, not just the
   * public app id. Read fresh on each call; these tokens expire.
   */
  authToken: () => string | null;
}

/** Serialize a bigint pubkey component for transport (hex string). */
function toHex(n: bigint): string {
  return "0x" + n.toString(16);
}

/** Parse a hex/decimal string back to a bigint pubkey component. */
function fromHex(s: string): bigint {
  return BigInt(s);
}

/**
 * WalletRegistry backed by the Cavos backend (`/api/wallets`) — the persistent,
 * cross-device source of truth for `user_id -> wallet`. The backend stores
 * authorized device signers in `wallet_devices`; the registry maps a backend
 * `userId` (the OAuth `sub`) onto that single wallet row.
 */
export class HttpWalletRegistry implements WalletRegistry {
  constructor(private readonly opts: HttpWalletRegistryOptions) {}

  async lookup(userId: string): Promise<RegisteredWallet | null> {
    const url = new URL("/api/wallets", this.opts.baseUrl);
    url.searchParams.set("app_id", this.opts.appId);
    url.searchParams.set("user_social_id", userId);
    url.searchParams.set("network", this.opts.network);
    if (this.opts.environment) url.searchParams.set("environment", this.opts.environment);

    const res = await fetch(url, { headers: this.headers() });
    if (!res.ok) throw new Error(`registry lookup failed: ${res.status}`);
    const data = await res.json();
    if (!data.found || !data.address) return null;

    const devices: DevicePublicKey[] | undefined = Array.isArray(data.devices)
      ? data.devices.map((d: { pub_x: string; pub_y: string }) => ({
          x: fromHex(d.pub_x),
          y: fromHex(d.pub_y),
        }))
      : undefined;

    return { address: data.address, devices };
  }

  async register(params: {
    userId: string;
    address: string;
    initialSigner: DevicePublicKey;
  }): Promise<RegisterResult> {
    const res = await fetch(new URL("/api/wallets", this.opts.baseUrl), {
      method: "POST",
      headers: this.headers(),
      body: JSON.stringify({
        app_id: this.opts.appId,
        ...(this.opts.environment ? { environment: this.opts.environment } : {}),
        user_social_id: params.userId,
        network: this.opts.network,
        address: params.address,
        // Device-signer wallets send their initial signer (no encrypted blob).
        devices: [{ x: toHex(params.initialSigner.x), y: toHex(params.initialSigner.y) }],
      }),
    });
    // 409: another device claimed this identity's row first. Its address is the
    // real one — adopt it rather than insisting on the one we computed.
    if (res.status === 409) {
      const data = await res.json().catch(() => ({}));
      if (!data.address) throw new Error("registry register conflicted without an address");
      return { address: data.address, conflict: true };
    }
    if (!res.ok) {
      const t = await res.text().catch(() => "");
      throw new Error(`registry register failed: ${res.status} ${t}`);
    }
    return { address: params.address, conflict: false };
  }

  private headers(): Record<string, string> {
    const token = this.opts.authToken();
    return {
      "Content-Type": "application/json",
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    };
  }

  async addDevice?(params: {
    userId: string;
    address: string;
    signer: DevicePublicKey;
  }): Promise<void> {
    // The backend mirrors `wallet_devices` via the confirm endpoint after an
    // on-chain add_signer, so this is a no-op here (kept for interface parity).
    void params;
  }

  async removeDevice?(params: {
    userId: string;
    address: string;
    signer: DevicePublicKey;
  }): Promise<void> {
    // Same as `addDevice`: the removal confirm endpoint deletes the mirrored
    // `wallet_devices` row once the on-chain remove_signer has been submitted.
    void params;
  }
}
