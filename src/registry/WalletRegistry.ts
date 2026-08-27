import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * The source of truth for "this user + this app + this chain -> this address".
 *
 * The address is named by the first device's pubkey, so it cannot be derived
 * from identity: connect LOOKS IT UP here first and only computes an address
 * when the user has none yet. Cavos holds this map and nothing else — it cannot
 * spend, and a device that has cached its address can sign without it.
 */
export interface WalletRegistry {
  /** The user's existing wallet, or null if they don't have one yet. */
  lookup(userId: string): Promise<RegisteredWallet | null>;

  /**
   * Claim the address this device computed. Insert-only: if another device got
   * there first, the returned address is THAT one, and this device is not the
   * owner-by-first-write (it needs device approval).
   */
  register(params: {
    userId: string;
    address: string;
    initialSigner: DevicePublicKey;
  }): Promise<RegisterResult>;

  /** Note an additional device signer for the user's wallet (after approval). */
  addDevice?(params: {
    userId: string;
    address: string;
    signer: DevicePublicKey;
  }): Promise<void>;

  /** Drop a device signer after it has been revoked on-chain. */
  removeDevice?(params: {
    userId: string;
    address: string;
    signer: DevicePublicKey;
  }): Promise<void>;
}

export interface RegisterResult {
  /** The address that is now recorded — ours, or the winner's on a conflict. */
  address: string;
  /** True when someone else had already claimed this identity's row. */
  conflict: boolean;
}

export interface RegisteredWallet {
  address: string;
  /** Public keys of the devices registered on this wallet (if tracked). */
  devices?: DevicePublicKey[];
}

/** Simple in-memory registry for demos / tests. */
export class InMemoryWalletRegistry implements WalletRegistry {
  private wallets = new Map<string, RegisteredWallet>();

  async lookup(userId: string): Promise<RegisteredWallet | null> {
    return this.wallets.get(userId) ?? null;
  }
  async register(params: { userId: string; address: string; initialSigner: DevicePublicKey }) {
    const existing = this.wallets.get(params.userId);
    if (existing) return { address: existing.address, conflict: existing.address !== params.address };
    this.wallets.set(params.userId, { address: params.address, devices: [params.initialSigner] });
    return { address: params.address, conflict: false };
  }
  async addDevice(params: { userId: string; address: string; signer: DevicePublicKey }) {
    const w = this.wallets.get(params.userId);
    if (w) w.devices = [...(w.devices ?? []), params.signer];
  }
  async removeDevice(params: { userId: string; address: string; signer: DevicePublicKey }) {
    const w = this.wallets.get(params.userId);
    if (w?.devices) {
      w.devices = w.devices.filter(
        (d) => d.x !== params.signer.x || d.y !== params.signer.y,
      );
    }
  }
}
