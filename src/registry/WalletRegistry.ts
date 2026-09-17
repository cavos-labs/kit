import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * First-write claim of a derived address. Native Ed25519 addresses come from
 * the MasterDEK, not from this map. Cavos records the claim for billing and
 * so two first devices cannot publish two different accounts for one login.
 */
export interface WalletRegistry {
  /** The user's existing wallet, or null if they don't have one yet. */
  lookup(userId: string): Promise<RegisteredWallet | null>;

  /**
   * Claim the address this device derived. Insert-only: if another device got
   * there first, the returned address is THAT one.
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
