import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * Off-chain wallet registry used for recovery metadata, analytics, and legacy
 * lookup-based recovery APIs. Normal chain connections derive their address
 * from `identity + appSalt` and verify deployment/authorization on-chain; a
 * registry row must never override that deterministic address.
 */
export interface WalletRegistry {
  /** The user's existing wallet, or null if they don't have one yet. */
  lookup(userId: string): Promise<RegisteredWallet | null>;

  /** Record a freshly deployed wallet for the user (first device). */
  register(params: {
    userId: string;
    address: string;
    initialSigner: DevicePublicKey;
  }): Promise<void>;

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
    this.wallets.set(params.userId, { address: params.address, devices: [params.initialSigner] });
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
