import type { DevicePublicKey } from "../signer/DeviceSigner";

/**
 * Off-chain map of `user_id -> wallet`. Because the account address is
 * `f(identity, first_device_pubkey)` (unforgeable, secure), it is NOT derivable
 * from the identity alone on a new device. The backend is the source of truth
 * for "does this user already have a wallet?" — enabling multi-device:
 *
 *   - First device, unknown user  -> deploy a new wallet, then `register`.
 *   - Same user, new device        -> `lookup` returns the existing wallet; the
 *                                      new device is added as a signer (recovery
 *                                      approval), NOT a new wallet.
 *
 * The backend implements this (it already manages the user<->address binding).
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
}
