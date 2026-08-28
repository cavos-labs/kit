import type { WalletRegistry } from "./WalletRegistry";
import type { DevicePublicKey } from "../signer/DeviceSigner";
import { readCachedAddress, writeCachedAddress, type AddressKey } from "./AddressCache";

export interface ResolvedAddress {
  address: string;
  /**
   * True when the address came from the registry (or from another device that
   * won the race), so this device is not necessarily an authorized signer yet.
   * The chain is still the authority on that — connect verifies on-chain.
   */
  existing: boolean;
}

export interface ResolveAddressParams {
  key: AddressKey;
  registry: WalletRegistry | null;
  /** The device that would name the address if the user has none yet. */
  initialSigner: DevicePublicKey;
  /** Compute this device's candidate address. Called only on a registry miss. */
  compute: () => string;
}

/**
 * cache -> registry -> claim. This is the whole identity model in one function.
 *
 * The address is named by the first device's key, so it cannot be re-derived
 * from a login: with a registry configured, a lookup or claim failure fails the
 * connect rather than silently minting a second wallet for the same user. The
 * cache is the one exception — a device that already knows its address keeps
 * working while Cavos is unreachable.
 *
 * With no registry (`appId` unset) the caller is in local/dev mode and the
 * computed address stands on its own.
 */
export async function resolveAddress(params: ResolveAddressParams): Promise<ResolvedAddress> {
  const { key, registry, compute, initialSigner } = params;

  if (!registry) return { address: compute(), existing: false };

  const cached = await readCachedAddress(key);

  let existing: string | null = null;
  try {
    existing = (await registry.lookup(key.userId))?.address ?? null;
  } catch (e) {
    // Offline with a known address: sign on. Offline without one: we cannot
    // invent an address, because the user may already have one we can't see.
    if (cached) return { address: cached, existing: true };
    throw e;
  }

  if (existing) {
    await writeCachedAddress(key, existing);
    return { address: existing, existing: true };
  }

  const claimed = await registry.register({
    userId: key.userId,
    address: compute(),
    initialSigner,
  });
  await writeCachedAddress(key, claimed.address);
  return { address: claimed.address, existing: claimed.conflict };
}
