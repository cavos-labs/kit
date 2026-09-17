import type { WalletRegistry } from "../registry/WalletRegistry";
import type { AddressIndex } from "./DeviceSecret";

const PLACEHOLDER_SIGNER = { x: 0n, y: 0n };

export function addressIndexFromRegistry(registry: WalletRegistry): AddressIndex {
  return {
    async lookup(userId) {
      const row = await registry.lookup(userId);
      return row?.address ?? null;
    },
    async claim(userId, _chain, address) {
      const result = await registry.register({
        userId,
        address,
        initialSigner: PLACEHOLDER_SIGNER,
      });
      return { address: result.address, existing: result.conflict };
    },
  };
}
