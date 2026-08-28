import type { DeviceApproval } from "./deviceAuthorization";

/**
 * Why passkey approval is a single-chain choice.
 *
 * The enclave mints an authority per wallet, so one login covers every chain
 * and there is nothing to keep in step. A passkey is one credential that has to
 * be registered on each chain separately, and keeping it in step across
 * accounts that are created at different times is where all the machinery came
 * from -- recovering candidate keys, finding a chain to check them against,
 * deciding which account to create and when.
 *
 * None of it was the real problem. A multichain app on passkeys has chains
 * where a new device cannot be authorized at all: not degraded, stuck. Better
 * to refuse the combination here, in the integrator's console on the first
 * render, than to discover it as a user who cannot sign.
 */
export function assertDeviceApprovalScope(
  approval: DeviceApproval,
  chains: readonly string[],
): void {
  if (approval !== "passkey" || chains.length <= 1) return;
  throw new Error(
    `kit: deviceApproval: 'passkey' supports one chain, and this app configures ${chains.length} ` +
      `(${chains.join(", ")}). A passkey is registered per chain, so on the others a new device ` +
      "could never be authorized. Use deviceApproval: 'enclave' for a multichain app, or configure " +
      "a single chain.",
  );
}
