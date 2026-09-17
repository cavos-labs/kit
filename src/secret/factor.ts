import type { DeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import { parseMasterDEK } from "./dek";
import { wrapDekToSec1 } from "./wrap";
import type { DeviceFactor } from "./DeviceSecret";

export function deviceFactorFromUnwrapKey(key: DeviceUnwrapKey): DeviceFactor {
  return {
    publicKeySec1: () => key.publicKeySec1(),
    unwrap: async (blob) => parseMasterDEK(await key.unwrap(blob)),
    wrap: (dek) => wrapDekToSec1(dek, key.publicKeySec1()),
  };
}
