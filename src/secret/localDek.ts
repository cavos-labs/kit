import type { DeviceUnwrapKey } from "../chains/stellar/DeviceUnwrapKey";
import { WebCryptoDeviceUnwrapKey } from "../chains/stellar/WebCryptoDeviceUnwrapKey";
import { zeroize, type MasterDEK } from "./dek";
import { nativeAddress, parseAppSalt, type Ed25519Chain } from "./derive";
import type { WrapStore } from "./DeviceSecret";
import { deviceFactorFromUnwrapKey } from "./factor";
import { idbWrapStore } from "./idbWrapStore";

export interface LocalDekInput {
  chain: Ed25519Chain;
  userId: string;
  appSalt: string;
  /** The account's address. The DEK is refused unless it derives it. */
  address: string;
  /** The same scope connect used; the vault passes the app id. */
  keyScope?: string;
  store?: WrapStore;
  unwrapKey?: DeviceUnwrapKey;
}

/** Open this device's wrap of the account's DEK. Throws if this device holds none, or holds another account's. */
export async function readLocalDek(input: LocalDekInput): Promise<MasterDEK> {
  const scoped = (id: string) => (input.keyScope ? `${input.keyScope}|${id}` : id);
  const store = input.store ?? idbWrapStore(input.keyScope);
  const wrap = await store.get(input.userId);
  const unwrapKey =
    input.unwrapKey ??
    (await WebCryptoDeviceUnwrapKey.load({ keyId: scoped(`${input.userId}:${input.appSalt}`) }));
  if (!wrap || !unwrapKey) {
    throw new Error("kit/secret: this device does not hold the wallet key. Add the passkey on the device you use to sign.");
  }
  const dek = await deviceFactorFromUnwrapKey(unwrapKey).unwrap(wrap);
  if (nativeAddress(dek, input.chain, parseAppSalt(input.appSalt)) !== input.address) {
    zeroize(dek);
    throw new Error("kit/secret: the key on this device does not open this wallet");
  }
  return dek;
}
