import { WebCryptoControlKey } from "../chains/stellar/WebCryptoControlKey";
import { WebCryptoDeviceUnwrapKey } from "../chains/stellar/WebCryptoDeviceUnwrapKey";
import { idbWrapStore } from "./idbWrapStore";

export interface EraseLocalAccountInput {
  userId: string;
  appSalt: string;
  /** The same scope connect used; the vault passes the app id. */
  keyScope?: string;
}

/** Removes this browser's copy of an account: its wrap, its device unwrap key and its stored control keys. */
export async function eraseLocalAccount(input: EraseLocalAccountInput): Promise<void> {
  const scoped = (id: string) => (input.keyScope ? `${input.keyScope}|${id}` : id);
  await idbWrapStore(input.keyScope).clear(input.userId);
  await WebCryptoDeviceUnwrapKey.remove(scoped(`${input.userId}:${input.appSalt}`));
  for (const chain of ["solana", "stellar"]) {
    await WebCryptoControlKey.remove(scoped(`${chain}:${input.userId}:${input.appSalt}`));
  }
}
