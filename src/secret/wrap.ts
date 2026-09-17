import { eciesUnwrapDEK, eciesWrapDEK } from "../chains/stellar/envelope";
import { parseMasterDEK, type MasterDEK } from "./dek";

declare const wrappedDekBrand: unique symbol;

/** ECIES blob. ephPubCompressed(33) || nonce(12) || AES-GCM(DEK). */
export type WrappedDEK = Uint8Array & { readonly [wrappedDekBrand]: "WrappedDEK" };

export function parseWrappedDEK(bytes: Uint8Array): WrappedDEK {
  if (bytes.length < 33 + 12 + 16) {
    throw new Error("kit/secret: WrappedDEK is too short");
  }
  return bytes.slice() as WrappedDEK;
}

export function wrapDekToSec1(dek: MasterDEK, recipientPubSec1: Uint8Array): WrappedDEK {
  return parseWrappedDEK(eciesWrapDEK(dek, recipientPubSec1));
}

export function unwrapDekFromScalar(blob: WrappedDEK, recipientPrivScalar: Uint8Array): MasterDEK {
  return parseMasterDEK(eciesUnwrapDEK(blob, recipientPrivScalar));
}
