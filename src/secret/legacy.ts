import { WebCryptoControlKey } from "../chains/stellar/WebCryptoControlKey";
import { WebCryptoDeviceUnwrapKey } from "../chains/stellar/WebCryptoDeviceUnwrapKey";
import { parseMasterDEK, zeroize } from "./dek";
import { PublicKey } from "@solana/web3.js";
import { StrKey } from "@stellar/stellar-sdk";
import { nativeAddress, parseAppSalt, type Ed25519Chain } from "./derive";
import { idbWrapStore } from "./idbWrapStore";

/**
 * Before the vault, the kit kept the spend key, the device unwrap key and the
 * wrapped DEK in the app's own storage, where any script on the page can use
 * them. Once the vault holds the same account, those copies are only risk.
 * Each is deleted only when it provably opens the address the vault returned;
 * a copy for any other address may be the only way into funds, so it stays.
 */
export async function dropLegacyCopies(
  chain: Ed25519Chain,
  userId: string,
  appSalt: string,
  vaultAddress: string,
): Promise<void> {
  if (typeof indexedDB === "undefined") return;

  const keyId = `${chain}:${userId}:${appSalt}`;
  const control = await WebCryptoControlKey.load({ keyId });
  if (control && addressOf(chain, control.publicKeyRaw()) === vaultAddress) {
    await WebCryptoControlKey.remove(keyId);
  }

  const unwrapKeyId = `${userId}:${appSalt}`;
  const unwrap = await WebCryptoDeviceUnwrapKey.load({ keyId: unwrapKeyId });
  const store = idbWrapStore();
  const wrap = await store.get(userId);
  if (!unwrap || !wrap) return;
  const dek = parseMasterDEK(await unwrap.unwrap(wrap));
  try {
    if (nativeAddress(dek, chain, parseAppSalt(appSalt)) !== vaultAddress) return;
  } finally {
    zeroize(dek);
  }
  await WebCryptoDeviceUnwrapKey.remove(unwrapKeyId);
  await store.clear(userId);
}

function addressOf(chain: Ed25519Chain, publicKey: Uint8Array): string {
  return chain === "solana" ? new PublicKey(publicKey).toBase58() : StrKey.encodeEd25519PublicKey(Buffer.from(publicKey));
}
