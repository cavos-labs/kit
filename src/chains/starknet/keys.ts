import { CallData, ec, hash } from "starknet";
import { OZ_ACCOUNT_CLASS_HASH } from "./constants";

/** Stark private key (hex, `0x`-prefixed) ground from a 32-byte seed with the standard EIP-2645 rejection sampling. */
export function starkKeyFromSeed(seed: Uint8Array): string {
  return `0x${ec.starkCurve.grindKey(seed)}`;
}

/** Stark public key (hex) of a private key. It is the OZ account's constructor argument and its deploy salt. */
export function starkPublicKey(privateKey: string): string {
  return ec.starkCurve.getStarkKey(privateKey);
}

/** OZ account address, unpadded lowercase hex as `calculateContractAddressFromHash` returns it. The registry stores this exact form. */
export function starknetAddressFromPublicKey(publicKey: string): string {
  return hash.calculateContractAddressFromHash(
    publicKey,
    OZ_ACCOUNT_CLASS_HASH,
    CallData.compile({ publicKey }),
    0,
  );
}

export function starknetAddressFromSeed(seed: Uint8Array): string {
  return starknetAddressFromPublicKey(starkPublicKey(starkKeyFromSeed(seed)));
}
