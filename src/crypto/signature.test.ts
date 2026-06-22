import { signatureToFelts, recoverYParity } from "./signature";
import { u256ToFelts, bigIntTo32Bytes } from "./encoding";
import type { DevicePublicKey } from "../signer/DeviceSigner";

// Same vector the contract is tested against: device key signs sha256(tx_hash).
const PUB: DevicePublicKey = {
  x: 0x9a60dea803efe2c5ac2332f021401b1d344a8381a2727c2a82a5755a207cf0ffn,
  y: 0x523f353cabeaf050e718ed1c296943ce49652d15af2c6d87cab25adf8caf210n,
};
const DIGEST = 0x53b8b0779609e8e8ac1c68e84d1cb9edad424657b5d1c72b86133ecb87f53a4cn; // sha256(tx_hash_be32)
const R = 0x7a284f75aaf1ffe510f65907503cde84bca66e7386672e42c60f027474b41ab3n;
const S = 0xa8615337502fda4c6c294814e7857174d04fdfd77fe60882fdb5b4c4226c6062n;

// The exact felt payload DeviceAccount.__validate__ accepts
// (test_sdk_signature_payload_authorized in account-contracts/starknet).
const EXPECTED_FELTS = [
  0xbca66e7386672e42c60f027474b41ab3n,
  0x7a284f75aaf1ffe510f65907503cde84n,
  0xd04fdfd77fe60882fdb5b4c4226c6062n,
  0xa8615337502fda4c6c294814e7857174n,
  1n,
];

describe("device signature -> contract payload", () => {
  it("recovers the parity bit from (r, s) over the digest", () => {
    expect(recoverYParity(R, S, bigIntTo32Bytes(DIGEST), PUB)).toBe(true);
  });

  it("serializes to the exact 5-felt payload the contract accepts", () => {
    const yParity = recoverYParity(R, S, bigIntTo32Bytes(DIGEST), PUB);
    expect(signatureToFelts({ r: R, s: S, yParity })).toEqual(EXPECTED_FELTS);
  });

  it("u256 split matches the [low, high] felt order", () => {
    expect(u256ToFelts(R)).toEqual([
      0xbca66e7386672e42c60f027474b41ab3n,
      0x7a284f75aaf1ffe510f65907503cde84n,
    ]);
  });
});
