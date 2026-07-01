import {
  base64urlEncode,
  webauthnDigest,
  recoverCandidatePublicKeys,
  derToRs,
  batchChallenge,
} from "./webauthn";
import { StarknetAdapter } from "../chains/starknet/StarknetAdapter";
import type { DevicePublicKey } from "../signer/DeviceSigner";

// Real vector from account-contracts/starknet/scripts/gen_webauthn.js — the same
// bytes the Cairo contract's passkey tests accept. Cross-checks that the SDK
// reproduces the exact challenge, digest and recovered approver on-chain.
const approver: DevicePublicKey = {
  x: 0x4742e95e9b8def5cf9c79b6f7ccb7e5d4c7d31ce6c31581cb00c4a6bbea5ca94n,
  y: 0x0345d891c22b5cc6acad2257f4c07c5d40e04a24cc1dc2c2a77d335f89038d7e0n,
};
const newSigner: DevicePublicKey = {
  x: 0x27dc812de9374f35b5ff02901dd3f0225bddad4dafed3f1dfcc068c9e0f5ab7bn,
  y: 0x8ed95e95d913435e93e5ac18196c1eb88df7156b3ed0f3cc7f9095857eb0ffden,
};
const r = 0x0cdfdd690533ff741fa3348797987f8d984d3c574febe2de346ebe5528c7cba1n;
const s = 0x8385e16d9356dac215f66ccfa5332fae04dbbdc2a1d88cbd86de91d4214de753n;
// Batch challenge (single leaf) = sha256(leaf), base64url-encoded.
const CHALLENGE_B64 = "L1yrvSwapYsp9vjq3KZffqwLBhLDZrY8lRN2D8715fc";

const clientDataJSON = new TextEncoder().encode(
  `{"type":"webauthn.get","challenge":"${CHALLENGE_B64}","origin":"https://cavos.xyz","crossOrigin":false}`,
);
const authenticatorData = new Uint8Array([
  0x97, 0xbf, 0xb7, 0x4a, 0xdf, 0xcd, 0x02, 0xd6, 0xfb, 0xaa, 0x66, 0xf3, 0x91, 0x3d, 0x8c, 0x24,
  0x6d, 0x86, 0xff, 0x0f, 0x95, 0x15, 0x9d, 0xe4, 0x91, 0x46, 0x81, 0x04, 0x68, 0x4c, 0x9e, 0x1b,
  0x05, 0x00, 0x00, 0x00, 0x00,
]);

const adapter = new StarknetAdapter({ classHash: "0x1" });

test("adapter leaf + batch challenge match the contract vector (base64url)", () => {
  const leaf = adapter.passkeyLeaf(newSigner, 0n);
  // Single-chain batch challenge = sha256(leaf), which is what the passkey signs.
  expect(base64urlEncode(batchChallenge([leaf]))).toBe(CHALLENGE_B64);
});

test("webauthnDigest + recovery yields the enrolled approver with the right parity", () => {
  const digest = webauthnDigest(authenticatorData, clientDataJSON);
  const candidates = recoverCandidatePublicKeys(r, s, digest);
  const match = candidates.find((c) => c.publicKey.x === approver.x && c.publicKey.y === approver.y);
  expect(match).toBeDefined();
  expect(match!.yParity).toBe(false); // Y_PARITY in the Cairo vector
});

test("derToRs round-trips a DER ECDSA signature", () => {
  // DER SEQUENCE( INTEGER 0x02, INTEGER 0x03 )
  const der = new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03]);
  expect(derToRs(der)).toEqual({ r: 2n, s: 3n });
});
