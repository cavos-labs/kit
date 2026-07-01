import { hash, num } from "starknet";
import { sha256 } from "@noble/hashes/sha256";
import type { ChainAdapter, ChainCall, ComputeAddressParams } from "../ChainAdapter";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { signatureToFelts } from "../../crypto/signature";
import { u256ToFelts, bigIntTo32Bytes, bytesToByteArrayCalldata, bytesToBigInt } from "../../crypto/encoding";
import type { PasskeyAssertion } from "../../crypto/webauthn";
import { UDC_ADDRESS } from "./constants";

export interface StarknetAdapterOptions {
  classHash: string;
  /** Read provider for `isAuthorizedSigner`. Optional for build-only usage. */
  provider?: { callContract(call: { contractAddress: string; entrypoint: string; calldata: string[] }): Promise<string[]> };
  /** Signer used to sign outgoing transactions. */
  signer?: DeviceSigner;
}

/** Starknet implementation of the device-signer account adapter. */
export class StarknetAdapter implements ChainAdapter {
  readonly chain = "starknet" as const;

  constructor(private readonly opts: StarknetAdapterOptions) {}

  computeAddress({ addressSeed, initialSigner, salt }: ComputeAddressParams): string {
    return hash.calculateContractAddressFromHash(
      num.toHex(salt ?? addressSeed),
      this.opts.classHash,
      this.constructorCalldata(addressSeed, initialSigner),
      0, // deployerAddress 0 => deterministic counterfactual address
    );
  }

  /** Single UDC deploy; the constructor registers the first device signer, so
   * the account is ready the moment it is deployed (fits the paymaster's
   * deploy + execute_from_outside bundle). */
  buildDeploy(params: ComputeAddressParams): ChainCall[] {
    const salt = params.salt ?? params.addressSeed;
    const calldata = this.constructorCalldata(params.addressSeed, params.initialSigner);
    return [
      {
        contractAddress: UDC_ADDRESS,
        entrypoint: "deployContract",
        calldata: [
          this.opts.classHash,
          num.toHex(salt),
          "0x0", // unique = false -> deployer-independent address
          num.toHex(calldata.length),
          ...calldata,
        ],
      },
    ];
  }

  /** Constructor calldata: [address_seed, pub_x_low, pub_x_high, pub_y_low, pub_y_high]. */
  constructorCalldata(addressSeed: bigint, initialSigner: DevicePublicKey): string[] {
    return [num.toHex(addressSeed), ...pubkeyCalldata(initialSigner)];
  }

  buildAddSigner(accountAddress: string, signer: DevicePublicKey): ChainCall {
    return { contractAddress: accountAddress, entrypoint: "add_signer", calldata: pubkeyCalldata(signer) };
  }

  buildRemoveSigner(accountAddress: string, signer: DevicePublicKey): ChainCall {
    return { contractAddress: accountAddress, entrypoint: "remove_signer", calldata: pubkeyCalldata(signer) };
  }

  async isAuthorizedSigner(accountAddress: string, signer: DevicePublicKey): Promise<boolean> {
    if (!this.opts.provider) throw new Error("kit/starknet: provider required for reads");
    const res = await this.opts.provider.callContract({
      contractAddress: accountAddress,
      entrypoint: "is_authorized_signer",
      calldata: pubkeyCalldata(signer),
    });
    return BigInt(res[0] ?? 0) !== 0n;
  }

  async buildSignature(txHash: bigint): Promise<string[]> {
    if (!this.opts.signer) throw new Error("kit/starknet: signer required to sign");
    const sig = await this.opts.signer.sign(bigIntTo32Bytes(txHash));
    return signatureToFelts(sig).map((f) => num.toHex(f));
  }

  // --- passkey approvers ---

  buildAddApprover(accountAddress: string, passkey: DevicePublicKey): ChainCall {
    return { contractAddress: accountAddress, entrypoint: "add_approver", calldata: pubkeyCalldata(passkey) };
  }

  buildRemoveApprover(accountAddress: string, passkey: DevicePublicKey): ChainCall {
    return { contractAddress: accountAddress, entrypoint: "remove_approver", calldata: pubkeyCalldata(passkey) };
  }

  async isApprover(accountAddress: string, passkey: DevicePublicKey): Promise<boolean> {
    if (!this.opts.provider) throw new Error("kit/starknet: provider required for reads");
    const res = await this.opts.provider.callContract({
      contractAddress: accountAddress,
      entrypoint: "is_approver",
      calldata: pubkeyCalldata(passkey),
    });
    return BigInt(res[0] ?? 0) !== 0n;
  }

  async getPasskeyNonce(accountAddress: string): Promise<bigint> {
    if (!this.opts.provider) throw new Error("kit/starknet: provider required for reads");
    const res = await this.opts.provider.callContract({
      contractAddress: accountAddress,
      entrypoint: "get_passkey_nonce",
      calldata: [],
    });
    return BigInt(res[0] ?? 0);
  }

  /** This chain's leaf for approving `add_signer(newSigner)` at `nonce`:
   * `sha256(new_x || new_y || nonce)` (coords 32B BE, nonce 16B BE). The batch
   * challenge the passkey signs is `sha256(concat(leaves))` across chains. */
  passkeyLeaf(newSigner: DevicePublicKey, nonce: bigint): Uint8Array {
    const msg = new Uint8Array(32 + 32 + 16);
    msg.set(bigIntTo32Bytes(newSigner.x), 0);
    msg.set(bigIntTo32Bytes(newSigner.y), 32);
    msg.set(bigIntTo32Bytes(nonce).subarray(16), 64); // low 16 bytes = u128 BE
    return sha256(msg);
  }

  /** Passkey-authorized `add_signer` call. `leaves`/`leafIndex` place this chain's
   * leaf in the multi-chain batch (single chain → `[leaf]`, index 0). `yParity`
   * matches the raw `(r, s)` — the contract normalizes high-S internally. */
  buildAddSignerViaPasskey(
    accountAddress: string,
    newSigner: DevicePublicKey,
    nonce: bigint,
    leaves: Uint8Array[],
    leafIndex: number,
    assertion: PasskeyAssertion,
    yParity: boolean,
  ): ChainCall {
    const [rl, rh] = u256ToFelts(assertion.r);
    const [sl, sh] = u256ToFelts(assertion.s);
    const leavesCalldata: string[] = [String(leaves.length)];
    for (const leaf of leaves) {
      const [lo, hi] = u256ToFelts(bytesToBigInt(leaf));
      leavesCalldata.push(num.toHex(lo), num.toHex(hi));
    }
    return {
      contractAddress: accountAddress,
      entrypoint: "add_signer_via_passkey",
      calldata: [
        ...pubkeyCalldata(newSigner), // new_x, new_y (u256 pairs)
        num.toHex(nonce),
        ...leavesCalldata, // Array<u256> leaves
        String(leafIndex),
        ...bytesToByteArrayCalldata(assertion.authenticatorData),
        ...bytesToByteArrayCalldata(assertion.clientDataJSON),
        String(assertion.challengeOffset),
        num.toHex(rl), num.toHex(rh),
        num.toHex(sl), num.toHex(sh),
        yParity ? "0x1" : "0x0",
      ],
    };
  }
}

/** Encode a P-256 pubkey as `[x_low, x_high, y_low, y_high]` (two u256s). */
function pubkeyCalldata(pk: DevicePublicKey): string[] {
  const [xl, xh] = u256ToFelts(pk.x);
  const [yl, yh] = u256ToFelts(pk.y);
  return [num.toHex(xl), num.toHex(xh), num.toHex(yl), num.toHex(yh)];
}
