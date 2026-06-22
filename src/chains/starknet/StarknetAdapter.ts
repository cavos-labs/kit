import { hash, num } from "starknet";
import type { ChainAdapter, ChainCall, ComputeAddressParams } from "../ChainAdapter";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { signatureToFelts } from "../../crypto/signature";
import { u256ToFelts, bigIntTo32Bytes } from "../../crypto/encoding";
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
}

/** Encode a P-256 pubkey as `[x_low, x_high, y_low, y_high]` (two u256s). */
function pubkeyCalldata(pk: DevicePublicKey): string[] {
  const [xl, xh] = u256ToFelts(pk.x);
  const [yl, yh] = u256ToFelts(pk.y);
  return [num.toHex(xl), num.toHex(xh), num.toHex(yl), num.toHex(yh)];
}
