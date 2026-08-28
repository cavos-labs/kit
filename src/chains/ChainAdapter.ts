import type { DevicePublicKey } from "../signer/DeviceSigner";

/** A chain-native contract call (Starknet `Call`-shaped; generic for portability). */
export interface ChainCall {
  contractAddress: string;
  entrypoint: string;
  calldata: string[];
}

/**
 * Options for state-changing wallet calls (`execute`, `addSigner`, etc.).
 *
 *   await wallet.execute(calls, { sponsored: false }); // self-funded
 *
 * `sponsored` defaults to `true`: the Cavos relayer / paymaster pays gas (and, on
 * Stellar, the reserve) so the user signs but never holds gas tokens. Pass
 * `sponsored: false` to submit directly — the account pays its own fee / reserve
 * from its own balance (ETH on Starknet, SOL on Solana, XLM on Stellar). Useful
 * for testing the device signature, for fee transparency, or as a fallback when
 * the relayer is unreachable. Self-funded mode requires the account to actually
 * hold enough native balance for the fee (and Stellar reserve, if the call adds
 * subentries).
 */
export interface ExecuteOptions {
  sponsored?: boolean;
}

export interface ComputeAddressParams {
  /** 32-byte app namespace (see `appNamespace` in identity.ts). */
  namespace: Uint8Array;
  /**
   * The first device signer. It NAMES the address on every chain, so it is
   * required: without the key there is no address to compute.
   */
  initialSigner: DevicePublicKey;
}

/**
 * Per-chain implementation surface. Phase 1 ships only Starknet, but the kit is
 * designed so Stellar and Solana adapters drop in behind the same interface.
 */
export interface ChainAdapter {
  readonly chain: "starknet" | "stellar" | "solana";

  /**
   * The address this device would claim if the user has none yet:
   * `f(app namespace, first device pubkey)`. Only ever used on a registry miss
   * — a user with an existing wallet gets their address from the registry.
   */
  computeAddress(params: ComputeAddressParams): string;

  /** Call(s) to deploy the account with its first device signer (UDC). */
  buildDeploy(params: ComputeAddressParams): ChainCall[];

  buildAddSigner(accountAddress: string, signer: DevicePublicKey): ChainCall;
  buildRemoveSigner(accountAddress: string, signer: DevicePublicKey): ChainCall;

  /** Read whether a pubkey is a currently-authorized signer of the account. */
  isAuthorizedSigner(accountAddress: string, signer: DevicePublicKey): Promise<boolean>;

  /**
   * Compute the signature payload for an outgoing transaction: given the chain's
   * tx hash, obtain a device assertion and serialize it to the chain's expected
   * signature encoding.
   */
  buildSignature(txHash: bigint): Promise<string[]>;
}
