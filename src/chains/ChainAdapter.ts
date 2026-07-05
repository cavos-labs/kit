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
  addressSeed: bigint;
  /**
   * First device signer. Required by chains whose address derivation still
   * includes the device pubkey (Solana PDA seeds, Stellar factory salt). The
   * Starknet adapter IGNORES this — its address is `f(addressSeed)` only.
   */
  initialSigner?: DevicePublicKey;
  /** Defaults to `addressSeed` when omitted. */
  salt?: bigint;
}

/**
 * Per-chain implementation surface. Phase 1 ships only Starknet, but the kit is
 * designed so Stellar and Solana adapters drop in behind the same interface.
 */
export interface ChainAdapter {
  readonly chain: "starknet" | "stellar" | "solana";

  /**
   * Deterministic account address. Starknet: `f(addressSeed)` only (device
   * pubkey not in the derivation — recovery is self-custodial). Solana: also
   * `f(addressSeed)` (PDA seeds use only the seed). Stellar: classic `G…`
   * multisig where the address is the source account.
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
