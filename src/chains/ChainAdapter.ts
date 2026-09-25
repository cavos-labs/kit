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
 *   await wallet.execute(calls);                          // the account pays
 *   await wallet.execute(calls, { fee: 'sponsored' });    // the app pays
 *   await wallet.execute(calls, { fee: { token: USDC } }); // the user pays, in USDC
 *
 * `fee` answers one question — who pays, and in what — so the three answers are
 * one field rather than several flags that look independent and are not.
 *
 *   - `'self'` (the default on Solana): the account pays from its own balance.
 *   - `'sponsored'`: the Cavos relayer / paymaster pays, so the user signs but
 *     never holds a gas token. On Starknet and Stellar this is the default,
 *     because a fresh account there cannot deploy itself or meet the base
 *     reserve without help.
 *   - `{ token }`: the user pays, in a token they already hold. Solana only.
 *     Toll is the fee payer and settles in that token in the same transaction,
 *     so an account holding no SOL still transacts. Requires a `toll` client.
 */
/** Who pays. Meaningful on every chain. */
export type FeeMode = 'self' | 'sponsored';

/**
 * Solana can also be paid in a token, through Toll. No other chain can, so no
 * other chain's options accept it — a `{ token }` written against Stellar or
 * Starknet fails to compile rather than being quietly ignored, which is what
 * it was doing when `fee` lived in the shared type but only Solana read it.
 */
export type SolanaFeeMode = FeeMode | { token: string };

export interface ExecuteOptions {
  fee?: FeeMode;
  /**
   * @deprecated Use `fee`. `true` is `'sponsored'`, `false` is `'self'`.
   */
  sponsored?: boolean;
}

export interface SolanaExecuteOptions extends Omit<ExecuteOptions, 'fee'> {
  fee?: SolanaFeeMode;
}

/** `fee` wins; `sponsored` is honoured while it is still around. */
export function resolveFeeMode<M extends SolanaFeeMode>(
  opts: { fee?: M; sponsored?: boolean } | undefined,
  fallback: M,
): M {
  if (opts?.fee !== undefined) return opts.fee;
  if (opts?.sponsored !== undefined) return (opts.sponsored ? 'sponsored' : 'self') as M;
  return fallback;
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
