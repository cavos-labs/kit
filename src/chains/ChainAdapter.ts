/** A chain-native contract call (Starknet `Call`-shaped; generic for portability). */
export interface ChainCall {
  contractAddress: string;
  entrypoint: string;
  calldata: string[];
}

/**
 * Options for state-changing wallet calls (`execute`, `upgrade`, etc.).
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
