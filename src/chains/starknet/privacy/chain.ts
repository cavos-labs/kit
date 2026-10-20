import { RpcProvider, num, shortString } from "starknet";

/** How many blocks a proof's base block must trail the chain head. Matches the pool's acceptance window. */
export const PROOF_BASE_BLOCK_DEPTH = 10;

/** The chain reads a private operation needs. */
export interface PrivacyChain {
  blockNumber(): Promise<number>;
  call(contract: string, entrypoint: string, calldata?: string[]): Promise<string[]>;
  /** Block the transaction landed in, or -1 when it reverted. */
  confirm(transactionHash: string, options: PollOptions): Promise<number>;
}

export interface PollOptions {
  pollIntervalMs: number;
  timeoutMs: number;
}

export const DEFAULT_POLL: PollOptions = { pollIntervalMs: 2_000, timeoutMs: 300_000 };

export function rpcChain(rpcUrl: string): PrivacyChain {
  const provider = new RpcProvider({ nodeUrl: rpcUrl });
  return {
    blockNumber: () => provider.getBlockNumber(),
    call: (contractAddress, entrypoint, calldata = []) => provider.callContract({ contractAddress, entrypoint, calldata }),
    async confirm(transactionHash, { pollIntervalMs, timeoutMs }) {
      const receipt = await provider.waitForTransaction(transactionHash, {
        errorStates: [],
        retryInterval: pollIntervalMs,
        retries: Math.max(1, Math.ceil(timeoutMs / pollIntervalMs)),
      });
      const block = (receipt as unknown as { block_number?: number }).block_number;
      const failed = (receipt as unknown as { isError(): boolean }).isError();
      return failed || block === undefined ? -1 : block;
    },
  };
}

/**
 * Block to prove against: `depth` behind the head, and strictly past
 * `sinceBlock`, the block holding the state the proof must see.
 */
export async function provableBlock(
  chain: PrivacyChain,
  sinceBlock: number,
  poll: PollOptions,
  depth = PROOF_BASE_BLOCK_DEPTH,
): Promise<number> {
  const deadline = Date.now() + poll.timeoutMs;
  for (;;) {
    const head = await chain.blockNumber();
    if (sinceBlock < head - depth) return head - depth;
    if (Date.now() >= deadline) {
      throw new Error(`kit/starknet: block ${sinceBlock} did not become ${depth} blocks old within ${poll.timeoutMs}ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, poll.pollIntervalMs));
  }
}

const SNOS_TAG = BigInt(shortString.encodeShortString("VIRTUAL_SNOS0"));

/** The block a proof was made against, read from its proof facts. Undefined for a layout this does not know. */
export function proofBaseBlock(proofFacts: string[]): number | undefined {
  const facts = proofFacts.map((fact) => num.toBigInt(fact));
  const at = facts.indexOf(SNOS_TAG) + 1;
  if (at === 0 || at >= facts.length) return undefined;
  const block = Number(facts[at]);
  return Number.isSafeInteger(block) && block > 0 ? block : undefined;
}

/** Refuses a proof the sequencer or the pool would reject, before the relay pays to submit it. */
export async function assertProofFresh(
  chain: PrivacyChain,
  pool: string,
  proofFacts: string[],
  depth = PROOF_BASE_BLOCK_DEPTH,
): Promise<void> {
  const base = proofBaseBlock(proofFacts);
  if (base === undefined) return;
  const [head, validity] = await Promise.all([chain.blockNumber(), proofValidityBlocks(chain, pool)]);
  const age = head - base;
  if (age < 0) throw new Error(`kit/starknet: the proof is for block ${base}, ahead of the head ${head}; the RPC node is behind the prover`);
  if (age < depth) throw new Error(`kit/starknet: the proof is only ${age} blocks old and the pool needs ${depth}; prove again`);
  if (validity !== undefined && age > validity) {
    throw new Error(`kit/starknet: the proof is ${age} blocks old and the pool accepts ${validity}; prove again`);
  }
}

async function proofValidityBlocks(chain: PrivacyChain, pool: string): Promise<number | undefined> {
  try {
    const [value] = await chain.call(pool, "get_proof_validity_blocks");
    const blocks = Number(num.toBigInt(value ?? ""));
    return Number.isSafeInteger(blocks) && blocks > 0 ? blocks : undefined;
  } catch {
    return undefined;
  }
}
