import { ec, num, shortString, type TypedData } from "starknet";
import { Mocknet, MockProofInvocationFactory, MockProofProvider, ContractDiscoveryProvider } from "@starkware-libs/starknet-privacy-sdk/testing";
import * as sdk from "@starkware-libs/starknet-privacy-sdk";
import type { PrivacyChain } from "./chain";
import type { PrivacyFeeMode, StarknetPrivacyConfig } from "./config";
import type { PrivacySessionInit } from "./session";

export const STRK = "0x04718f5a0fc34cc1af16a1cdee98ffb20c31f5cd61d6ab07201858f4287c938d";
export const FORWARDER = "0x75a1";
export const PRIVATE_KEY = "0x1234567890abcdef1234567890abcdef1234567890abcdef";
export const CHAIN_ID = "0x534e5f5345504f4c4941";

export interface MockPrivacyOptions {
  fee?: PrivacyFeeMode;
  feeAmount?: bigint;
  maxFee?: string;
  poolFee?: bigint;
  quotedRecipient?: string;
}

/** The SDK's in-memory pool behind a fake paymaster, so a whole private flow runs without a chain. */
export function mockPrivacy(options: MockPrivacyOptions = {}) {
  const mocknet = new Mocknet({ poolAddress: 0x123n });
  const env = mocknet.initialize();
  const pool = hex(mocknet.poolAddress);
  const ace = hex(BigInt(env.ace));
  const bee = hex(BigInt(env.bee));
  const strk = hex(BigInt(STRK));
  for (const account of [env.alice, env.bob]) mocknet.fundUser(account.address, strk, 10n ** 21n);
  const alice = hex(env.alice.address);
  const bob = hex(env.bob.address);
  const fee: PrivacyFeeMode = options.fee ?? { mode: "sponsored", pool_fee: { paid_by: "sponsor" } };
  const feeAmount = options.feeAmount ?? 0n;
  const built: { method: string; params: any; headers: Record<string, string> }[] = [];
  const executed: { method: string; params: any }[] = [];
  let head = 1000;
  let submissions = 0;

  const config: StarknetPrivacyConfig = {
    pool,
    prover: "https://prover.test",
    discovery: "https://discovery.test",
    relay: {
      url: "https://relay.test",
      fee,
      maxFee: options.maxFee ?? "1000",
      allowedFeeRecipients: [FORWARDER],
    },
  };

  const chain: PrivacyChain = {
    blockNumber: async () => head,
    call: async (_contract, entrypoint, calldata = []) => {
      if (entrypoint === "get_public_key") return [num.toHex(mocknet.pool.get_public_key(BigInt(calldata[0]!)))];
      if (entrypoint === "get_fee_amount") return [num.toHex(options.poolFee ?? 10n ** 18n)];
      throw new Error(`unexpected call ${entrypoint}`);
    },
    confirm: async () => head - 20,
  };

  const relayFetch = (async (_url: string, init?: RequestInit) => {
    const body = JSON.parse(String(init?.body)) as { method: string; params: any };
    const headers = (init?.headers ?? {}) as Record<string, string>;
    const reply = (result: unknown) => ({ ok: true, status: 200, json: async () => ({ result }) }) as Response;
    if (body.method === "paymaster_buildTransaction") {
      built.push({ ...body, headers });
      const requested = body.params.parameters.fee_mode as PrivacyFeeMode;
      const sponsor = requested.mode === "sponsored" && requested.pool_fee.paid_by === "sponsor";
      const token = requested.mode === "default" ? requested.gas_token : requested.pool_fee.paid_by === "user" ? requested.pool_fee.token : ace;
      const calls = body.params.transaction.invoke?.calls as { to: string; selector: string; calldata: string[] }[] | undefined;
      const typed_data: TypedData | undefined = calls && {
        domain: { name: "Account.execute_from_outside", version: "2", chainId: "SN_SEPOLIA", revision: "1" },
        primaryType: "OutsideExecution",
        types: {
          StarknetDomain: [
            { name: "name", type: "shortstring" },
            { name: "version", type: "shortstring" },
            { name: "chainId", type: "shortstring" },
            { name: "revision", type: "shortstring" },
          ],
          OutsideExecution: [
            { name: "Caller", type: "ContractAddress" },
            { name: "Nonce", type: "felt" },
            { name: "Execute After", type: "u128" },
            { name: "Execute Before", type: "u128" },
            { name: "Calls", type: "Call*" },
          ],
          Call: [
            { name: "To", type: "ContractAddress" },
            { name: "Selector", type: "selector" },
            { name: "Calldata", type: "felt*" },
          ],
        },
        message: {
          Caller: FORWARDER,
          Nonce: "0x1",
          "Execute After": "0x1",
          "Execute Before": `0x${(Math.floor(Date.now() / 1000) + 3600).toString(16)}`,
          Calls: calls.map((call) => ({ To: call.to, Selector: call.selector, Calldata: call.calldata })),
        },
      };
      return reply({
        parameters: body.params.parameters,
        fee_action: sponsor
          ? { type: "none" }
          : { type: "withdraw", recipient: options.quotedRecipient ?? FORWARDER, token, amount: num.toHex(feeAmount) },
        ...(typed_data ? { typed_data } : {}),
      });
    }
    executed.push(body);
    mocknet.pool.apply_actions(body.params.transaction.apply_action.apply_actions_call.calldata.map(symbolic));
    submissions += 1;
    return reply({ transaction_hash: `0x${submissions.toString(16)}aa`, tracking_id: `0x${submissions}` });
  }) as unknown as typeof fetch;

  const init: PrivacySessionInit = {
    config,
    chainId: CHAIN_ID,
    rpcUrl: "https://rpc.test",
    account: { address: alice, spend: { privateKey: () => PRIVATE_KEY } },
    paymasterApiKey: () => "key-1",
    deps: {
      chain,
      sdk,
      provingProvider: new MockProofProvider(mocknet.pool),
      discoveryProvider: new ContractDiscoveryProvider(mocknet.pool),
      proofInvocationFactory: new MockProofInvocationFactory(),
      fetch: relayFetch,
      poll: { pollIntervalMs: 1, timeoutMs: 1000 },
    },
  };

  return {
    mocknet,
    env,
    config,
    init,
    pool,
    ace,
    bee,
    strk,
    alice,
    bob,
    built,
    executed,
    setHead: (value: number) => {
      head = value;
    },
    bobInit: {
      ...init,
      account: { address: bob, spend: { privateKey: () => "0x7777777777777777" } },
    } as PrivacySessionInit,
    publicKeyOf: (privateKey: string) => ec.starkCurve.getStarkKey(privateKey),
  };
}

function hex(value: bigint): string {
  return `0x${value.toString(16)}`;
}

function symbolic(felt: string): string {
  try {
    const text = shortString.decodeShortString(felt);
    return /^[A-Z][A-Za-z]{2,}$/.test(text) ? text : felt;
  } catch {
    return felt;
  }
}
