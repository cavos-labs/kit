import type { TypedData } from "starknet";

/** A SNIP-9 v2 outside execution, as the paymaster asks the account to sign. For tests. */
export function outsideExecution(calls: { To: string; Selector: string; Calldata: string[] }[]): TypedData {
  return {
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
    primaryType: "OutsideExecution",
    domain: { name: "Account.execute_from_outside", version: "2", chainId: "SN_SEPOLIA", revision: "1" },
    message: { Caller: "0x414e595f43414c4c4552", Nonce: "0x1", "Execute After": "0x0", "Execute Before": "0xffffffffff", Calls: calls },
  };
}
