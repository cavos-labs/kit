import { Address, Keypair, StrKey, scValToNative, xdr } from "@stellar/stellar-sdk";
import { TrustlessWorkEscrow } from "./trustlesswork";
import type { CavosStellar } from "../chains/stellar/CavosStellar";

/**
 * Verifies the Trustless Work escrow wrapper maps each method to the right
 * contract entrypoint and argument order, passing THIS account's address as the
 * `require_auth` role argument. We stub `invokeContract` and inspect the call.
 */

const ACCOUNT = Keypair.random().publicKey();
const CONTRACT_ID = StrKey.encodeContract(Buffer.alloc(32, 2));

function makeEscrow() {
  const calls: { method: string; args: xdr.ScVal[] }[] = [];
  const wallet = {
    address: ACCOUNT,
    invokeContract: jest.fn(async (p: { method: string; args?: xdr.ScVal[] }) => {
      calls.push({ method: p.method, args: p.args ?? [] });
      return "hash";
    }),
  } as unknown as CavosStellar;
  return { escrow: new TrustlessWorkEscrow(wallet, CONTRACT_ID), calls };
}

describe("TrustlessWorkEscrow", () => {
  it("approveMilestone → approve_milestone(index, approver=self)", async () => {
    const { escrow, calls } = makeEscrow();
    await escrow.approveMilestone(2);
    expect(calls[0].method).toBe("approve_milestone");
    expect(scValToNative(calls[0].args[0])).toBe(2);
    expect(Address.fromScVal(calls[0].args[1]).toString()).toBe(ACCOUNT);
  });

  it("changeMilestoneStatus encodes optional evidence as void when omitted", async () => {
    const { escrow, calls } = makeEscrow();
    await escrow.changeMilestoneStatus(0, "in-progress");
    expect(calls[0].method).toBe("change_milestone_status");
    expect(scValToNative(calls[0].args[1])).toBe("in-progress");
    expect(calls[0].args[2].switch().name).toBe("scvVoid");
    expect(Address.fromScVal(calls[0].args[3]).toString()).toBe(ACCOUNT);
  });

  it("releaseFunds → release_funds(self, trustless_work_address)", async () => {
    const { escrow, calls } = makeEscrow();
    const tw = Keypair.random().publicKey();
    await escrow.releaseFunds(tw);
    expect(calls[0].method).toBe("release_funds");
    expect(Address.fromScVal(calls[0].args[0]).toString()).toBe(ACCOUNT);
    expect(Address.fromScVal(calls[0].args[1]).toString()).toBe(tw);
  });

  it("disputeEscrow → dispute_escrow(self)", async () => {
    const { escrow, calls } = makeEscrow();
    await escrow.disputeEscrow();
    expect(calls[0].method).toBe("dispute_escrow");
    expect(Address.fromScVal(calls[0].args[0]).toString()).toBe(ACCOUNT);
  });

  it("resolveDispute encodes distributions as a Map<Address,i128>", async () => {
    const { escrow, calls } = makeEscrow();
    const tw = Keypair.random().publicKey();
    const winner = Keypair.random().publicKey();
    await escrow.resolveDispute(tw, { [winner]: 1000n });
    expect(calls[0].method).toBe("resolve_dispute");
    const map = calls[0].args[2];
    expect(map.switch().name).toBe("scvMap");
    const entry = map.map()![0];
    expect(Address.fromScVal(entry.key()).toString()).toBe(winner);
    expect(scValToNative(entry.val())).toBe(1000n);
  });
});
