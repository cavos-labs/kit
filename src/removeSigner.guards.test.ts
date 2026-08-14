import { Cavos } from "./Cavos";
import { CavosSolana } from "./chains/solana/CavosSolana";
import type { DevicePublicKey } from "./signer/DeviceSigner";

/**
 * Revocation is the one call whose failure modes are worse than not working:
 * revoking your own key strands the wallet, and calling it from an unauthorized
 * device would burn gas on a guaranteed on-chain revert. Both guards run before
 * anything is submitted, so they are asserted here without a chain.
 *
 * `Object.create` is used because both classes have private constructors —
 * these tests exercise the guard logic, not construction.
 */

const self: DevicePublicKey = { x: 1n, y: 2n };
const other: DevicePublicKey = { x: 3n, y: 4n };

function fakeStarknet(overrides: {
  status: string;
  isAuthorizedSigner?: () => Promise<boolean>;
  execute?: jest.Mock;
}): Cavos {
  const wallet = Object.create(Cavos.prototype) as Cavos & Record<string, unknown>;
  wallet.status = overrides.status;
  wallet.address = "0xacc";
  wallet.devicePubkey = self;
  wallet.adapter = {
    buildRemoveSigner: (account: string, signer: DevicePublicKey) => ({
      contractAddress: account,
      entrypoint: "remove_signer",
      calldata: [String(signer.x), String(signer.y)],
    }),
    isAuthorizedSigner: overrides.isAuthorizedSigner ?? (async () => true),
  };
  wallet.execute = overrides.execute ?? jest.fn(async () => ({ transactionHash: "0xtx" }));
  return wallet as Cavos;
}

function fakeSolana(overrides: {
  status: string;
  isAuthorizedSigner?: () => Promise<boolean>;
  send?: jest.Mock;
}): CavosSolana {
  const wallet = Object.create(CavosSolana.prototype) as CavosSolana & Record<string, unknown>;
  wallet.status = overrides.status;
  wallet.address = "acc";
  wallet.devicePubkey = self;
  wallet.adapter = {
    buildRemoveSigner: async () => ["ix"],
    isAuthorizedSigner: overrides.isAuthorizedSigner ?? (async () => true),
  };
  wallet.send = overrides.send ?? jest.fn(async () => "sig");
  return wallet as CavosSolana;
}

describe("removeSigner guards", () => {
  it("starknet: refuses to revoke the device doing the signing", async () => {
    const execute = jest.fn();
    const wallet = fakeStarknet({ status: "ready", execute });
    await expect(wallet.removeSigner(self)).rejects.toThrow(/cannot revoke the device you are signing with/);
    expect(execute).not.toHaveBeenCalled();
  });

  it("starknet: refuses when this device is not itself an authorized signer", async () => {
    const execute = jest.fn();
    const wallet = fakeStarknet({ status: "needs-device-approval", execute });
    await expect(wallet.removeSigner(other)).rejects.toThrow(/already an authorized signer/);
    expect(execute).not.toHaveBeenCalled();
  });

  it("starknet: refuses when the target is already gone, instead of reverting on-chain", async () => {
    const execute = jest.fn();
    const wallet = fakeStarknet({ status: "ready", execute, isAuthorizedSigner: async () => false });
    await expect(wallet.removeSigner(other)).rejects.toThrow(/not an authorized signer of this wallet/);
    expect(execute).not.toHaveBeenCalled();
  });

  it("starknet: submits remove_signer for a valid target", async () => {
    const execute = jest.fn(async () => ({ transactionHash: "0xtx" }));
    const wallet = fakeStarknet({ status: "ready", execute });
    await expect(wallet.removeSigner(other)).resolves.toEqual({ transactionHash: "0xtx" });
    expect(execute).toHaveBeenCalledWith(
      [{ contractAddress: "0xacc", entrypoint: "remove_signer", calldata: ["3", "4"] }],
      undefined,
    );
  });

  it("solana: applies the same guards", async () => {
    const send = jest.fn(async () => "sig");
    await expect(fakeSolana({ status: "ready", send }).removeSigner(self)).rejects.toThrow(
      /cannot revoke the device you are signing with/,
    );
    await expect(fakeSolana({ status: "needs-device-approval", send }).removeSigner(other)).rejects.toThrow(
      /already an authorized signer/,
    );
    await expect(
      fakeSolana({ status: "ready", send, isAuthorizedSigner: async () => false }).removeSigner(other),
    ).rejects.toThrow(/not an authorized signer of this wallet/);
    expect(send).not.toHaveBeenCalled();

    await expect(fakeSolana({ status: "ready", send }).removeSigner(other)).resolves.toBe("sig");
    expect(send).toHaveBeenCalledWith(["ix"]);
  });
});
