import { describe, expect, it, jest } from "@jest/globals";
import { PublicKey } from "@solana/web3.js";
import { SolanaAdapter } from "./SolanaAdapter";

/**
 * An address the program has not created can still exist: funded by an airdrop
 * or a transfer, it is a system account holding lamports and no data. The
 * readers took existence as proof of the layout and read past the end of it, so
 * connect died on "Trying to access beyond buffer length" and the session never
 * came back -- for a wallet whose only sin was having been sent some SOL.
 */
describe("reading an account that is not one of ours", () => {
  const address = "5UCmo53f4xxkUYvGvucmVwfcTZ4ehEHoLowR2wpz89Th";
  const device = { x: 1n, y: 2n };

  const adapterOver = (data: Buffer | null) => {
    const adapter = new SolanaAdapter({ network: "devnet" });
    const getAccountInfo = jest.fn(async () => (data ? { data } : null));
    jest
      .spyOn(adapter as unknown as { requireConnection: () => unknown }, "requireConnection")
      .mockReturnValue({ getAccountInfo });
    return adapter;
  };

  it("does not explode on a funded account with no data", async () => {
    const adapter = adapterOver(Buffer.alloc(0));
    await expect(adapter.isAuthorizedSigner(address, device)).resolves.toBe(false);
  });

  it("does not explode on data too short to hold the layout", async () => {
    // Truncated is the same as absent: it cannot be a device account.
    const adapter = adapterOver(Buffer.alloc(60));
    await expect(adapter.isAuthorizedSigner(address, device)).resolves.toBe(false);
  });

  it("still reports no signer when the account is absent", async () => {
    const adapter = adapterOver(null);
    await expect(adapter.isAuthorizedSigner(address, device)).resolves.toBe(false);
  });

  it("reads an account that does hold the layout", async () => {
    // Header, then a zero-length signer vector: a real account, no signers.
    const data = Buffer.alloc(8 + 32 + 1 + 8 + 33 + 4);
    const adapter = adapterOver(data);
    await expect(adapter.isAuthorizedSigner(address, device)).resolves.toBe(false);
    expect(new PublicKey(address).toBase58()).toBe(address);
  });
});

/**
 * The status the wallet reports rests on the same question, and got it wrong in
 * the same way: an address holding lamports was read as a deployed wallet, so
 * the device that created it was told it was not a signer of it.
 */
describe("deciding whether the program created the account", () => {
  const address = "5UCmo53f4xxkUYvGvucmVwfcTZ4ehEHoLowR2wpz89Th";

  const adapterOver = (data: Buffer | null) => {
    const adapter = new SolanaAdapter({ network: "devnet" });
    const getAccountInfo = jest.fn(async () => (data ? { data } : null));
    jest
      .spyOn(adapter as unknown as { requireConnection: () => unknown }, "requireConnection")
      .mockReturnValue({ getAccountInfo });
    return adapter;
  };

  it("does not call a funded address a wallet", async () => {
    await expect(adapterOver(Buffer.alloc(0)).isDeviceAccount(address)).resolves.toBe(false);
  });

  it("does not call a missing address a wallet", async () => {
    await expect(adapterOver(null).isDeviceAccount(address)).resolves.toBe(false);
  });

  it("recognises an account the program created", async () => {
    const data = Buffer.alloc(8 + 32 + 1 + 8 + 33 + 4);
    await expect(adapterOver(data).isDeviceAccount(address)).resolves.toBe(true);
  });
});
