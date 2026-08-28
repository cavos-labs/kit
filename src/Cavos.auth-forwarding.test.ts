import { describe, expect, it, jest, afterEach } from "@jest/globals";
import { Cavos } from "./Cavos";
import { CavosSolana } from "./chains/solana/CavosSolana";
import { CavosStellar } from "./chains/stellar/CavosStellar";
import type { AuthProvider } from "./auth/AuthProvider";

/**
 * The registry authenticates the END USER, so the login token has to reach the
 * chain connector that builds it. `Cavos.connect` forwarded identity but not
 * `auth`, which left every registry call unauthenticated and 401'd all three
 * chains against a backend that enforces it.
 */
describe("Cavos.connect forwards the auth provider", () => {
  const identity = { userId: "google:u1" };
  const auth: AuthProvider = {
    authenticate: async () => identity,
    getAuthToken: () => "id-token",
  };

  afterEach(() => jest.restoreAllMocks());

  it("hands the auth provider to the Solana connector", async () => {
    const spy = jest
      .spyOn(CavosSolana, "connect")
      .mockResolvedValue({} as never);

    await Cavos.connect({
      chain: "solana",
      network: "testnet",
      identity,
      auth,
      appSalt: "salt",
      appId: "app-1",
    });

    expect(spy.mock.calls[0][0].auth).toBe(auth);
  });

  it("hands the auth provider to the Stellar connector", async () => {
    const spy = jest
      .spyOn(CavosStellar, "connect")
      .mockResolvedValue({} as never);

    await Cavos.connect({
      chain: "stellar",
      network: "testnet",
      identity,
      auth,
      appSalt: "salt",
      appId: "app-1",
      stellarDeviceKey: {
        slotId: () => "slot",
        publicKeySec1: () => new Uint8Array(65),
        unwrap: async () => new Uint8Array(32),
      } as never,
    });

    expect(spy.mock.calls[0][0].auth).toBe(auth);
  });
});
