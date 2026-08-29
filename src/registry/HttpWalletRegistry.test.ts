import { afterEach, describe, expect, it, jest } from "@jest/globals";
import { HttpWalletRegistry } from "./HttpWalletRegistry";

function registry(token: string | null = "id-token") {
  return new HttpWalletRegistry({
    baseUrl: "https://cavos.xyz",
    appId: "app-1",
    network: "sepolia",
    authToken: () => token,
  });
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}

afterEach(() => jest.restoreAllMocks());

describe("HttpWalletRegistry", () => {
  it("authenticates the end user, not just the app", async () => {
    const fetchSpy = jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ found: true, address: "0xabc", devices: [] }));

    await registry().lookup("google:u1");

    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer id-token");
  });

  it("does not fetch when this session has no login token", async () => {
    const fetchSpy = jest.spyOn(globalThis, "fetch");

    await expect(registry(null).lookup("google:u1")).rejects.toThrow(
      "registry lookup skipped: no login token",
    );
    expect(fetchSpy).not.toHaveBeenCalled();
  });

  it("returns the winner's address on a 409 instead of throwing", async () => {
    jest
      .spyOn(globalThis, "fetch")
      .mockResolvedValue(jsonResponse({ error: "address_already_registered", address: "0xwinner" }, 409));

    const result = await registry().register({
      userId: "google:u1",
      address: "0xmine",
      initialSigner: { x: 1n, y: 2n },
    });

    expect(result).toEqual({ address: "0xwinner", conflict: true });
  });

  it("throws on an unauthorized lookup rather than reporting no wallet", async () => {
    jest.spyOn(globalThis, "fetch").mockResolvedValue(jsonResponse({ error: "Invalid user token" }, 401));

    await expect(registry().lookup("google:u1")).rejects.toThrow(
      /registry lookup failed: 401.*Invalid user token/,
    );
  });
});
