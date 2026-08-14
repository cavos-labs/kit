import { HttpRecoveryClient } from "./HttpRecoveryClient";

/**
 * The revocation half of the device relay: reading the request behind the "this
 * wasn't me" email link, and mirroring the on-chain remove_signer afterwards.
 */
describe("HttpRecoveryClient device removal", () => {
  const client = new HttpRecoveryClient({ baseUrl: "https://cavos.xyz", appId: "app-1" });
  const fetchMock = jest.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;
  });

  function ok(body: unknown) {
    return { ok: true, status: 200, json: async () => body, text: async () => "" };
  }

  it("getRemovalRequest parses the request into signer pubkeys", async () => {
    fetchMock.mockResolvedValue(
      ok({
        found: true,
        request_id: "rem-1",
        app_id: "app-1",
        wallet_address: "0xabc",
        network: "sepolia",
        app_salt: "0x99",
        target_pub_x: "0x1",
        target_pub_y: "0x2",
        device_label: "Chrome on Linux",
        status: "available",
        created_at: "2026-08-13T00:00:00Z",
      }),
    );

    const req = await client.getRemovalRequest("rem-1");
    expect(fetchMock.mock.calls[0][0].toString()).toBe("https://cavos.xyz/api/devices/removal/rem-1");
    expect(req).toEqual({
      requestId: "rem-1",
      appId: "app-1",
      accountAddress: "0xabc",
      network: "sepolia",
      appSalt: "0x99",
      target: { x: 1n, y: 2n },
      deviceLabel: "Chrome on Linux",
      createdAt: "2026-08-13T00:00:00Z",
      status: "available",
    });
  });

  it("getRemovalRequest returns null for an unknown link", async () => {
    fetchMock.mockResolvedValue(ok({ found: false }));
    expect(await client.getRemovalRequest("nope")).toBeNull();
  });

  it("confirmDeviceRemoval posts the tx hash to the removal confirm endpoint", async () => {
    fetchMock.mockResolvedValue(ok({ success: true }));
    await client.confirmDeviceRemoval({ requestId: "rem-1", txHash: "0xdead" });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toBe("https://cavos.xyz/api/devices/removal/rem-1/confirm");
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body)).toEqual({ tx_hash: "0xdead" });
  });

  it("confirmDeviceAddition forwards the owner email so the notice can be sent", async () => {
    fetchMock.mockResolvedValue(ok({ success: true }));
    await client.confirmDeviceAddition({ requestId: "add-1", txHash: "0xbeef", email: "a@b.c" });

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ tx_hash: "0xbeef", email: "a@b.c" });
  });

  it("confirmDeviceAddition omits the email key entirely when there is none", async () => {
    fetchMock.mockResolvedValue(ok({ success: true }));
    await client.confirmDeviceAddition({ requestId: "add-1", txHash: "0xbeef" });

    const [, init] = fetchMock.mock.calls[0];
    expect(JSON.parse(init.body)).toEqual({ tx_hash: "0xbeef" });
  });

  it("surfaces a failed removal confirm instead of silently succeeding", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 400, text: async () => "Request expired" });
    await expect(
      client.confirmDeviceRemoval({ requestId: "rem-1", txHash: "0xdead" }),
    ).rejects.toThrow(/400 Request expired/);
  });
});

/**
 * The device-added notice is what closes the loop for flows that authorize a
 * device without the owner approving anything — the TEE recovery path above all.
 */
describe("HttpRecoveryClient.notifyDeviceAdded", () => {
  const client = new HttpRecoveryClient({ baseUrl: "https://cavos.xyz", appId: "app-1" });
  const fetchMock = jest.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    (globalThis as unknown as { fetch: unknown }).fetch = fetchMock;
  });

  it("posts the signer, owner email and tx to the path-agnostic endpoint", async () => {
    fetchMock.mockResolvedValue({ ok: true, status: 200, json: async () => ({ success: true }) });
    await client.notifyDeviceAdded({
      accountAddress: "0xabc",
      signer: { x: 1n, y: 2n },
      email: "a@b.c",
      deviceLabel: "Chrome on Linux",
      txHash: "0xdead",
    });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url.toString()).toBe("https://cavos.xyz/api/devices/added");
    expect(JSON.parse(init.body)).toEqual({
      app_id: "app-1",
      wallet_address: "0xabc",
      pub_x: "0x1",
      pub_y: "0x2",
      device_label: "Chrome on Linux",
      email: "a@b.c",
      tx_hash: "0xdead",
    });
  });

  it("throws on failure so callers can log it (they must not rethrow)", async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 400, text: async () => "Wallet not found" });
    await expect(
      client.notifyDeviceAdded({ accountAddress: "0xabc", signer: { x: 1n, y: 2n } }),
    ).rejects.toThrow(/400 Wallet not found/);
  });
});
