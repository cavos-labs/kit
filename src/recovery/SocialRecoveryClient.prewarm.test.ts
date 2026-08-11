import { SocialRecoveryClient } from "./SocialRecoveryClient";

const ATTESTATION = {
  audience: "https://example.com/attestation",
  imageDigest: "sha256:test",
  projectNumber: "123",
  serviceAccount: "worker@example.iam.gserviceaccount.com",
};

describe("SocialRecoveryClient prewarm", () => {
  const originalFetch = global.fetch;

  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("reuses one prewarm and claims it on the first session only", async () => {
    const requests: Array<{ url: string; body: any }> = [];
    global.fetch = jest.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      requests.push({ url, body: init?.body ? JSON.parse(String(init.body)) : undefined });
      if (url.endsWith("/api/recovery/social/prewarm")) {
        return new Response(
          JSON.stringify({
            prewarm_id: "11111111-1111-4111-8111-111111111111",
            claim_token: "claim-token",
            expires_at: new Date(Date.now() + 60_000).toISOString(),
          }),
          { status: 202, headers: { "content-type": "application/json" } },
        );
      }
      return new Response(
        JSON.stringify({
          session_id: "11111111-1111-4111-8111-111111111111",
          provider: "google",
          policy: {},
          delay_seconds: 0,
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const client = new SocialRecoveryClient({
      baseUrl: "https://cavos.example",
      appId: "app",
      environment: "development",
      attestation: ATTESTATION,
    });
    const first = await client.prewarm();
    expect(await client.prewarm()).toBe(first);

    await (client as any).start("0xabc", "recover", "fingerprint");
    await (client as any).start("0xabc", "recover", "fingerprint-2");

    expect(requests).toHaveLength(3);
    expect(requests[1].body).toMatchObject({
      prewarm_id: first.prewarmId,
      prewarm_token: first.claimToken,
    });
    expect(requests[2].body).not.toHaveProperty("prewarm_id");
    expect(requests[2].body).not.toHaveProperty("prewarm_token");
  });

  it("does not submit an expired prewarm capability", async () => {
    let body: any;
    global.fetch = jest.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      body = JSON.parse(String(init?.body));
      return new Response(
        JSON.stringify({
          session_id: "new-session",
          provider: "google",
          policy: {},
          delay_seconds: 0,
        }),
        { status: 202, headers: { "content-type": "application/json" } },
      );
    }) as typeof fetch;

    const client = new SocialRecoveryClient({
      baseUrl: "https://cavos.example",
      appId: "app",
      attestation: ATTESTATION,
      prewarm: {
        prewarmId: "expired",
        claimToken: "expired-token",
        expiresAt: new Date(Date.now() - 1_000).toISOString(),
      },
    });
    await (client as any).start("0xabc", "recover", "fingerprint");
    expect(body).not.toHaveProperty("prewarm_id");
  });
});
