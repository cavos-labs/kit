import "fake-indexeddb/auto";
import { everyoneSignedIn } from "./fixtures";
import { NO_IDENTITY } from "./identity";
import { createVaultHandler, serveVault } from "./host";
import { memoryLedger } from "./ledger";
import { STRICT_POLICY } from "./limits";
import { VaultClient, vaultLoginHost } from "./VaultClient";
import { WebCryptoLoginKey } from "../auth/loginKey";
import { loginNonceOf, pkceChallenge } from "../auth/loginBinding";
import { CavosAuth } from "../auth/CavosAuth";

const APP_ID = "0f9d5a1c-3b2e-4c5a-8d7f-1a2b3c4d5e6f";

function vault() {
  const handle = createVaultHandler({
    appId: APP_ID,
    backendUrl: "https://cavos.test",
    policy: STRICT_POLICY,
    identity: NO_IDENTITY,
    sessions: everyoneSignedIn,
    ledger: memoryLedger(),
    confirm: async () => true,
    consent: async () => true,
    passkey: () => ({
      enroll: async () => ({ credentialId: new Uint8Array(16), secret: new Uint8Array(32) }),
      getSecret: async () => new Uint8Array(32),
    }),
  });
  const channel = new MessageChannel();
  serveVault(channel.port2, handle);
  const client = VaultClient.fromPort(channel.port1);
  const close = () => {
    channel.port1.close();
    channel.port2.close();
  };
  return { client, close };
}

describe("login in the vault", () => {
  afterEach(() => WebCryptoLoginKey.remove(APP_ID));

  it("makes the key in the vault and returns only the nonce and the PKCE challenge", async () => {
    const { client, close } = vault();
    const started = await client.loginStart();
    const key = await WebCryptoLoginKey.load(APP_ID);
    expect(Object.keys(started).sort()).toEqual(["codeChallenge", "nonce"]);
    expect(started.nonce).toBe(loginNonceOf(key!.publicKeyRaw()));
    expect(started.codeChallenge).toBe(pkceChallenge(key!.codeVerifier));
    close();
  });

  it("replaces the key at every login and deletes it on loginEnd", async () => {
    const { client, close } = vault();
    const first = await client.loginStart();
    const second = await client.loginStart();
    expect(second.nonce).not.toBe(first.nonce);
    await client.loginEnd();
    await expect(WebCryptoLoginKey.load(APP_ID)).resolves.toBeNull();
    close();
  });

  it("refuses to verify when no login was started", async () => {
    const { client, close } = vault();
    await expect(client.loginVerify({ provider: "github", grant: "g" })).rejects.toThrow("no sign-in in progress");
    close();
  });

  it("serves CavosAuth through vaultLoginHost over the vault port", async () => {
    const { client, close } = vault();
    const attach = jest.spyOn(VaultClient, "attach").mockReturnValue(client);
    const host = vaultLoginHost({ appId: APP_ID });
    const auth = new CavosAuth({ appId: APP_ID, backendUrl: "https://cavos.test", login: host });
    const realFetch = globalThis.fetch;
    let sent = "";
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      sent = String(input);
      return { ok: true, json: async () => ({ url: "https://provider.test/authorize" }) } as Response;
    }) as typeof fetch;
    (globalThis as { window?: unknown }).window = {};
    try {
      await auth.getGoogleOAuthUrl("https://app.test/callback");
    } finally {
      globalThis.fetch = realFetch;
      delete (globalThis as { window?: unknown }).window;
      attach.mockRestore();
    }
    const key = await WebCryptoLoginKey.load(APP_ID);
    expect(new URL(sent).searchParams.get("nonce")).toBe(loginNonceOf(key!.publicKeyRaw()));
    close();
  });
});
