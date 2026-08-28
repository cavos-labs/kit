import { describe, expect, it, beforeEach, afterEach } from "@jest/globals";
import { CavosAuth } from "./CavosAuth";

// The suite runs in Node, where there is no `window`. A map behind the Storage
// interface is enough: what is under test is that the token is written and read
// back across instances, not the browser's implementation of it.
function installSessionStorage() {
  const entries = new Map<string, string>();
  const storage = {
    getItem: (k: string) => entries.get(k) ?? null,
    setItem: (k: string, v: string) => void entries.set(k, v),
    removeItem: (k: string) => void entries.delete(k),
    clear: () => entries.clear(),
  };
  (globalThis as { window?: unknown }).window = { sessionStorage: storage, localStorage: storage };
  return storage;
}

/**
 * The registry authenticates with this token and `resolveAddress` fails closed,
 * so a token that does not outlive a navigation takes every reconnect with it —
 * and a device with no cached address cannot connect at all. Production showed
 * this as 48 unauthenticated `/api/wallets` calls and a login stuck on its
 * spinner.
 */
function tokenFor(sub: string): string {
  const payload = Buffer.from(
    JSON.stringify({ iss: "https://accounts.google.com", sub }),
  ).toString("base64url");
  return `e30.${payload}.sig`;
}

function login(auth: CavosAuth, token: string) {
  return (auth as unknown as {
    identityFromAuthData: (data: string, provider: string) => Promise<unknown>;
  }).identityFromAuthData(JSON.stringify({ jwt: token }), "oauth");
}

describe("the login token survives a reconnect", () => {
  let storage: ReturnType<typeof installSessionStorage>;
  beforeEach(() => {
    storage = installSessionStorage();
  });
  afterEach(() => {
    delete (globalThis as { window?: unknown }).window;
  });

  it("is readable by a new instance in the same tab", async () => {
    const token = tokenFor("u1");
    await login(new CavosAuth({ appId: "app-1" }), token);

    // A reload builds a fresh provider; the token has to still be there.
    expect(new CavosAuth({ appId: "app-1" }).getAuthToken()).toBe(token);
  });

  it("is scoped to the app", async () => {
    await login(new CavosAuth({ appId: "app-1" }), tokenFor("u1"));
    expect(new CavosAuth({ appId: "app-2" }).getAuthToken()).toBeNull();
  });

  it("is dropped on sign-out", async () => {
    const auth = new CavosAuth({ appId: "app-1" });
    await login(auth, tokenFor("u1"));
    auth.clearStoredIdentity();

    expect(auth.getAuthToken()).toBeNull();
    expect(new CavosAuth({ appId: "app-1" }).getAuthToken()).toBeNull();
  });

  it("keeps working when storage is unavailable", async () => {
    // Private mode and blocked site data throw on access. The token then lives
    // in memory only, which is exactly the behaviour this replaced — degraded,
    // not broken.
    storage.setItem = () => {
      throw new Error("blocked");
    };
    storage.getItem = () => {
      throw new Error("blocked");
    };

    const auth = new CavosAuth({ appId: "app-1" });
    const token = tokenFor("u1");
    await login(auth, token);
    expect(auth.getAuthToken()).toBe(token);
  });
});
