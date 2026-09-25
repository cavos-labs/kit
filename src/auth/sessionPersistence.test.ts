import { describe, expect, it, beforeEach, afterEach } from "@jest/globals";
import { CavosAuth } from "./CavosAuth";

// The suite runs in Node, where there is no `window`. Two separate maps behind
// the Storage interface, because what is under test is which one is written.
function memoryStorage() {
  const entries = new Map<string, string>();
  return {
    entries,
    getItem: (k: string) => entries.get(k) ?? null,
    setItem: (k: string, v: string) => void entries.set(k, v),
    removeItem: (k: string) => void entries.delete(k),
    clear: () => entries.clear(),
  };
}

const IDENTITY_KEY = "cavos-kit:identity:app-1";

function tokenFor(sub: string): string {
  const payload = Buffer.from(
    JSON.stringify({ iss: "https://accounts.google.com", sub }),
  ).toString("base64url");
  return `e30.${payload}.sig`;
}

function login(auth: CavosAuth, sub = "u1") {
  return (auth as unknown as {
    identityFromAuthData: (data: string, provider: string) => Promise<unknown>;
  }).identityFromAuthData(JSON.stringify({ jwt: tokenFor(sub) }), "oauth");
}

describe("persistSession", () => {
  let local: ReturnType<typeof memoryStorage>;
  let session: ReturnType<typeof memoryStorage>;
  beforeEach(() => {
    local = memoryStorage();
    session = memoryStorage();
    (globalThis as { window?: unknown }).window = { localStorage: local, sessionStorage: session };
  });
  afterEach(() => {
    delete (globalThis as { window?: unknown }).window;
  });

  it("false keeps the identity in sessionStorage, not localStorage", async () => {
    await login(new CavosAuth({ appId: "app-1", persistSession: false }));

    expect(session.entries.has(IDENTITY_KEY)).toBe(true);
    expect(local.entries.has(IDENTITY_KEY)).toBe(false);
    // A reload in the same tab still restores it.
    expect(new CavosAuth({ appId: "app-1", persistSession: false }).restoreIdentity()?.userId).toBeDefined();
  });

  it("false removes an identity saved earlier in localStorage and does not restore it", async () => {
    await login(new CavosAuth({ appId: "app-1" }));
    expect(local.entries.has(IDENTITY_KEY)).toBe(true);

    const auth = new CavosAuth({ appId: "app-1", persistSession: false });

    expect(local.entries.has(IDENTITY_KEY)).toBe(false);
    expect(auth.restoreIdentity()).toBeNull();
  });

  it("defaults to localStorage, as before", async () => {
    await login(new CavosAuth({ appId: "app-1" }));

    expect(local.entries.has(IDENTITY_KEY)).toBe(true);
    expect(session.entries.has(IDENTITY_KEY)).toBe(false);
    expect(new CavosAuth({ appId: "app-1" }).restoreIdentity()?.userId).toBeDefined();
  });

  it.each([
    ["localStorage", undefined],
    ["sessionStorage", false],
  ] as const)("clearStoredIdentity clears %s", async (_, persistSession) => {
    const auth = new CavosAuth({ appId: "app-1", persistSession });
    await login(auth);
    auth.clearStoredIdentity();

    expect(local.entries.has(IDENTITY_KEY)).toBe(false);
    expect(session.entries.has(IDENTITY_KEY)).toBe(false);
    expect(new CavosAuth({ appId: "app-1", persistSession }).restoreIdentity()).toBeNull();
  });
});
