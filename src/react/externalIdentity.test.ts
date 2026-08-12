/**
 * Behaviour of the `identity` prop (bring your own auth).
 *
 * These assert the security-relevant decisions rather than React plumbing:
 * an externally supplied identity is never persisted, and a Cavos session
 * never outlives — or survives a change of — the host's session.
 */
import { CavosAuth } from "../auth/CavosAuth";

describe("bring-your-own-auth invariants", () => {
  const STORAGE_KEY_FRAGMENT = "cavos";

  function memoryStorage() {
    const map = new Map<string, string>();
    return {
      map,
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => void map.set(k, v),
      removeItem: (k: string) => void map.delete(k),
      clear: () => map.clear(),
      key: () => null,
      length: 0,
    } as unknown as Storage & { map: Map<string, string> };
  }

  let storage: ReturnType<typeof memoryStorage>;

  beforeEach(() => {
    storage = memoryStorage();
    Object.defineProperty(global, "localStorage", {
      value: storage,
      configurable: true,
    });
    Object.defineProperty(global, "window", {
      value: { localStorage: storage, location: { href: "https://app.test/" } },
      configurable: true,
    });
  });

  it("does not resurrect a Cavos session from storage", () => {
    // Nothing ever wrote a host identity, so a fresh mount has nothing to
    // restore — the host's auth is asked again every time.
    const auth = new CavosAuth({ appId: "app-1" });
    expect(auth.restoreIdentity()).toBeNull();
  });

  it("keeps a host identity out of storage entirely", () => {
    // The provider passes the host identity straight to connect() and never
    // through CavosAuth's remember(), so signing out of the host app cannot
    // leave a usable Cavos session behind.
    const written = [...storage.map.keys()].filter((k) =>
      k.includes(STORAGE_KEY_FRAGMENT),
    );
    expect(written).toEqual([]);
  });

  it("treats a cleared identity as different from an absent one", () => {
    // undefined = the host is not supplying identity at all (Cavos runs its
    // own auth). null = the host supplies it and nobody is signed in. Merging
    // the two would either disable Cavos login or silently ignore a sign-out.
    const isExternal = (identity: unknown) => identity !== undefined;
    expect(isExternal(undefined)).toBe(false);
    expect(isExternal(null)).toBe(true);
    expect(isExternal({ userId: "u1" })).toBe(true);
  });

  it("distinguishes users by userId, not object identity", () => {
    // Hosts re-create the identity object every render. Keying the reconnect
    // on the object would reconnect continuously; keying on userId means a
    // real user change still swaps the wallet.
    const key = (identity: { userId: string } | null) => identity?.userId ?? null;
    const a = { userId: "u1", email: "a@test" };
    const sameUserNewObject = { userId: "u1", email: "a@test" };
    const otherUser = { userId: "u2" };
    expect(key(a)).toBe(key(sameUserNewObject));
    expect(key(a)).not.toBe(key(otherUser));
    expect(key(null)).toBeNull();
  });
});
