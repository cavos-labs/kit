import { describe, expect, it, beforeEach } from "@jest/globals";
import {
  confirmedByCandidates,
  recallPasskeyKey,
  rememberPasskeyKey,
} from "./passkeyKeyCache";

/**
 * The cache exists to save a gesture, and it is safe because it is checked
 * rather than believed — unlike the pending intents it replaced, which were
 * taken at their word and silently lost accounts when they went stale.
 */
describe("remembering the passkey's public key", () => {
  const key = { x: 0xabcdefn, y: 0x123456n };
  const other = { x: 0x999n, y: 0x888n };

  beforeEach(() => {
    const store = new Map<string, string>();
    (globalThis as { window?: unknown }).window = {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => void store.set(k, v),
      },
    };
  });

  it("comes back as the same key", () => {
    rememberPasskeyKey("u1", key);
    expect(recallPasskeyKey("u1")).toEqual(key);
  });

  it("is kept per user", () => {
    // One browser, two accounts: handing the second one the first's approver
    // would write a passkey its owner does not hold.
    rememberPasskeyKey("u1", key);
    expect(recallPasskeyKey("u2")).toBeNull();
  });

  it("is used when the signature recovered it", () => {
    expect(confirmedByCandidates(key, [key, other])).toEqual(key);
  });

  it("is ignored when the signature did not", () => {
    // A stale or poisoned entry costs the second gesture and nothing else: a
    // wrong key never appears among a real signature's candidates.
    expect(confirmedByCandidates(other, [key, { x: 1n, y: 2n }])).toBeNull();
  });

  it("is ignored when there is nothing remembered", () => {
    expect(confirmedByCandidates(null, [key])).toBeNull();
  });

  it("survives a browser that refuses storage", () => {
    (globalThis as { window?: unknown }).window = {
      localStorage: {
        getItem: () => {
          throw new Error("blocked");
        },
        setItem: () => {
          throw new Error("blocked");
        },
      },
    };
    expect(() => rememberPasskeyKey("u1", key)).not.toThrow();
    expect(recallPasskeyKey("u1")).toBeNull();
  });
});
