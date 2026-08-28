import {
  validateCavosConfig,
  checkAppSaltDrift,
  formatConfigProblems,
} from "./validateConfig";
import type { CavosConfig } from "./CavosProvider";

const base: CavosConfig = {
  appId: "app-1",
  chain: "solana",
  network: "testnet",
  appSalt: "my-app",
};

const codes = (c: CavosConfig) => validateCavosConfig(c).map((p) => p.code);

describe("validateCavosConfig", () => {
  it("says nothing about a correct config", () => {
    expect(validateCavosConfig(base)).toEqual([]);
    expect(
      validateCavosConfig({ ...base, chain: "starknet", paymasterApiKey: "k" }),
    ).toEqual([]);
  });

  it("catches the config that cannot work", () => {
    expect(codes({ ...base, appSalt: "" })).toContain("missing-app-salt");
    expect(codes({ ...base, chain: "starknet" })).toContain("missing-paymaster-key");
    expect(codes({ ...base, appId: undefined, socialRecovery: true })).toContain(
      "social-recovery-without-app-id",
    );
  });

  it("flags a paymaster key on a chain that ignores it", () => {
    // Easy to carry over when copying a Starknet config; it ships a key for
    // nothing, so it is worth a word even though everything still works.
    expect(codes({ ...base, chain: "stellar", paymasterApiKey: "k" })).toContain(
      "unused-paymaster-key",
    );
    expect(codes({ ...base, chain: "starknet", paymasterApiKey: "k" })).not.toContain(
      "unused-paymaster-key",
    );
  });

  it("separates what breaks from what is merely suspect", () => {
    const problems = validateCavosConfig({ ...base, appId: undefined });
    expect(problems.every((p) => p.level === "warning")).toBe(true);
  });

  it("renders problems as readable lines", () => {
    const text = formatConfigProblems(validateCavosConfig({ ...base, appSalt: "" }));
    expect(text).toContain("missing-app-salt");
    expect(text).toContain("✗");
  });
});

describe("checkAppSaltDrift", () => {
  function memoryStorage(seed: Record<string, string> = {}) {
    const map = new Map(Object.entries(seed));
    return {
      map,
      getItem: (k: string) => map.get(k) ?? null,
      setItem: (k: string, v: string) => void map.set(k, v),
    };
  }

  it("stays quiet on a first run and remembers the salt", () => {
    // A new browser has no prior salt. Warning here would fire for every user.
    const s = memoryStorage();
    expect(checkAppSaltDrift(base, s)).toBeNull();
    expect([...s.map.values()]).toContain("my-app");
  });

  it("stays quiet when the salt is unchanged", () => {
    const s = memoryStorage();
    checkAppSaltDrift(base, s);
    expect(checkAppSaltDrift(base, s)).toBeNull();
  });

  it("reports a changed salt, naming both values", () => {
    const s = memoryStorage();
    checkAppSaltDrift(base, s);
    const problem = checkAppSaltDrift({ ...base, appSalt: "my-app-v2" }, s);
    expect(problem?.code).toBe("app-salt-changed");
    expect(problem?.level).toBe("error");
    expect(problem?.message).toContain("my-app");
    expect(problem?.message).toContain("my-app-v2");
  });

  it("only reports the change once", () => {
    const s = memoryStorage();
    checkAppSaltDrift(base, s);
    const next = { ...base, appSalt: "my-app-v2" };
    expect(checkAppSaltDrift(next, s)?.code).toBe("app-salt-changed");
    expect(checkAppSaltDrift(next, s)).toBeNull();
  });

  it("tracks each chain and network separately", () => {
    // The same app legitimately runs different salts per config object; drift
    // means "this exact wallet set moved", not "some salt somewhere differs".
    const s = memoryStorage();
    checkAppSaltDrift(base, s);
    expect(checkAppSaltDrift({ ...base, chain: "starknet" }, s)).toBeNull();
    expect(checkAppSaltDrift({ ...base, network: "mainnet" }, s)).toBeNull();
  });

  it("does nothing without storage or without a salt", () => {
    expect(checkAppSaltDrift(base, undefined)).toBeNull();
    expect(checkAppSaltDrift({ ...base, appSalt: "" }, memoryStorage())).toBeNull();
  });

  it("survives storage that throws", () => {
    const hostile = {
      getItem: () => {
        throw new Error("blocked");
      },
      setItem: () => {
        throw new Error("blocked");
      },
    };
    expect(() => checkAppSaltDrift(base, hostile)).not.toThrow();
  });
});

describe("rpcUrl across several chains", () => {
  const base = { appId: "app-1", appSalt: "salt", network: "testnet" as const, paymasterApiKey: "k" };

  it("rejects a single rpcUrl once more than one chain is configured", () => {
    // One node cannot serve three chains, and the mismatched one answers
    // `starknet_call` with "Method not found" rather than failing usefully.
    const problems = validateCavosConfig({
      ...base,
      chains: ["starknet", "solana"],
      rpcUrl: "https://api.devnet.solana.com",
    } as never);
    expect(problems.map((p) => p.code)).toContain("ambiguous-rpc-url");
  });

  it("accepts per-chain overrides", () => {
    const problems = validateCavosConfig({
      ...base,
      chains: ["starknet", "solana"],
      rpcUrls: { solana: "https://api.devnet.solana.com" },
    } as never);
    expect(problems.map((p) => p.code)).not.toContain("ambiguous-rpc-url");
  });

  it("leaves a single-chain config alone", () => {
    const problems = validateCavosConfig({
      ...base,
      chain: "solana",
      rpcUrl: "https://api.devnet.solana.com",
    } as never);
    expect(problems.map((p) => p.code)).not.toContain("ambiguous-rpc-url");
  });
});
