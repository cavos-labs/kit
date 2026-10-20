import { randomBytes } from "@noble/hashes/utils";
import { deriveViewingKey } from "../chains/starknet/viewingKey";
import { CHAIN_ID, mockPrivacy, PRIVATE_KEY } from "../chains/starknet/privacy/fixtures";
import type { StarknetSpend } from "../chains/starknet/nativeConnect";
import { createVaultHandler, serveVault } from "./host";
import { memoryLedger } from "./ledger";
import type { OverLimit } from "./limits";
import type { Line } from "./policy";
import { VaultClient } from "./VaultClient";

const params = { network: "sepolia", appSalt: "salt", userId: "u1", recovery: "none" as const };

function setup(options: { confirm?: () => Promise<boolean>; overLimit?: OverLimit; configured?: boolean } = {}) {
  const m = mockPrivacy();
  const asked: Line[][] = [];
  const spend: StarknetSpend = {
    address: () => m.alice,
    publicKey: () => "0x1",
    privateKey: () => PRIVATE_KEY,
  };
  const channel = new MessageChannel();
  const wire: unknown[] = [];
  const reply = channel.port2.postMessage.bind(channel.port2);
  channel.port2.postMessage = ((message: unknown, ...rest: unknown[]) => {
    wire.push(message);
    return (reply as (...args: unknown[]) => void)(message, ...rest);
  }) as typeof channel.port2.postMessage;
  const handle = createVaultHandler({
    appId: "app",
    backendUrl: "https://cavos.test",
    policy: {
      overLimit: options.overLimit ?? "ask",
      limits: [{ chain: "starknet", asset: "STRK", perTx: "1", perDay: "3" }],
    },
    ledger: memoryLedger(),
    confirm: async (lines) => {
      asked.push(lines);
      return (options.confirm ?? (async () => true))();
    },
    passkey: () => ({ enroll: async () => ({ credentialId: new Uint8Array(16), secret: randomBytes(32) }), getSecret: async () => randomBytes(32) }),
    resolveStarknet: async () => ({ address: m.alice, spend, isNewAccount: false }),
    privacy: (network) => (options.configured === false ? undefined : network === "sepolia" ? m.config : undefined),
    privacyDeps: m.init.deps,
  });
  serveVault(channel.port2, handle);
  const client = VaultClient.fromPort(channel.port1);
  const raw = (method: string, requestParams: unknown) =>
    new Promise<{ ok: boolean; result?: unknown; error?: string }>((resolve) => {
      const id = 9000 + Math.floor(Math.random() * 1000);
      const listener = ({ data }: MessageEvent) => {
        if (data.id !== id) return;
        channel.port1.removeEventListener("message", listener);
        resolve(data);
      };
      channel.port1.addEventListener("message", listener);
      channel.port1.postMessage({ id, method, params: requestParams });
    });
  const close = () => {
    channel.port1.close();
    channel.port2.close();
  };
  return { m, client, asked, wire, raw, close };
}

const ONE_STRK = 10n ** 18n;

describe("private transfers through the vault", () => {
  it("runs register, deposit, transfer, balance and withdraw end to end", async () => {
    const { m, client, close } = setup();
    const connected = await client.connectStarknet({ ...params }, "api-key");
    const privacy = connected.privacy!;
    expect(await privacy.status()).toEqual({ registered: false });
    expect((await privacy.register()).transactionHash).toMatch(/^0x/);
    expect(await privacy.status()).toEqual({ registered: true });

    await privacy.deposit(m.strk, 5n);
    expect(await privacy.balance(m.strk)).toBe(5n);
    await privacy.withdraw(m.strk, m.alice, 2n);
    expect(await privacy.balance(m.strk)).toBe(3n);
    expect(m.built.every((entry) => entry.headers["x-paymaster-api-key"] === "api-key")).toBe(true);
    close();
  });

  it("transfers privately to a registered recipient", async () => {
    const { m, client, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    await privacy!.deposit(m.strk, 10n);
    const { createPrivacySession } = await import("../chains/starknet/privacy/session");
    await createPrivacySession(m.bobInit).register();
    await privacy!.transfer(m.strk, m.bob, 4n);
    expect(await privacy!.balance(m.strk)).toBe(6n);
    expect(await createPrivacySession(m.bobInit).balance(m.strk)).toBe(4n);
    close();
  });

  it("sends only hashes, balances and status across the boundary, never a key or a note", async () => {
    const { m, client, wire, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    await privacy!.deposit(m.strk, 5n);
    await privacy!.balance(m.strk);
    await privacy!.status(m.strk);

    const viewingKey = deriveViewingKey(PRIVATE_KEY, { chainId: CHAIN_ID, accountAddress: m.alice, poolAddress: m.pool });
    const secrets = [viewingKey, BigInt(viewingKey).toString(), BigInt(viewingKey).toString(16), PRIVATE_KEY, BigInt(PRIVATE_KEY).toString(16)];
    const serialized = JSON.stringify(wire, (_key, value) => (typeof value === "bigint" ? value.toString() : value));
    for (const secret of secrets) expect(serialized.toLowerCase()).not.toContain(secret.toLowerCase());

    const results = (wire as { ok?: boolean; result?: unknown }[]).filter((message) => message.ok && message.result);
    for (const { result } of results) {
      const shape = typeof result === "object" && result !== null ? Object.keys(result).sort() : typeof result;
      expect([["registered"], ["registered", "requirement"], ["transactionHash"], "string", ["address", "handle", "isNewAccount", "passkey", "publicKey"]].some((allowed) => JSON.stringify(allowed) === JSON.stringify(shape))).toBe(true);
    }
    const balances = results.filter((message) => typeof message.result === "string" && /^\d+$/.test(message.result as string));
    expect(balances.map((message) => message.result)).toEqual(["5"]);
    close();
  });

  it("ignores a pool, prover or discovery the page tries to pass", async () => {
    const { m, client, raw, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    const handle = `starknet:u1:salt`;
    const answer = await raw("privacyDeposit", {
      handle,
      token: m.strk,
      amount: "5",
      paymasterApiKey: "api-key",
      pool: "0xdead",
      poolAddress: "0xdead",
      prover: "https://evil.example",
      discovery: "https://evil.example",
      ohttp: false,
      relay: { url: "https://evil.example" },
      config: { pool: "0xdead" },
    });
    expect(answer.ok).toBe(true);
    const sent = m.built.map((entry) => entry.params.transaction.apply_action.pool_address);
    expect(sent.every((pool: string) => pool === m.pool)).toBe(true);
    close();
  });

  it("asks before a deposit over the limit and not under it", async () => {
    const { m, client, asked, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    expect(asked).toHaveLength(0);

    await privacy!.deposit(m.strk, 10n);
    expect(asked).toHaveLength(0);

    await privacy!.deposit(m.strk, 2n * ONE_STRK);
    expect(asked).toHaveLength(1);
    expect(asked[0]![0]).toMatchObject({ kind: "send", amount: "2", asset: "STRK", to: `0x${BigInt(m.pool).toString(16).padStart(64, "0")}` });
    expect(asked[0]![1]).toMatchObject({ kind: "action", text: expect.stringContaining("Private") });
    close();
  });

  it("asks before a private transfer or withdrawal over the limit, naming the receiver", async () => {
    const { m, client, asked, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    await privacy!.deposit(m.strk, 3n * ONE_STRK);
    asked.length = 0;
    const { createPrivacySession } = await import("../chains/starknet/privacy/session");
    await createPrivacySession(m.bobInit).register();

    await privacy!.transfer(m.strk, m.bob, 2n * ONE_STRK);
    expect(asked[0]![0]).toMatchObject({ kind: "send", asset: "STRK", amount: "2", to: `0x${BigInt(m.bob).toString(16).padStart(64, "0")}` });
    await privacy!.withdraw(m.strk, m.alice, 2n);
    expect(asked).toHaveLength(1);
    close();
  });

  it("always asks for a token it does not know", async () => {
    const { m, client, asked, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    await privacy!.deposit(m.ace, 1n);
    expect(asked).toHaveLength(1);
    expect(asked[0]![0]).toMatchObject({ kind: "send", asset: expect.stringContaining("unknown token") });
    close();
  });

  it("does not submit when the user rejects", async () => {
    const { m, client, close } = setup({ confirm: async () => false });
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    const before = m.executed.length;
    await expect(privacy!.deposit(m.strk, 2n * ONE_STRK)).rejects.toThrow(/rejected/);
    await expect(privacy!.transfer(m.strk, m.bob, 2n * ONE_STRK)).rejects.toThrow(/rejected/);
    await expect(privacy!.withdraw(m.strk, m.alice, 2n * ONE_STRK)).rejects.toThrow(/rejected/);
    expect(m.executed).toHaveLength(before);
    close();
  });

  it("blocks without asking when the policy says so", async () => {
    const { m, client, asked, close } = setup({ overLimit: "block" });
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await expect(privacy!.deposit(m.strk, 2n * ONE_STRK)).rejects.toThrow(/policy/);
    expect(asked).toHaveLength(0);
    close();
  });

  it("asks nothing to register", async () => {
    const { client, asked, close } = setup();
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await privacy!.register();
    expect(asked).toHaveLength(0);
    close();
  });

  it("says so when the app has no private transfer settings", async () => {
    const { m, client, close } = setup({ configured: false });
    const { privacy } = await client.connectStarknet({ ...params }, "api-key");
    await expect(privacy!.status()).rejects.toThrow(/private transfer settings for sepolia/);
    await expect(privacy!.deposit(m.strk, 1n)).rejects.toThrow(/private transfer settings/);
    close();
  });

  it("refuses malformed amounts and addresses", async () => {
    const { m, client, raw, close } = setup();
    await client.connectStarknet({ ...params }, "api-key");
    const handle = "starknet:u1:salt";
    const base = { handle, token: m.strk, paymasterApiKey: "k" };
    expect((await raw("privacyDeposit", { ...base, amount: "-1" })).ok).toBe(false);
    expect((await raw("privacyDeposit", { ...base, amount: "0" })).ok).toBe(false);
    expect((await raw("privacyDeposit", { ...base, amount: "1.5" })).ok).toBe(false);
    expect((await raw("privacyTransfer", { ...base, amount: "1", recipient: "bob" })).ok).toBe(false);
    expect((await raw("privacyWithdraw", { ...base, amount: "1" })).ok).toBe(false);
    expect(m.built).toHaveLength(0);
    close();
  });

  it("needs a connected account", async () => {
    const { m, raw, close } = setup();
    const answer = await raw("privacyBalance", { handle: "starknet:nobody:salt", token: m.strk });
    expect(answer).toMatchObject({ ok: false, error: expect.stringContaining("connect first") });
    close();
  });
});
