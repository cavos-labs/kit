import { mockPrivacy, PRIVATE_KEY, STRK } from "./fixtures";
import { createPrivacySession } from "./session";
import { deriveViewingKey, viewingPublicKey } from "../viewingKey";

const USER_FEE = (token: string) => ({ mode: "sponsored", pool_fee: { paid_by: "user", token } }) as const;

describe("private session on the in-memory pool", () => {
  it("registers, deposits, transfers, reports the balance and withdraws", async () => {
    const m = mockPrivacy();
    const session = createPrivacySession(m.init);

    expect(await session.status()).toEqual({ registered: false });
    expect(await session.balance(m.ace)).toBe(0n);

    const registered = await session.register();
    expect(registered.transactionHash).toMatch(/^0x/);
    expect(await session.status()).toEqual({ registered: true });
    const key = deriveViewingKey(PRIVATE_KEY, { chainId: m.init.chainId, accountAddress: m.alice, poolAddress: m.pool });
    expect(m.mocknet.pool.get_public_key(m.env.alice.address)).toBe(BigInt(viewingPublicKey(key)));

    await createPrivacySession(m.bobInit).register();

    await session.deposit(m.ace, 100n);
    expect(await session.balance(m.ace)).toBe(100n);

    await session.transfer(m.ace, m.bob, 30n);
    expect(await session.balance(m.ace)).toBe(70n);

    await session.withdraw(m.ace, m.alice, 20n);
    expect(await session.balance(m.ace)).toBe(50n);

    expect(await createPrivacySession(m.bobInit).balance(m.ace)).toBe(30n);

    expect(m.executed.map((entry) => entry.params.transaction.type)).toEqual([
      "apply_action",
      "apply_action",
      "invoke_and_apply_action",
      "apply_action",
      "apply_action",
    ]);
    expect(m.built.every((entry) => entry.headers["x-paymaster-api-key"] === "key-1")).toBe(true);
  });

  it("sends the approval as a signed relay call and the registration with the sponsor paying", async () => {
    const m = mockPrivacy({ fee: USER_FEE("0x1") });
    const session = createPrivacySession(m.init);
    await session.register();
    expect(m.built[0]!.params.parameters.fee_mode).toEqual({ mode: "sponsored", pool_fee: { paid_by: "sponsor" } });

    await session.deposit(m.ace, 100n);
    const deposit = m.built[1]!.params;
    expect(deposit.transaction.type).toBe("invoke_and_apply_action");
    expect(deposit.parameters.fee_mode).toEqual(USER_FEE("0x1"));
    expect(deposit.transaction.invoke.calls).toHaveLength(1);
    const signed = m.executed[1]!.params.transaction.invoke;
    expect(signed.signature).toHaveLength(2);
    expect(signed.user_address).toBe(m.alice);
  });

  it("takes a user-paid pool fee out of the private balance", async () => {
    const probe = mockPrivacy();
    const m = mockPrivacy({ fee: USER_FEE(probe.ace), feeAmount: 5n });
    const session = createPrivacySession(m.init);
    await session.register();
    await session.deposit(m.ace, 100n);
    expect(await session.balance(m.ace)).toBe(95n);
  });

  it("refuses to go on when the pool holds another viewing key for the account", async () => {
    const m = mockPrivacy();
    const other = createPrivacySession({ ...m.init, account: { ...m.init.account, spend: { privateKey: () => "0xabc123" } } });
    await other.register();

    const session = createPrivacySession(m.init);
    await expect(session.status()).rejects.toThrow(/different viewing key/);
    await expect(session.register()).rejects.toThrow(/different viewing key/);
    await expect(session.deposit(m.ace, 1n)).rejects.toThrow(/different viewing key/);
    expect(m.executed).toHaveLength(1);
  });

  it("refuses a second registration", async () => {
    const m = mockPrivacy();
    const session = createPrivacySession(m.init);
    await session.register();
    await expect(session.register()).rejects.toThrow(/already registered/);
  });

  it("leaves registration to the first deposit when the app does not sponsor", async () => {
    const m = mockPrivacy({ fee: { mode: "default", gas_token: STRK } });
    const session = createPrivacySession(m.init);
    await expect(session.register()).rejects.toThrow(/first deposit registers/);
    expect(m.executed).toHaveLength(0);
  });

  it("rejects malformed tokens, recipients and amounts before touching the relay", async () => {
    const m = mockPrivacy();
    const session = createPrivacySession(m.init);
    await expect(session.deposit("nope", 1n)).rejects.toThrow(/token/);
    await expect(session.transfer(m.ace, "0x0", 1n)).rejects.toThrow(/recipient/);
    await expect(session.withdraw(m.ace, m.bob, 0n)).rejects.toThrow(/amount/);
    expect(m.built).toHaveLength(0);
  });

  it("serialises operations: the second proves after the first lands", async () => {
    const m = mockPrivacy();
    const session = createPrivacySession(m.init);
    await session.register();
    const order: string[] = [];
    const first = session.deposit(m.ace, 10n).then(() => order.push("first"));
    const second = session.deposit(m.ace, 20n).then(() => order.push("second"));
    await Promise.all([first, second]);
    expect(order).toEqual(["first", "second"]);
    expect(await session.balance(m.ace)).toBe(30n);
  });

  it("waits for the previous transaction to age before proving", async () => {
    const m = mockPrivacy();
    const session = createPrivacySession(m.init);
    await session.register();
    m.init.deps!.chain!.confirm = async () => 995;
    const pending = session.deposit(m.ace, 10n);
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(m.executed).toHaveLength(1);
    m.setHead(1010);
    await pending;
    expect(m.executed).toHaveLength(2);
  });

  it("never reaches a fee recipient the app did not allow", async () => {
    const probe = mockPrivacy();
    const m = mockPrivacy({ fee: USER_FEE(probe.ace), feeAmount: 5n, quotedRecipient: "0xbad" });
    const session = createPrivacySession(m.init);
    await expect(session.deposit(m.ace, 10n)).rejects.toThrow(/does not allow/);
    expect(m.executed).toHaveLength(0);
  });
});
