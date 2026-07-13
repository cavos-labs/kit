import { Address, Keypair, StrKey, xdr } from "@stellar/stellar-sdk";
import { CavosStellar } from "./CavosStellar";
import { StellarAdapter } from "./StellarAdapter";
import { deriveStellarMasterKeypair } from "./keys";
import { LocalDeviceUnwrapKey } from "./DeviceUnwrapKey";
import type { StellarRelayer } from "./StellarRelayer";

/**
 * Verifies `CavosStellar.invokeContract` — the Soroban path that lets a Cavos
 * account act as a `require_auth(role)` signer (e.g. Trustless Work escrow).
 *
 * Two things matter: (1) only the auth entry whose credential address is THIS
 * account gets re-signed with the control key — entries for other roles are left
 * byte-for-byte untouched; (2) submission routes correctly (relayer fee-bump when
 * sponsored, direct RPC otherwise). We stub the adapter's build/submit so no
 * network is touched; the auth-signing logic runs for real.
 */

const identity = { userId: "u1", appSalt: "app" };
const CONTRACT_ID = StrKey.encodeContract(Buffer.alloc(32, 1));

/** A minimal address-credential auth entry authorizing `pub`. */
function addressEntry(pub: string): xdr.SorobanAuthorizationEntry {
  const creds = xdr.SorobanCredentials.sorobanCredentialsAddress(
    new xdr.SorobanAddressCredentials({
      address: Address.fromString(pub).toScAddress(),
      nonce: xdr.Int64.fromString("0"),
      signatureExpirationLedger: 0,
      signature: xdr.ScVal.scvVoid(),
    }),
  );
  const inv = new xdr.SorobanAuthorizedInvocation({
    function: xdr.SorobanAuthorizedFunction.sorobanAuthorizedFunctionTypeContractFn(
      new xdr.InvokeContractArgs({
        contractAddress: Address.fromString(CONTRACT_ID).toScAddress(),
        functionName: "m",
        args: [],
      }),
    ),
    subInvocations: [],
  });
  return new xdr.SorobanAuthorizationEntry({ credentials: creds, rootInvocation: inv });
}

describe("CavosStellar.invokeContract", () => {
  it("re-signs only this account's auth entry, leaving other roles untouched", async () => {
    const acct = Keypair.random();
    const otherRole = addressEntry(Keypair.random().publicKey());
    const ours = addressEntry(acct.publicKey());
    const otherBefore = otherRole.toXDR("base64");

    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    const fakeTx = { operations: [{ auth: [otherRole, ours] }], sign: jest.fn(), toXDR: () => "x" };
    (adapter as any).buildInvokeTx = jest.fn().mockResolvedValue(fakeTx);
    (adapter as any).latestLedger = jest.fn().mockResolvedValue(1000);
    (adapter as any).submitSoroban = jest.fn().mockResolvedValue("rpcHash");

    const Ctor = CavosStellar as unknown as new (...args: unknown[]) => CavosStellar;
    const wallet = new Ctor(
      identity,
      acct.publicKey(), // address == the account whose entry should get signed
      "ready",
      "stellar-testnet",
      adapter,
      LocalDeviceUnwrapKey.generate(),
      acct,
      new Uint8Array(32),
      undefined,
    );

    const hash = await wallet.invokeContract({ contractId: CONTRACT_ID, method: "release_funds", args: [] });

    expect(hash).toBe("rpcHash");
    const [signedOther, signedOurs] = fakeTx.operations[0].auth as xdr.SorobanAuthorizationEntry[];
    // other role untouched (still void signature)
    expect(signedOther.toXDR("base64")).toBe(otherBefore);
    expect(signedOther.credentials().address().signature().switch().name).toBe("scvVoid");
    // ours signed (signature became a vec + expiration bounded)
    expect(signedOurs.credentials().address().signature().switch().name).toBe("scvVec");
    expect(signedOurs.credentials().address().signatureExpirationLedger()).toBe(1000 + 720);
  });

  it("fee-bumps through the relayer when sponsored (default)", async () => {
    const acct = Keypair.random();
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    const fakeTx = { operations: [{ auth: [] }], sign: jest.fn(), toXDR: () => "x" };
    (adapter as any).buildInvokeTx = jest.fn().mockResolvedValue(fakeTx);
    (adapter as any).latestLedger = jest.fn().mockResolvedValue(1000);
    (adapter as any).wrapFeeBump = jest.fn().mockReturnValue({ toXDR: () => "bumpXdr" });
    (adapter as any).submitSoroban = jest.fn();

    const relayer = {
      getSource: async () => Keypair.random().publicKey(),
      submit: jest.fn().mockResolvedValue("relayerHash"),
    } as unknown as StellarRelayer;

    const Ctor = CavosStellar as unknown as new (...args: unknown[]) => CavosStellar;
    const wallet = new Ctor(
      identity,
      acct.publicKey(),
      "ready",
      "stellar-testnet",
      adapter,
      LocalDeviceUnwrapKey.generate(),
      acct,
      new Uint8Array(32),
      relayer,
    );

    const hash = await wallet.invokeContract({ contractId: CONTRACT_ID, method: "fund_escrow" });
    expect(hash).toBe("relayerHash");
    expect((relayer as any).submit).toHaveBeenCalledWith("soroban", "bumpXdr");
    expect((adapter as any).submitSoroban).not.toHaveBeenCalled();
  });

  it("submits directly via RPC when { sponsored: false }", async () => {
    const acct = Keypair.random();
    const adapter = new StellarAdapter({ network: "stellar-testnet" });
    const fakeTx = { operations: [{ auth: [] }], sign: jest.fn(), toXDR: () => "x" };
    (adapter as any).buildInvokeTx = jest.fn().mockResolvedValue(fakeTx);
    (adapter as any).latestLedger = jest.fn().mockResolvedValue(1000);
    (adapter as any).submitSoroban = jest.fn().mockResolvedValue("rpcHash");

    const relayer = {
      getSource: async () => Keypair.random().publicKey(),
      submit: jest.fn(),
    } as unknown as StellarRelayer;

    const Ctor = CavosStellar as unknown as new (...args: unknown[]) => CavosStellar;
    const wallet = new Ctor(
      identity, acct.publicKey(), "ready", "stellar-testnet", adapter,
      LocalDeviceUnwrapKey.generate(), acct, new Uint8Array(32), relayer,
    );

    const hash = await wallet.invokeContract({
      contractId: CONTRACT_ID,
      method: "approve_milestone",
      args: [0],
      opts: { sponsored: false },
    });
    expect(hash).toBe("rpcHash");
    expect((adapter as any).submitSoroban).toHaveBeenCalled();
    expect((relayer as any).submit).not.toHaveBeenCalled();
  });
});
