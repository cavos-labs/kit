import {
  Address,
  Operation,
  StrKey,
  hash,
  nativeToScVal,
  scValToNative,
  xdr,
  rpc,
} from "@stellar/stellar-sdk";
import { sha256 } from "@noble/hashes/sha256";
import type { DeviceSigner, DevicePublicKey, DeviceSignature } from "../../signer/DeviceSigner";
import { bigIntTo32Bytes } from "../../crypto/encoding";
import type { PasskeyAssertion } from "../../crypto/webauthn";
import {
  FACTORY_CONTRACT_ID,
  STELLAR_NETWORKS,
  type StellarNetwork,
} from "./constants";

/** secp256r1 (P-256) curve order — for low-S normalization (verifier requires it). */
const SECP256R1_N =
  0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

export interface StellarAdapterOptions {
  network: StellarNetwork;
  /** RPC override (else the network default). */
  rpcUrl?: string;
  /** Factory contract id override (else the per-network default). */
  factoryId?: string;
  /** The device signer that authorizes account operations. */
  signer: DeviceSigner;
}

/**
 * Stellar / Soroban implementation of the Cavos device-account surface. Unlike
 * Starknet (`buildSignature(txHash: bigint)`) the Soroban signing unit is a
 * 32-byte Soroban *auth-entry* preimage, so — as the Solana adapter did for its
 * own model — this adapter exposes chain-native methods rather than the generic
 * `ChainAdapter` shape. Its job:
 *   - derive the deterministic account address off-chain (matches the factory),
 *   - build the factory/account/token invocations as host functions, and
 *   - sign a Soroban authorization entry with the silent P-256 device key,
 *     producing the `Vec<DeviceSignature>` ScVal that the contract's
 *     `__check_auth` verifies.
 */
export class StellarAdapter {
  readonly chain = "stellar" as const;
  readonly network: StellarNetwork;
  readonly passphrase: string;
  private readonly rpcUrl: string;
  private readonly factoryId: string;
  private readonly signer: DeviceSigner;
  private _server?: rpc.Server;

  constructor(opts: StellarAdapterOptions) {
    this.network = opts.network;
    this.passphrase = STELLAR_NETWORKS[opts.network].passphrase;
    this.rpcUrl = opts.rpcUrl ?? STELLAR_NETWORKS[opts.network].rpcUrl;
    this.factoryId = opts.factoryId ?? FACTORY_CONTRACT_ID[opts.network];
    if (!this.factoryId) {
      throw new Error(`kit/stellar: no factory contract id configured for ${opts.network}`);
    }
    this.signer = opts.signer;
  }

  server(): rpc.Server {
    if (!this._server) {
      this._server = new rpc.Server(this.rpcUrl, {
        allowHttp: this.rpcUrl.startsWith("http://"),
      });
    }
    return this._server;
  }

  private networkId(): Buffer {
    return hash(Buffer.from(this.passphrase));
  }

  /**
   * Deterministic account address for `(addressSeed, initialSigner)` — computed
   * off-chain, byte-identical to the factory's on-chain `account_address`.
   * `contractId = sha256(HashIdPreimage(networkId, factory, salt))` with
   * `salt = sha256(addressSeed || sec1(initialSigner))`.
   */
  computeAddress(addressSeed: Uint8Array, initialSigner: DevicePublicKey): string {
    const salt = this.accountSalt(addressSeed, initialSigner);
    const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
      new xdr.HashIdPreimageContractId({
        networkId: this.networkId(),
        contractIdPreimage: xdr.ContractIdPreimage.contractIdPreimageFromAddress(
          new xdr.ContractIdPreimageFromAddress({
            address: new Address(this.factoryId).toScAddress(),
            salt,
          }),
        ),
      }),
    );
    return StrKey.encodeContract(hash(preimage.toXDR()));
  }

  /** `salt = sha256(addressSeed(32) || sec1(initialSigner)(65))` — matches the factory. */
  accountSalt(addressSeed: Uint8Array, initialSigner: DevicePublicKey): Buffer {
    return hash(Buffer.concat([Buffer.from(addressSeed), Buffer.from(sec1Pubkey(initialSigner))]));
  }

  /** Host function: `factory.deploy(address_seed, initial_signer)`. */
  buildDeploy(addressSeed: Uint8Array, initialSigner: DevicePublicKey): xdr.HostFunction {
    return invokeFunc(this.factoryId, "deploy", [
      bytesScVal(addressSeed),
      bytesScVal(sec1Pubkey(initialSigner)),
    ]);
  }

  /** Host function: `account.add_signer(new_signer)` (requires device auth). */
  buildAddSigner(accountAddress: string, signer: DevicePublicKey): xdr.HostFunction {
    return invokeFunc(accountAddress, "add_signer", [bytesScVal(sec1Pubkey(signer))]);
  }

  /** Host function: `account.remove_signer(signer)` (requires device auth). */
  buildRemoveSigner(accountAddress: string, signer: DevicePublicKey): xdr.HostFunction {
    return invokeFunc(accountAddress, "remove_signer", [bytesScVal(sec1Pubkey(signer))]);
  }

  /** Host function: `account.add_approver(passkey)` (requires device auth). */
  buildAddApprover(accountAddress: string, passkey: DevicePublicKey): xdr.HostFunction {
    return invokeFunc(accountAddress, "add_approver", [bytesScVal(sec1Pubkey(passkey))]);
  }

  /** Host function: `account.remove_approver(passkey)` (requires device auth). */
  buildRemoveApprover(accountAddress: string, passkey: DevicePublicKey): xdr.HostFunction {
    return invokeFunc(accountAddress, "remove_approver", [bytesScVal(sec1Pubkey(passkey))]);
  }

  /** This chain's leaf for approving `add_signer(newSigner)` at `nonce`:
   * `sha256(sec1(new_signer) || nonce_be8)`. The batch challenge the passkey signs
   * is `sha256(concat(leaves))` across chains. */
  passkeyLeaf(newSigner: DevicePublicKey, nonce: bigint): Uint8Array {
    const msg = new Uint8Array(65 + 8);
    msg.set(sec1Pubkey(newSigner), 0);
    const n = new Uint8Array(8);
    let v = nonce;
    for (let i = 7; i >= 0; i--) {
      n[i] = Number(v & 0xffn);
      v >>= 8n;
    }
    msg.set(n, 65);
    return sha256(msg);
  }

  /** Host function: passkey-authorized `add_signer_via_passkey` (no device auth —
   * authorized by the embedded WebAuthn assertion, so any relayer can submit).
   * `leaves`/`leafIndex` place this chain's leaf in the multi-chain batch. */
  buildAddSignerViaPasskey(
    accountAddress: string,
    newSigner: DevicePublicKey,
    passkey: DevicePublicKey,
    nonce: bigint,
    leaves: Uint8Array[],
    leafIndex: number,
    assertion: PasskeyAssertion,
  ): xdr.HostFunction {
    const sig = encodeLowSSignature({ r: assertion.r, s: assertion.s, yParity: false });
    const leavesScVal = xdr.ScVal.scvVec(leaves.map((l) => bytesScVal(l)));
    return invokeFunc(accountAddress, "add_signer_via_passkey", [
      bytesScVal(sec1Pubkey(newSigner)),
      bytesScVal(sec1Pubkey(passkey)),
      nativeToScVal(nonce, { type: "u64" }),
      leavesScVal,
      nativeToScVal(leafIndex, { type: "u32" }),
      bytesScVal(assertion.authenticatorData),
      bytesScVal(assertion.clientDataJSON),
      nativeToScVal(assertion.challengeOffset, { type: "u32" }),
      bytesScVal(sig),
    ]);
  }

  /** Read whether `passkey` is a registered approver (read-only simulation). */
  async isApprover(
    accountAddress: string,
    passkey: DevicePublicKey,
    readSource: string,
  ): Promise<boolean> {
    if (!(await this.isDeployed(accountAddress))) return false;
    const { Account, TransactionBuilder, BASE_FEE } = await import("@stellar/stellar-sdk");
    const src = new Account(readSource, "0");
    const op = Operation.invokeHostFunction({
      func: invokeFunc(accountAddress, "is_approver", [bytesScVal(sec1Pubkey(passkey))]),
      auth: [],
    });
    const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(op)
      .setTimeout(30)
      .build();
    const sim = await this.server().simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`kit/stellar: is_approver simulation failed: ${sim.error}`);
    }
    if (!sim.result?.retval) return false;
    return scValToNative(sim.result.retval) === true;
  }

  /** Read the current passkey-approval nonce (read-only simulation). */
  async passkeyNonce(accountAddress: string, readSource: string): Promise<bigint> {
    if (!(await this.isDeployed(accountAddress))) return 0n;
    const { Account, TransactionBuilder, BASE_FEE } = await import("@stellar/stellar-sdk");
    const src = new Account(readSource, "0");
    const op = Operation.invokeHostFunction({
      func: invokeFunc(accountAddress, "passkey_nonce", []),
      auth: [],
    });
    const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(op)
      .setTimeout(30)
      .build();
    const sim = await this.server().simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`kit/stellar: passkey_nonce simulation failed: ${sim.error}`);
    }
    if (!sim.result?.retval) return 0n;
    return BigInt(scValToNative(sim.result.retval));
  }

  /** Host function: SEP-41 `token.transfer(from=account, to, amount)` (device auth). */
  buildTransfer(
    tokenId: string,
    accountAddress: string,
    destination: string,
    amount: bigint,
  ): xdr.HostFunction {
    return invokeFunc(tokenId, "transfer", [
      new Address(accountAddress).toScVal(),
      new Address(destination).toScVal(),
      nativeToScVal(amount, { type: "i128" }),
    ]);
  }

  /**
   * Sign a Soroban authorization entry with the silent device key, producing the
   * `Vec<DeviceSignature>` the account's `__check_auth` verifies. The device
   * signs `sha256(preimage)` (WebCrypto hashes once more internally), which is
   * exactly what the contract recomputes. Mutates + returns the entry.
   */
  async signAuthEntry(
    entry: xdr.SorobanAuthorizationEntry,
    validUntilLedger: number,
  ): Promise<xdr.SorobanAuthorizationEntry> {
    const addrCreds = entry.credentials().address();
    addrCreds.signatureExpirationLedger(validUntilLedger);

    const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
      new xdr.HashIdPreimageSorobanAuthorization({
        networkId: this.networkId(),
        nonce: addrCreds.nonce(),
        signatureExpirationLedger: validUntilLedger,
        invocation: entry.rootInvocation(),
      }),
    );
    const payload = hash(preimage.toXDR());
    const sig = await this.signer.sign(new Uint8Array(payload));
    const pubkey = await this.signer.getPublicKey();
    addrCreds.signature(deviceSignatureScVal(pubkey, sig));
    return entry;
  }

  /**
   * Read a SEP-41 token balance of `account` via a read-only simulation of
   * `token.balance(account)`. Returns 0 when the account isn't deployed or holds
   * none. `readSource` is any funded G-account (used only for the simulation).
   */
  async readBalance(tokenId: string, account: string, readSource: string): Promise<bigint> {
    if (!(await this.isDeployed(account))) return 0n;
    const { Account, TransactionBuilder, BASE_FEE } = await import("@stellar/stellar-sdk");
    const src = new Account(readSource, "0");
    const op = Operation.invokeHostFunction({
      func: invokeFunc(tokenId, "balance", [new Address(account).toScVal()]),
      auth: [],
    });
    const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(op)
      .setTimeout(30)
      .build();
    const sim = await this.server().simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim) || !sim.result?.retval) return 0n;
    return BigInt(scValToNative(sim.result.retval) as string | number | bigint);
  }

  /** Whether the account contract instance exists on-chain (is deployed). */
  async isDeployed(accountAddress: string): Promise<boolean> {
    try {
      const res = await this.server().getContractData(
        accountAddress,
        xdr.ScVal.scvLedgerKeyContractInstance(),
        rpc.Durability.Persistent,
      );
      return !!res;
    } catch {
      return false;
    }
  }

  /**
   * Read whether `signer` is a currently-authorized signer of the account, via a
   * read-only simulation of `account.is_authorized(signer)`. `readSource` is any
   * funded G-account (used only for the simulation's source/sequence).
   */
  async isAuthorizedSigner(
    accountAddress: string,
    signer: DevicePublicKey,
    readSource: string,
  ): Promise<boolean> {
    if (!(await this.isDeployed(accountAddress))) return false;
    const { Account, TransactionBuilder, BASE_FEE } = await import("@stellar/stellar-sdk");
    const src = new Account(readSource, "0");
    const op = Operation.invokeHostFunction({
      func: invokeFunc(accountAddress, "is_authorized", [bytesScVal(sec1Pubkey(signer))]),
      auth: [],
    });
    const tx = new TransactionBuilder(src, { fee: BASE_FEE, networkPassphrase: this.passphrase })
      .addOperation(op)
      .setTimeout(30)
      .build();
    const sim = await this.server().simulateTransaction(tx);
    if (rpc.Api.isSimulationError(sim)) {
      throw new Error(`kit/stellar: is_authorized simulation failed: ${sim.error}`);
    }
    if (!sim.result?.retval) return false;
    return scValToNative(sim.result.retval) === true;
  }
}

/** SEC-1 uncompressed P-256 public key (65 bytes: 0x04 || X || Y). */
export function sec1Pubkey(pk: DevicePublicKey): Uint8Array {
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(bigIntTo32Bytes(pk.x), 1);
  out.set(bigIntTo32Bytes(pk.y), 33);
  return out;
}

/** Raw 64-byte `r || s`, normalized to low-S (secp256r1_verify requires it). */
export function encodeLowSSignature(sig: DeviceSignature): Uint8Array {
  const lowS = sig.s > SECP256R1_N / 2n ? SECP256R1_N - sig.s : sig.s;
  const out = new Uint8Array(64);
  out.set(bigIntTo32Bytes(sig.r), 0);
  out.set(bigIntTo32Bytes(lowS), 32);
  return out;
}

/**
 * The `Vec<DeviceSignature>` ScVal the contract's `__check_auth` decodes. Each
 * element is a struct `{ public_key: BytesN<65>, signature: BytesN<64> }`.
 * Soroban serializes a struct as a symbol-keyed map sorted by key; `public_key`
 * precedes `signature`, so `nativeToScVal` (which sorts) yields the exact layout.
 */
export function deviceSignatureScVal(
  pubkey: DevicePublicKey,
  sig: DeviceSignature,
): xdr.ScVal {
  const element = nativeToScVal(
    {
      public_key: Buffer.from(sec1Pubkey(pubkey)),
      signature: Buffer.from(encodeLowSSignature(sig)),
    },
    { type: { public_key: ["symbol", "bytes"], signature: ["symbol", "bytes"] } },
  );
  return xdr.ScVal.scvVec([element]);
}

function invokeFunc(contractId: string, method: string, args: xdr.ScVal[]): xdr.HostFunction {
  return xdr.HostFunction.hostFunctionTypeInvokeContract(
    new xdr.InvokeContractArgs({
      contractAddress: new Address(contractId).toScAddress(),
      functionName: method,
      args,
    }),
  );
}

function bytesScVal(bytes: Uint8Array): xdr.ScVal {
  return xdr.ScVal.scvBytes(Buffer.from(bytes));
}
