import {
  Connection,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";
import { Buffer } from "buffer";
import { sha256 } from "@noble/hashes/sha256";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { bigIntTo32Bytes } from "../../crypto/encoding";
import {
  ACCOUNT_SEED,
  SOCIAL_RECOVERY_SEED,
  DEVICE_ACCOUNT_PROGRAM_ID,
  DOMAIN_ADD,
  DOMAIN_REMOVE,
  DOMAIN_TRANSFER,
  DOMAIN_EXECUTE,
  DOMAIN_ADD_APPROVER,
  DOMAIN_REMOVE_APPROVER,
  DOMAIN_ENROLL_SOCIAL,
  SECP256R1_N,
  SECP256R1_PROGRAM_ID,
} from "./constants";
import type { PasskeyAssertion } from "../../crypto/webauthn";

const COMPRESSED_PUBKEY_SIZE = 33;
/** 8 discriminator + 32 address_seed + 1 bump + 8 nonce + 33 initial_signer. */
const DEVICE_ACCOUNT_HEADER = 8 + 32 + 1 + 8 + COMPRESSED_PUBKEY_SIZE;
const SIGNATURE_SIZE = 64;
const CURRENT_IX = 0xffff;

/** An account meta candidate for a CPI instruction inside `execute`. Mirrors the
 *  on-chain `AccountMetaCandidate` (Borsh). */
export interface InstructionAccount {
  pubkey: string;
  isSigner: boolean;
  isWritable: boolean;
}

/** A CPI instruction the device key authorizes via `execute`. Mirrors the
 *  on-chain `InstructionData` (Borsh). Serialized canonically and hashed before
 *  signing, so a signature binds exactly this instruction set. */
export interface InstructionData {
  programId: string;
  accounts: InstructionAccount[];
  data: Uint8Array;
}

/** A social-recovery authorization that was scheduled but not yet finalized. */
export interface PendingRecovery {
  /** Compressed SEC1 key the enclave authorized. */
  signerCompressed: Uint8Array;
  /** Unix seconds after which `finalize` is allowed (the on-chain timelock). */
  readyAt: number;
  /** Unix seconds after which it can no longer be finalized, and a new
   *  authorization may replace it. */
  expiresAt: number;
}

export interface SolanaAdapterOptions {
  /** Cavos device-account program id (defaults to the deployed one). */
  programId?: string;
  /** RPC connection for reads (`isAuthorizedSigner`) and nonce fetch. */
  connection?: Connection;
  /** Device signer used to authorize guarded actions. */
  signer?: DeviceSigner;
}

/**
 * Solana adapter for the Cavos device-signer account. Unlike Starknet (where the
 * account contract verifies the P-256 signature in `__validate__`), Solana
 * verifies it natively via the secp256r1 precompile, so every guarded action is
 * a two-instruction bundle: `[secp256r1 precompile ix, program ix]`. This adapter
 * derives the account PDA, builds those bundles, and reuses the same
 * `DeviceSigner` (P-256 / WebCrypto) as every other chain.
 */
export class SolanaAdapter {
  readonly chain = "solana" as const;
  readonly programId: PublicKey;

  constructor(private readonly opts: SolanaAdapterOptions = {}) {
    this.programId = new PublicKey(opts.programId ?? DEVICE_ACCOUNT_PROGRAM_ID);
  }

  /**
   * Account address: PDA of [ACCOUNT_SEED, namespace, initial_signer_x]. The
   * first device pubkey is in the seeds, so `initialize` with a different key
   * derives a different PDA and cannot claim this address.
   */
  computeAddress(namespace: Uint8Array, initialSigner: DevicePublicKey): string {
    return this.pda(namespace, initialSigner).toBase58();
  }

  private pda(namespace: Uint8Array, initialSigner: DevicePublicKey): PublicKey {
    // A PDA seed is capped at 32 bytes, so the 33-byte compressed key
    // contributes its X coordinate — exactly what the program re-derives.
    const compressed = compressedPubkey(initialSigner);
    const [pda] = PublicKey.findProgramAddressSync(
      [Buffer.from(ACCOUNT_SEED), Buffer.from(namespace), Buffer.from(compressed.slice(1, 33))],
      this.programId,
    );
    return pda;
  }

  socialRecoveryPda(account: string | PublicKey): PublicKey {
    const accountPk = typeof account === "string" ? new PublicKey(account) : account;
    return PublicKey.findProgramAddressSync(
      [Buffer.from(SOCIAL_RECOVERY_SEED), accountPk.toBuffer()],
      this.programId,
    )[0];
  }

  /**
   * `initialize` instruction: creates the account PDA and registers the first
   * device signer. The PDA seeds contain that signer, so this can only ever
   * create the account the caller's own key names.
   */
  buildInitialize(
    namespace: Uint8Array,
    payer: string,
    initialSigner: DevicePublicKey,
  ): TransactionInstruction[] {
    const initialCompressed = compressedPubkey(initialSigner);
    const account = this.pda(namespace, initialSigner);
    const data = Buffer.concat([
      anchorDiscriminator("initialize"),
      Buffer.from(namespace), // [u8;32] app_namespace
      Buffer.from(initialCompressed), // [u8;33]
    ]);
    const programIx = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: account, isSigner: false, isWritable: true },
        { pubkey: new PublicKey(payer), isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
    return [programIx];
  }

  /** `[precompile, add_signer]` bundle, authorized by an existing device signer. */
  async buildAddSigner(
    account: string,
    newSigner: DevicePublicKey
  ): Promise<TransactionInstruction[]> {
    const accountPk = new PublicKey(account);
    const newCompressed = compressedPubkey(newSigner);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_ADD),
      accountPk.toBuffer(),
      newCompressed,
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: this.guardedKeys(accountPk),
      data: Buffer.concat([anchorDiscriminator("add_signer"), Buffer.from(newCompressed)]),
    });
    return [precompileIx, ix];
  }

  /** `[precompile, remove_signer]` bundle, authorized by an existing device signer. */
  async buildRemoveSigner(
    account: string,
    signer: DevicePublicKey
  ): Promise<TransactionInstruction[]> {
    const accountPk = new PublicKey(account);
    const compressed = compressedPubkey(signer);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_REMOVE),
      accountPk.toBuffer(),
      compressed,
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: this.guardedKeys(accountPk),
      data: Buffer.concat([anchorDiscriminator("remove_signer"), Buffer.from(compressed)]),
    });
    return [precompileIx, ix];
  }

  /** `[precompile, add_approver]` bundle enrolling a passkey approver (device-signed). */
  async buildAddApprover(
    account: string,
    passkey: DevicePublicKey
  ): Promise<TransactionInstruction[]> {
    const accountPk = new PublicKey(account);
    const compressed = compressedPubkey(passkey);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_ADD_APPROVER),
      accountPk.toBuffer(),
      compressed,
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: this.guardedKeys(accountPk),
      data: Buffer.concat([anchorDiscriminator("add_approver"), Buffer.from(compressed)]),
    });
    return [precompileIx, ix];
  }

  /** `[precompile, remove_approver]` bundle (device-signed). */
  async buildRemoveApprover(
    account: string,
    passkey: DevicePublicKey
  ): Promise<TransactionInstruction[]> {
    const accountPk = new PublicKey(account);
    const compressed = compressedPubkey(passkey);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_REMOVE_APPROVER),
      accountPk.toBuffer(),
      compressed,
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: this.guardedKeys(accountPk),
      data: Buffer.concat([anchorDiscriminator("remove_approver"), Buffer.from(compressed)]),
    });
    return [precompileIx, ix];
  }

  /** Device-authorized enrolment of the dedicated TEE recovery key. */
  async buildEnrollSocialRecovery(
    account: string,
    payer: string,
    recoveryPubkeyCompressed: Uint8Array,
    delaySeconds: number,
    policyHash: Uint8Array,
  ): Promise<TransactionInstruction[]> {
    if (recoveryPubkeyCompressed.length !== 33 || policyHash.length !== 32) {
      throw new Error("kit/solana: invalid social recovery key or policy hash");
    }
    const accountPk = new PublicKey(account);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_ENROLL_SOCIAL),
      accountPk.toBuffer(),
      recoveryPubkeyCompressed,
      u32le(delaySeconds),
      policyHash,
      u64le(nonce),
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const recovery = this.socialRecoveryPda(accountPk);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: accountPk, isSigner: false, isWritable: true },
        { pubkey: recovery, isSigner: false, isWritable: true },
        { pubkey: new PublicKey(payer), isSigner: true, isWritable: true },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("enroll_social_recovery"),
        Buffer.from(recoveryPubkeyCompressed),
        u32le(delaySeconds),
        Buffer.from(policyHash),
      ]),
    });
    return [precompileIx, ix];
  }

  /** Read the nonce that the enclave must bind into a Solana authorization. */
  async socialRecoveryNonce(account: string): Promise<bigint> {
    const info = await this.requireConnection().getAccountInfo(
      this.socialRecoveryPda(account),
    );
    if (!info) throw new Error("kit/solana: social recovery is not enrolled");
    // discriminator + device_account + recovery_pubkey + delay + policy_hash
    return readU64le(info.data, 8 + 32 + 33 + 4 + 32);
  }

  /**
   * Read the pending social-recovery authorization, if any.
   *
   * `schedule_social_recovery` refuses to overwrite a pending authorization
   * until it has expired, so a run that scheduled but never finalized — a closed
   * tab, a relay error between the two calls — locks the account out of retrying
   * for the whole expiry window (an hour, by default). Reading the state first
   * lets the caller resume that authorization instead of trying to replace it.
   *
   * Layout after the 8-byte discriminator: device_account(32), recovery_pubkey
   * (33), delay_seconds(4), policy_hash(32), recovery_nonce(8), pending(1),
   * pending_signer(33), ready_at(8), expires_at(8).
   */
  async pendingSocialRecovery(account: string): Promise<PendingRecovery | null> {
    const info = await this.requireConnection().getAccountInfo(
      this.socialRecoveryPda(account),
    );
    if (!info) return null;
    const PENDING = 8 + 32 + 33 + 4 + 32 + 8;
    if (info.data[PENDING] !== 1) return null;
    const signerAt = PENDING + 1;
    return {
      signerCompressed: new Uint8Array(info.data.subarray(signerAt, signerAt + 33)),
      readyAt: readI64le(info.data, signerAt + 33),
      expiresAt: readI64le(info.data, signerAt + 41),
    };
  }

  /** Build `[P-256 precompile, schedule_social_recovery]` from the enclave's
   * exact signed message. No device signer is involved. */
  buildScheduleSocialRecovery(params: {
    account: string;
    newSigner: DevicePublicKey;
    expiresAt: number;
    message: Uint8Array;
    signature: Uint8Array;
    recoveryPubkeyCompressed: Uint8Array;
  }): TransactionInstruction[] {
    if (params.signature.length !== 64 || params.recoveryPubkeyCompressed.length !== 33) {
      throw new Error("kit/solana: malformed enclave authorization");
    }
    const accountPk = new PublicKey(params.account);
    const precompileIx = buildSecp256r1Instruction(
      params.recoveryPubkeyCompressed,
      params.signature,
      params.message,
    );
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: accountPk, isSigner: false, isWritable: true },
        {
          pubkey: this.socialRecoveryPda(accountPk),
          isSigner: false,
          isWritable: true,
        },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        anchorDiscriminator("schedule_social_recovery"),
        Buffer.from(compressedPubkey(params.newSigner)),
        i64le(params.expiresAt),
      ]),
    });
    return [precompileIx, ix];
  }

  buildFinalizeSocialRecovery(account: string): TransactionInstruction {
    const accountPk = new PublicKey(account);
    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: accountPk, isSigner: false, isWritable: true },
        {
          pubkey: this.socialRecoveryPda(accountPk),
          isSigner: false,
          isWritable: true,
        },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: anchorDiscriminator("finalize_social_recovery"),
    });
  }

  /** This chain's leaf for approving `add_signer(newSigner)` at `nonce`:
   * `sha256(compressed(new_signer) || passkey_nonce_le8)`. The batch challenge the
   * passkey signs is `sha256(concat(leaves))` across chains. */
  passkeyLeaf(newSigner: DevicePublicKey, nonce: bigint): Uint8Array {
    return sha256(concatBytes(compressedPubkey(newSigner), u64le(nonce)));
  }

  /**
   * `[precompile(passkey), add_signer_via_passkey]` bundle. The precompile ix
   * verifies the PASSKEY's WebAuthn assertion over `authData || sha256(clientDataJSON)`;
   * the program ix binds the challenge to `newSigner` + the passkey nonce and adds
   * the signer. No device signature — a gasless relayer can submit it.
   */
  buildAddSignerViaPasskey(
    account: string,
    newSigner: DevicePublicKey,
    passkey: DevicePublicKey,
    leaves: Uint8Array[],
    leafIndex: number,
    assertion: PasskeyAssertion
  ): TransactionInstruction[] {
    const accountPk = new PublicKey(account);
    const newCompressed = compressedPubkey(newSigner);
    const passkeyCompressed = compressedPubkey(passkey);

    // Precompile message = authData || sha256(clientDataJSON); the precompile
    // hashes it once → the WebAuthn signed digest.
    const clientHash = sha256(assertion.clientDataJSON);
    const message = concatBytes(assertion.authenticatorData, clientHash);
    const signature = encodeLowSSignature(assertion.r, assertion.s);
    const precompileIx = buildSecp256r1Instruction(passkeyCompressed, signature, message);

    // Borsh Vec<[u8; 32]> leaves: u32 len + len*32 bytes.
    const leavesBlob = Buffer.concat([u32le(leaves.length), ...leaves.map((l) => Buffer.from(l))]);
    const data = Buffer.concat([
      anchorDiscriminator("add_signer_via_passkey"),
      Buffer.from(newCompressed),
      leavesBlob,
      u32le(leafIndex),
      serializeVecU8(assertion.authenticatorData),
      serializeVecU8(assertion.clientDataJSON),
      u32le(assertion.challengeOffset),
    ]);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: this.guardedKeys(accountPk),
      data,
    });
    return [precompileIx, ix];
  }

  /** Read whether `passkey` is a registered approver. */
  /** True if the account has at least one passkey registered as an approver. */
  async hasPasskeyApprover(account: string): Promise<boolean> {
    const approvers = await this.fetchApprovers(new PublicKey(account));
    return approvers.length > 0;
  }

  async isApprover(account: string, passkey: DevicePublicKey): Promise<boolean> {
    const approvers = await this.fetchApprovers(new PublicKey(account));
    const target = Buffer.from(compressedPubkey(passkey)).toString("hex");
    return approvers.some((a) => Buffer.from(a).toString("hex") === target);
  }

  /** Read the current passkey-approval nonce. */
  async passkeyNonce(account: string): Promise<bigint> {
    const info = await this.requireConnection().getAccountInfo(new PublicKey(account));
    if (!isDeviceAccountData(info?.data)) return 0n;
    const d = info.data;
    const signersLenOff = 8 + 32 + 1 + 8 + COMPRESSED_PUBKEY_SIZE; // 82
    const signerCount = d.readUInt32LE(signersLenOff);
    const approversLenOff = signersLenOff + 4 + signerCount * COMPRESSED_PUBKEY_SIZE;
    const approverCount = d.readUInt32LE(approversLenOff);
    const passkeyNonceOff = approversLenOff + 4 + approverCount * COMPRESSED_PUBKEY_SIZE;
    return readU64le(d, passkeyNonceOff);
  }

  /** `[precompile, execute_transfer]` bundle moving lamports out of the account. */
  async buildExecuteTransfer(
    account: string,
    destination: string,
    amount: bigint
  ): Promise<TransactionInstruction[]> {
    const accountPk = new PublicKey(account);
    const destPk = new PublicKey(destination);
    const nonce = await this.fetchNonce(accountPk);
    const message = concatBytes(
      Buffer.from(DOMAIN_TRANSFER),
      accountPk.toBuffer(),
      destPk.toBuffer(),
      u64le(amount),
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: accountPk, isSigner: false, isWritable: true },
        { pubkey: destPk, isSigner: false, isWritable: true },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([anchorDiscriminator("execute_transfer"), u64le(amount)]),
    });
    return [precompileIx, ix];
  }

  /**
   * `[precompile, execute]` bundle running arbitrary CPI instructions with the
   * account PDA as signer. The device key signs over
   * `DOMAIN_EXECUTE || account || sha256(canonical(instructions)) || nonce`, so
   * the signature commits to the EXACT instruction set the program will invoke —
   * no account/data substitution is possible after signing.
   *
   * The instructions' accounts are passed to the program via `remaining_accounts`
   * (flattened, in order); the program enforces an exact, ordered mapping.
   */
  async buildExecute(
    account: string,
    instructions: InstructionData[]
  ): Promise<TransactionInstruction[]> {
    if (instructions.length === 0) throw new Error("kit/solana: execute requires at least one instruction");

    const accountPk = new PublicKey(account);
    const nonce = await this.fetchNonce(accountPk);

    // Canonical Borsh serialization MUST match the on-chain
    // `hash_instructions` (sha256 over the concatenated `InstructionData`).
    const blob = serializeInstructions(instructions);
    const ixsHash = sha256(blob);

    const message = concatBytes(
      Buffer.from(DOMAIN_EXECUTE),
      accountPk.toBuffer(),
      Buffer.from(ixsHash),
      u64le(nonce)
    );
    const { precompileIx } = await this.signToPrecompile(message);

    // The program ix carries the instructions in its data; the accounts they
    // reference are flattened into `remaining_accounts` in order. The wire format
    // is discriminator + Borsh Vec<u8>(blob) = discriminator + u32_len + blob.
    // The signed hash (above) is over the inner `blob` only — no length prefix —
    // matching the program's parse and the relay's allowlist parser.
    const blobLen = Buffer.alloc(4);
    new DataView(blobLen.buffer).setUint32(0, blob.length, true);
    const data = Buffer.concat([anchorDiscriminator("execute"), blobLen, blob]);
    const remainingAccounts: Array<{ pubkey: PublicKey; isSigner: false; isWritable: boolean }> = [];
    for (const ix of instructions) {
      for (const acc of ix.accounts) {
        remainingAccounts.push({
          pubkey: new PublicKey(acc.pubkey),
          isSigner: false, // signer flags are part of the signed InstructionData
          isWritable: acc.isWritable,
        });
      }
      // The CPI target program must be a remaining_account too — invoke_signed
      // needs it loaded. Appended (not part of the signed account list).
      remainingAccounts.push({
        pubkey: new PublicKey(ix.programId),
        isSigner: false,
        isWritable: false,
      });
    }
    const ix = new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: accountPk, isSigner: false, isWritable: true },
        { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
        ...remainingAccounts,
      ],
      data,
    });
    return [precompileIx, ix];
  }

  /** Read whether `signer` is currently an authorized signer of `account`. */
  async isAuthorizedSigner(account: string, signer: DevicePublicKey): Promise<boolean> {
    const signers = await this.fetchSigners(new PublicKey(account));
    const target = Buffer.from(compressedPubkey(signer)).toString("hex");
    return signers.some((s) => Buffer.from(s).toString("hex") === target);
  }

  private guardedKeys(account: PublicKey) {
    return [
      { pubkey: account, isSigner: false, isWritable: true },
      { pubkey: SYSVAR_INSTRUCTIONS_PUBKEY, isSigner: false, isWritable: false },
    ];
  }

  /** Sign `message` with the device key and build the matching precompile ix. */
  private async signToPrecompile(
    message: Uint8Array
  ): Promise<{ precompileIx: TransactionInstruction }> {
    if (!this.opts.signer) throw new Error("kit/solana: signer required to authorize");
    const pubkey = await this.opts.signer.getPublicKey();
    // The signer signs sha256(message); the precompile recomputes sha256(message).
    const sig = await this.opts.signer.sign(message as Uint8Array);
    const signature = encodeLowSSignature(sig.r, sig.s);
    const precompileIx = buildSecp256r1Instruction(
      compressedPubkey(pubkey),
      signature,
      message
    );
    return { precompileIx };
  }

  /**
   * Sign `message` with the device key WITHOUT building a precompile ix. Returns
   * the 64-byte low-S signature + the compressed pubkey. Used by
   * `CavosSolana.signMessage` (off-chain message) and `signTransaction` (the
   * device's contribution to a future relayed transaction).
   */
  async signRaw(message: Uint8Array): Promise<{ signature: Uint8Array; pubkey: Uint8Array }> {
    if (!this.opts.signer) throw new Error("kit/solana: signer required to sign");
    const pubkey = await this.opts.signer.getPublicKey();
    const sig = await this.opts.signer.sign(message);
    return { signature: encodeLowSSignature(sig.r, sig.s), pubkey: compressedPubkey(pubkey) };
  }

  /**
   * Build the domain-tagged transfer message the device signs (without building
   * the instructions). Used by `CavosSolana.signTransaction` to expose the
   * signed transfer message for a relayer to assemble.
   */
  async buildTransferMessage(
    account: string,
    destination: string,
    amount: bigint,
  ): Promise<Uint8Array> {
    const accountPk = new PublicKey(account);
    const destPk = new PublicKey(destination);
    const nonce = await this.fetchNonce(accountPk);
    return concatBytes(
      Buffer.from(DOMAIN_TRANSFER),
      accountPk.toBuffer(),
      destPk.toBuffer(),
      u64le(amount),
      u64le(nonce),
    );
  }

  private async fetchNonce(account: PublicKey): Promise<bigint> {
    const info = await this.requireConnection().getAccountInfo(account);
    if (!isDeviceAccountData(info?.data)) return 0n;
    // layout: 8 disc + 32 address_seed + 1 bump + 8 nonce(LE) + 33 initial_signer + ...
    // nonce is right after bump, so its offset is unaffected by initial_signer.
    return readU64le(info.data, 41);
  }

  private async fetchSigners(account: PublicKey): Promise<Uint8Array[]> {
    const info = await this.requireConnection().getAccountInfo(account);
    if (!isDeviceAccountData(info?.data)) return [];
    const d = info.data;
    // layout: 8 disc + 32 address_seed + 1 bump + 8 nonce + 33 initial_signer + 4 vec_len + signers
    const lenOffset = 8 + 32 + 1 + 8 + COMPRESSED_PUBKEY_SIZE; // = 82
    const count = d.readUInt32LE(lenOffset);
    const out: Uint8Array[] = [];
    let off = lenOffset + 4;
    for (let i = 0; i < count; i++) {
      out.push(Uint8Array.from(d.subarray(off, off + COMPRESSED_PUBKEY_SIZE)));
      off += COMPRESSED_PUBKEY_SIZE;
    }
    return out;
  }

  private async fetchApprovers(account: PublicKey): Promise<Uint8Array[]> {
    const info = await this.requireConnection().getAccountInfo(account);
    if (!isDeviceAccountData(info?.data)) return [];
    const d = info.data;
    const signersLenOff = 8 + 32 + 1 + 8 + COMPRESSED_PUBKEY_SIZE; // 82
    const signerCount = d.readUInt32LE(signersLenOff);
    const approversLenOff = signersLenOff + 4 + signerCount * COMPRESSED_PUBKEY_SIZE;
    const count = d.readUInt32LE(approversLenOff);
    const out: Uint8Array[] = [];
    let off = approversLenOff + 4;
    for (let i = 0; i < count; i++) {
      out.push(Uint8Array.from(d.subarray(off, off + COMPRESSED_PUBKEY_SIZE)));
      off += COMPRESSED_PUBKEY_SIZE;
    }
    return out;
  }

  private requireConnection(): Connection {
    if (!this.opts.connection) throw new Error("kit/solana: connection required for reads");
    return this.opts.connection;
  }
}

/** Compressed SEC1 P-256 pubkey (33 bytes) from {x, y}. */
export function compressedPubkey(pk: DevicePublicKey): Uint8Array {
  const out = new Uint8Array(COMPRESSED_PUBKEY_SIZE);
  out[0] = pk.y % 2n === 0n ? 0x02 : 0x03;
  out.set(bigIntTo32Bytes(pk.x), 1);
  return out;
}

/** Encode (r, s) as raw 64-byte r‖s, normalized to low-S (precompile requires it). */
export function encodeLowSSignature(r: bigint, s: bigint): Uint8Array {
  const lowS = s > SECP256R1_N / 2n ? SECP256R1_N - s : s;
  const out = new Uint8Array(SIGNATURE_SIZE);
  out.set(bigIntTo32Bytes(r), 0);
  out.set(bigIntTo32Bytes(lowS), 32);
  return out;
}

/** Build the native secp256r1 precompile instruction (single self-contained sig). */
export function buildSecp256r1Instruction(
  compressed: Uint8Array,
  signature: Uint8Array,
  message: Uint8Array
): TransactionInstruction {
  const headerLen = 2;
  const offsetsLen = 14;
  const pubkeyOffset = headerLen + offsetsLen;
  const sigOffset = pubkeyOffset + COMPRESSED_PUBKEY_SIZE;
  const msgOffset = sigOffset + SIGNATURE_SIZE;
  const data = Buffer.alloc(msgOffset + message.length);

  data.writeUInt8(1, 0);
  data.writeUInt8(0, 1);
  let o = headerLen;
  data.writeUInt16LE(sigOffset, o); o += 2;
  data.writeUInt16LE(CURRENT_IX, o); o += 2;
  data.writeUInt16LE(pubkeyOffset, o); o += 2;
  data.writeUInt16LE(CURRENT_IX, o); o += 2;
  data.writeUInt16LE(msgOffset, o); o += 2;
  data.writeUInt16LE(message.length, o); o += 2;
  data.writeUInt16LE(CURRENT_IX, o); o += 2;
  Buffer.from(compressed).copy(data, pubkeyOffset);
  Buffer.from(signature).copy(data, sigOffset);
  Buffer.from(message).copy(data, msgOffset);

  return new TransactionInstruction({
    keys: [],
    programId: new PublicKey(SECP256R1_PROGRAM_ID),
    data,
  });
}

/** Anchor instruction discriminator = sha256("global:<name>")[..8]. */
export function anchorDiscriminator(name: string): Buffer {
  return Buffer.from(sha256(`global:${name}`).slice(0, 8));
}

function u32le(n: number): Buffer {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(n);
  return b;
}

function u64le(n: bigint | number): Buffer {
  const b = Buffer.alloc(8);
  // Avoid Buffer.writeBigUInt64LE: the browser `buffer` polyfill doesn't
  // implement the BigInt methods. Use DataView instead.
  new DataView(b.buffer, b.byteOffset, 8).setBigUint64(0, BigInt(n), true);
  return b;
}

function i64le(n: bigint | number): Buffer {
  const b = Buffer.alloc(8);
  new DataView(b.buffer, b.byteOffset, 8).setBigInt64(0, BigInt(n), true);
  return b;
}

/**
 * Whether this is one of our device accounts, rather than any account that
 * happens to live at the address.
 *
 * An address the program has not created can still exist -- funded by an
 * airdrop or a transfer, it is a system account holding lamports and no data.
 * The readers took the account's existence as proof of the layout and read
 * straight past the end of it, so connect died on `Trying to access beyond
 * buffer length` and the whole session failed to come back, for a wallet whose
 * only sin was having been sent some SOL.
 */
function isDeviceAccountData(data: Buffer | undefined): data is Buffer {
  return !!data && data.length >= DEVICE_ACCOUNT_HEADER + 4;
}

function readU64le(buf: Buffer, offset: number): bigint {
  return new DataView(buf.buffer, buf.byteOffset, buf.length).getBigUint64(
    offset,
    true,
  );
}

/** Signed 64-bit read, for the unix timestamps in the recovery config. */
function readI64le(buf: Buffer, offset: number): number {
  return Number(
    new DataView(buf.buffer, buf.byteOffset, buf.length).getBigInt64(offset, true),
  );
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// ─── Canonical Borsh serialization for `execute` ────────────────────────────
// MUST match the on-chain `InstructionData`/`AccountMetaCandidate` AnchorSer
// layout byte-for-byte: `hash_instructions` hashes this and the program
// requires the precompile-verified message to commit to the same hash. Changing
// the byte layout here breaks signature binding (and recovery of past sigs).

/** Serialize a single `InstructionData` exactly as Anchor's Borsh derive would. */
function serializeInstruction(ix: InstructionData): Buffer {
  const programId = new PublicKey(ix.programId).toBuffer(); // 32 bytes
  const accounts = serializeAccounts(ix.accounts);
  const data = serializeVecU8(ix.data);
  return Buffer.concat([programId, accounts, data]);
}

function serializeAccounts(metas: InstructionAccount[]): Buffer {
  const len = Buffer.alloc(4);
  new DataView(len.buffer).setUint32(0, metas.length, true);
  const parts = metas.map(serializeAccountMeta);
  return Buffer.concat([len, ...parts]);
}

function serializeAccountMeta(meta: InstructionAccount): Buffer {
  const pubkey = new PublicKey(meta.pubkey).toBuffer(); // 32 bytes
  return Buffer.concat([pubkey, Buffer.from([meta.isSigner ? 1 : 0, meta.isWritable ? 1 : 0])]);
}

function serializeVecU8(data: Uint8Array): Buffer {
  const len = Buffer.alloc(4);
  new DataView(len.buffer).setUint32(0, data.length, true);
  return Buffer.concat([len, Buffer.from(data)]);
}

/** Serialize the full instruction set — the bytes `hash_instructions` hashes. */
export function serializeInstructions(instructions: InstructionData[]): Buffer {
  return Buffer.concat(instructions.map(serializeInstruction));
}
