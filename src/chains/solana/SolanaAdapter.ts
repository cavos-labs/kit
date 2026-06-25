import {
  Connection,
  PublicKey,
  SystemProgram,
  SYSVAR_INSTRUCTIONS_PUBKEY,
  TransactionInstruction,
} from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha256";
import type { DeviceSigner, DevicePublicKey } from "../../signer/DeviceSigner";
import { bigIntTo32Bytes } from "../../crypto/encoding";
import {
  ACCOUNT_SEED,
  DEVICE_ACCOUNT_PROGRAM_ID,
  DOMAIN_ADD,
  DOMAIN_REMOVE,
  DOMAIN_TRANSFER,
  SECP256R1_N,
  SECP256R1_PROGRAM_ID,
} from "./constants";

const COMPRESSED_PUBKEY_SIZE = 33;
const SIGNATURE_SIZE = 64;
const CURRENT_IX = 0xffff;

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

  /** Deterministic account address: PDA of [seed, address_seed, initial_signer_x]. */
  computeAddress(addressSeed: Uint8Array, initialSigner: DevicePublicKey): string {
    return this.pda(addressSeed, compressedPubkey(initialSigner)).toBase58();
  }

  private pda(addressSeed: Uint8Array, initialCompressed: Uint8Array): PublicKey {
    const [pda] = PublicKey.findProgramAddressSync(
      [
        Buffer.from(ACCOUNT_SEED),
        Buffer.from(addressSeed),
        Buffer.from(initialCompressed.slice(1, 33)), // x-coordinate
      ],
      this.programId
    );
    return pda;
  }

  /** `initialize` instruction creating the account with its first device signer. */
  buildInitialize(
    addressSeed: Uint8Array,
    payer: string,
    initialSigner: DevicePublicKey
  ): TransactionInstruction {
    const initialCompressed = compressedPubkey(initialSigner);
    const account = this.pda(addressSeed, initialCompressed);
    const data = Buffer.concat([
      anchorDiscriminator("initialize"),
      Buffer.from(addressSeed), // [u8;32]
      Buffer.from(initialCompressed), // [u8;33]
    ]);
    return new TransactionInstruction({
      programId: this.programId,
      keys: [
        { pubkey: account, isSigner: false, isWritable: true },
        { pubkey: new PublicKey(payer), isSigner: true, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data,
    });
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

  private async fetchNonce(account: PublicKey): Promise<bigint> {
    const info = await this.requireConnection().getAccountInfo(account);
    if (!info) return 0n;
    // layout: 8 disc + 32 address_seed + 1 bump + 8 nonce(LE) ...
    return readU64le(info.data, 41);
  }

  private async fetchSigners(account: PublicKey): Promise<Uint8Array[]> {
    const info = await this.requireConnection().getAccountInfo(account);
    if (!info) return [];
    const d = info.data;
    const lenOffset = 8 + 32 + 1 + 8; // = 49
    const count = d.readUInt32LE(lenOffset);
    const out: Uint8Array[] = [];
    let off = lenOffset + 4;
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

function u64le(n: bigint | number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(BigInt(n));
  return b;
}

function readU64le(buf: Buffer, offset: number): bigint {
  return buf.readBigUInt64LE(offset);
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
