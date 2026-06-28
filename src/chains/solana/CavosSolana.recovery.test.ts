import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { PublicKey, SYSVAR_INSTRUCTIONS_PUBKEY } from "@solana/web3.js";
import { SolanaAdapter, compressedPubkey, anchorDiscriminator } from "./SolanaAdapter";
import { DOMAIN_ADD } from "./constants";
import { BackupSigner, deriveBackupKey, generateRecoveryCode } from "../../recovery/BackupSigner";
import { bytesToBigInt, bigIntTo32Bytes } from "../../crypto/encoding";
import type { DevicePublicKey } from "../../signer/DeviceSigner";

function devicePubkey(priv: Uint8Array): DevicePublicKey {
  const uncompressed = p256.getPublicKey(priv, false); // 0x04 || x || y
  return {
    x: bytesToBigInt(uncompressed.slice(1, 33)),
    y: bytesToBigInt(uncompressed.slice(33, 65)),
  };
}

/** Minimal Connection stub: returns a fixed nonce (0) and an empty signers vec
 *  so fetchNonce/fetchSigners don't need a live RPC. The adapter only reads the
 *  account info for those two fields. */
function mockConnection(): any {
  const info = { data: Buffer.alloc(8 + 32 + 1 + 8 + 33 + 4 + 8 * 33) };
  // nonce at offset 41 is already 0 (Buffer.alloc zero-fills); vec len at 82 is 0.
  return {
    getAccountInfo: async () => info,
  };
}

describe("CavosSolana recovery — backup-signed add_signer", () => {
  const connection = mockConnection();

  it("derives the SAME backup key from the same code (determinism across devices)", () => {
    const code = generateRecoveryCode();
    const a = deriveBackupKey(code);
    const b = deriveBackupKey(code);
    expect(a.privateKey).toEqual(b.privateKey);
    expect(a.publicKey).toEqual(b.publicKey);
  });

  it("builds an add_signer bundle whose precompile signature verifies under the BACKUP key", async () => {
    const code = generateRecoveryCode();
    const backup = BackupSigner.fromCode(code);
    const backupPubkey = await backup.getPublicKey();
    const backupCompressed = compressedPubkey(backupPubkey);

    // The adapter is constructed with the BACKUP signer (recovery path), so the
    // bundle it builds must be authorized by the backup key — exactly what an
    // on-chain `add_signer` requires to admit the new device.
    const adapter = new SolanaAdapter({ connection, signer: backup });

    const account = new PublicKey(
      "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ"
    ).toBase58();
    const newDevice = devicePubkey(p256.utils.randomPrivateKey());
    const [precompileIx, addIx] = await adapter.buildAddSigner(account, newDevice);

    // The program instruction is add_signer with the anchor discriminator.
    expect(addIx.programId.toBase58()).toBe(
      "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ"
    );
    expect(addIx.data.subarray(0, 8)).toEqual(anchorDiscriminator("add_signer"));
    expect(addIx.keys[0].pubkey.equals(new PublicKey(account))).toBe(true);
    expect(addIx.keys[1].pubkey.equals(SYSVAR_INSTRUCTIONS_PUBKEY)).toBe(true);

    // Reconstruct the signed message from the precompile ix and verify it under
    // the backup pubkey — this is the core invariant of recovery.
    const preData = precompileIx.data as Buffer;
    // layout: [1 num_sigs][1 pad][14 offsets][33 pubkey][64 sig][N msg]
    const msgOffset = preData.readUInt16LE(2 + 8);
    const msgLen = preData.readUInt16LE(2 + 10);
    const msg = preData.subarray(msgOffset, msgOffset + msgLen);
    const sigOff = preData.readUInt16LE(2);
    const sigBytes = preData.subarray(sigOff, sigOff + 64);

    // Message must be DOMAIN_ADD || account || newCompressed || nonce(0).
    const newCompressed = compressedPubkey(newDevice);
    const expected = Buffer.concat([
      Buffer.from(DOMAIN_ADD),
      new PublicKey(account).toBuffer(),
      Buffer.from(newCompressed),
      u64le(0n),
    ]);
    expect(Buffer.from(msg)).toEqual(expected);

    // And the signature verifies under the backup pubkey over sha256(message).
    const r = bytesToBigInt(sigBytes.subarray(0, 32));
    const s = bytesToBigInt(sigBytes.subarray(32, 64));
    // Rebuild the uncompressed pubkey from {x,y} (noble expects 0x04||x||y).
    const backupUncompressed = Buffer.concat([
      Buffer.from([0x04]),
      bigIntTo32Bytes(backupPubkey.x),
      bigIntTo32Bytes(backupPubkey.y),
    ]);
    const ok = p256.verify({ r, s }, sha256(msg), backupUncompressed);
    expect(ok).toBe(true);
  });

  it("the device-key adapter and backup-key adapter sign the SAME message under DIFFERENT keys", async () => {
    // A normal device signer.
    const devicePriv = p256.utils.randomPrivateKey();
    const deviceSigner = {
      getPublicKey: async () => devicePubkey(devicePriv),
      sign: async (m: Uint8Array) => {
        const sig = p256.sign(sha256(m), devicePriv, { lowS: true });
        return { r: sig.r, s: sig.s, yParity: false };
      },
    };
    // A backup signer.
    const backup = BackupSigner.fromCode(generateRecoveryCode());

    const account = "11111111111111111111111111111111";
    const newDevice = devicePubkey(p256.utils.randomPrivateKey());

    const deviceAdapter = new SolanaAdapter({ connection, signer: deviceSigner as any });
    const backupAdapter = new SolanaAdapter({ connection, signer: backup });

    const [devicePre] = await deviceAdapter.buildAddSigner(account, newDevice);
    const [backupPre] = await backupAdapter.buildAddSigner(account, newDevice);

    // Same signed message (same action), but verified under different pubkeys.
    const readMsg = (ix: any) => {
      const d = ix.data as Buffer;
      const off = d.readUInt16LE(2 + 8);
      const len = d.readUInt16LE(2 + 10);
      return d.subarray(off, off + len);
    };
    const mDevice = readMsg(devicePre);
    const mBackup = readMsg(backupPre);
    expect(Buffer.from(mDevice)).toEqual(Buffer.from(mBackup));
    // But the pubkeys embedded differ:
    const readPk = (ix: any) => {
      const d = ix.data as Buffer;
      const off = d.readUInt16LE(2 + 4);
      return d.subarray(off, off + 33);
    };
    expect(Buffer.from(readPk(devicePre))).not.toEqual(Buffer.from(readPk(backupPre)));
  });
});

/** u64le of n as an 8-byte LE buffer (nonce helper for the expected message). */
function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}
