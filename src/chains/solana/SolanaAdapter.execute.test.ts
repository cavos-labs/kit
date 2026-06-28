import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { PublicKey } from "@solana/web3.js";
import {
  SolanaAdapter,
  serializeInstructions,
  compressedPubkey,
} from "./SolanaAdapter";
import { DOMAIN_EXECUTE } from "./constants";
import { bytesToBigInt, bigIntTo32Bytes } from "../../crypto/encoding";
import type { DevicePublicKey, DeviceSigner } from "../../signer/DeviceSigner";

function mockConnection(): any {
  const info = { data: Buffer.alloc(8 + 32 + 1 + 8 + 33 + 4 + 8 * 33) }; // nonce 0
  return { getAccountInfo: async () => info };
}

describe("SolanaAdapter.buildExecute — arbitrary CPI", () => {
  const connection = mockConnection();

  it("serializes instructions in canonical Borsh matching the on-chain layout", () => {
    const ixs = [
      {
        programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", // SPL Token
        accounts: [
          { pubkey: "11111111111111111111111111111111", isSigner: false, isWritable: true },
          { pubkey: "22dddddddddddddddddddddddddddddddddddddddddd", isSigner: false, isWritable: true },
          { pubkey: "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ", isSigner: false, isWritable: false },
        ],
        data: new Uint8Array([1, 2, 3, 4]),
      },
    ];
    const blob = serializeInstructions(ixs);
    // Expected layout: pubkey(32) + accounts(vec: u32 len + 3*(pubkey32+2)) + data(vec: u32 len + 4)
    const expectedLen = 32 + (4 + 3 * (32 + 2)) + (4 + 4);
    expect(blob.length).toBe(expectedLen);

    // First 32 bytes = program id (canonical pubkey bytes).
    expect(blob.subarray(0, 32)).toEqual(new PublicKey(ixs[0].programId).toBuffer());
    // accounts vec length = 3 (u32 LE).
    expect(new DataView(blob.buffer, blob.byteOffset + 32, 4).getUint32(0, true)).toBe(3);
    // first account is_signer byte = 0.
    expect(blob[32 + 4 + 32]).toBe(0);
  });

  it("builds an execute bundle whose signed message commits to sha256(instructions)", async () => {
    // A deterministic device signer so we can recompute the signature check.
    const priv = p256.utils.randomPrivateKey();
    const pub: DevicePublicKey = {
      x: bytesToBigInt(p256.getPublicKey(priv, false).slice(1, 33)),
      y: bytesToBigInt(p256.getPublicKey(priv, false).slice(33, 65)),
    };
    const signer: DeviceSigner = {
      getPublicKey: async () => pub,
      sign: async (m: Uint8Array) => {
        const sig = p256.sign(sha256(m), priv, { lowS: true });
        return { r: sig.r, s: sig.s, yParity: false };
      },
    };
    const adapter = new SolanaAdapter({ connection, signer });

    const account = "FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ";
    const ixs = [
      {
        programId: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
        accounts: [
          { pubkey: "11111111111111111111111111111111", isSigner: false, isWritable: true },
          { pubkey: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", isSigner: false, isWritable: true },
          { pubkey: account, isSigner: false, isWritable: false },
        ],
        data: new Uint8Array([1, 2, 3]),
      },
    ];

    const [precompileIx, executeIx] = await adapter.buildExecute(account, ixs);

    // Program instruction is `execute` with the anchor discriminator.
    const disc = Buffer.from(sha256("global:execute").slice(0, 8));
    expect(executeIx.data.subarray(0, 8)).toEqual(disc);

    // remaining_accounts = flattened instruction accounts (3 here).
    // remaining_accounts = flattened instruction accounts (3) + the CPI program
    // account (1, needed by invoke_signed). Plus account + sysvar = 6.
    expect(executeIx.keys.length).toBe(2 + 4);

    // Reconstruct the signed message from the precompile ix.
    const d = precompileIx.data as Buffer;
    const msgOff = d.readUInt16LE(2 + 8);
    const msgLen = d.readUInt16LE(2 + 10);
    const msg = d.subarray(msgOff, msgOff + msgLen);

    const ixsHash = sha256(serializeInstructions(ixs));
    const expected = Buffer.concat([
      Buffer.from(DOMAIN_EXECUTE),
      new PublicKey(account).toBuffer(),
      Buffer.from(ixsHash),
      u64le(0n),
    ]);
    expect(Buffer.from(msg)).toEqual(expected);

    // Signature verifies under the device pubkey over sha256(message).
    const sigOff = d.readUInt16LE(2);
    const sigBytes = d.subarray(sigOff, sigOff + 64);
    const r = bytesToBigInt(sigBytes.subarray(0, 32));
    const s = bytesToBigInt(sigBytes.subarray(32, 64));
    const pubUncompressed = Buffer.concat([
      Buffer.from([0x04]),
      bigIntTo32Bytes(pub.x),
      bigIntTo32Bytes(pub.y),
    ]);
    expect(p256.verify({ r, s }, sha256(msg), pubUncompressed)).toBe(true);
  });

  it("rejects an empty instruction set", async () => {
    const priv = p256.utils.randomPrivateKey();
    const signer: DeviceSigner = {
      getPublicKey: async () => ({
        x: bytesToBigInt(p256.getPublicKey(priv, false).slice(1, 33)),
        y: bytesToBigInt(p256.getPublicKey(priv, false).slice(33, 65)),
      }),
      sign: async (m: Uint8Array) => {
        const sig = p256.sign(sha256(m), priv, { lowS: true });
        return { r: sig.r, s: sig.s, yParity: false };
      },
    };
    const adapter = new SolanaAdapter({ connection, signer });
    await expect(
      adapter.buildExecute("FHnoYNfYAmFrwt18gcBGG7G1S5q3RAbCBvrV2D29izNJ", []),
    ).rejects.toThrow(/at least one instruction/);
  });
});

function u64le(n: bigint): Buffer {
  const b = Buffer.alloc(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}
