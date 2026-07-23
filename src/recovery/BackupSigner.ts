import { p256 } from "@noble/curves/p256";
import { hkdf } from "@noble/hashes/hkdf";
import { pbkdf2 } from "@noble/hashes/pbkdf2";
import { sha256 } from "@noble/hashes/sha256";
import { randomBytes } from "@noble/hashes/utils";
import type { DeviceSigner, DevicePublicKey, DeviceSignature } from "../signer/DeviceSigner";
import { bytesToBigInt, bigIntTo32Bytes, utf8ToBytes } from "../crypto/encoding";
import { recoverYParity } from "../crypto/signature";

/**
 * Self-custodial account recovery via a backup signer derived from a code.
 *
 * The user generates a human-readable recovery code once (see
 * `generateRecoveryCode`). That code is stretched with PBKDF2 + HKDF into a
 * deterministic secp256r1 private key — the SAME key on every device that
 * enters the SAME code. The code never leaves the device: the backend and the
 * chain only ever see the derived public key, which is registered on-chain as
 * an ordinary signer via `add_signer`. Recovering access after losing every
 * device is therefore: enter the code → re-derive the backup key → sign an
 * `add_signer` for the new device. No guardian, no timelock, no custodial key.
 *
 * This module is intentionally chain-agnostic and free of WebCrypto/DOM calls:
 * the derivation is pure `@noble/*` math, so the identical code runs in the
 * browser, React Native, and (eventually) Solana / Stellar / EVM adapters.
 */

/** Fixed domain-separation salt for `deriveBackupKey`. Bumped only to re-derive
 *  a new key space (e.g. changing the KDF parameters). Never per-user. */
const BACKUP_KDF_SALT = "cavos-recovery-v1";
/** PBKDF2 iteration count. High enough to make brute-forcing a strong code
 *  infeasible, low enough that derivation stays well under a second. */
const BACKUP_PBKDF2_ITERATIONS = 210_000;
/** HKDF info string, scopes the derived material to "backup-signer". */
const BACKUP_HKDF_INFO = "cavos-backup-signer";

/** How many words make up a recovery code. 16 words @ 8 bits/word = 128 bits. */
const CODE_WORDS = 16;

/**
 * Generate a fresh, human-readable recovery code. The caller MUST present this
 * to the user exactly once and never persist it server-side. ~128 bits of
 * entropy encoded as words from a fixed wordlist (BIP39-style but our own list,
 * so we don't pull a dependency on a BIP39 wordfile).
 */
export function generateRecoveryCode(): string {
  const bytes = randomBytes(CODE_WORDS);
  const words: string[] = [];
  for (const b of bytes) words.push(WORDLIST[b]);
  return words.join(" ");
}

/**
 * Deterministically derive a secp256r1 keypair from a recovery code. Pure
 * function: the same normalised code always yields the same keypair, on any
 * runtime. Returns the raw 32-byte private key (so it can be wrapped in a
 * `BackupSigner` or fed to any chain adapter) plus the public key coordinates
 * the contract stores as an authorised signer.
 *
 * Normalisation trims surrounding whitespace and collapses runs of spaces, so
 * "a  b" and "a b" derive the same key regardless of how the code was pasted.
 */
export function deriveBackupKey(code: string): {
  privateKey: Uint8Array;
  publicKey: DevicePublicKey;
} {
  const normalised = code.trim().replace(/\s+/g, " ").toLowerCase();
  if (!normalised) throw new Error("kit: recovery code is empty");

  // Stretch the low-entropy-ish human code into 32 bytes with PBKDF2, then mix
  // into a scoped seed with HKDF. PBKDF2 also serves as the brute-force brake.
  const stretched = pbkdf2(
    sha256,
    utf8ToBytes(normalised),
    utf8ToBytes(BACKUP_KDF_SALT),
    { c: BACKUP_PBKDF2_ITERATIONS, dkLen: 32 },
  );
  const seed = hkdf(sha256, stretched, undefined, BACKUP_HKDF_INFO, 32);

  // Reduce the seed to a valid secp256r1 scalar. The seed is 32 bytes (< n with
  // overwhelming probability); reducing mod n keeps it a valid private key
  // without bias that matters in practice for an HMAC-stretched 256-bit input.
  const d = bytesToBigInt(seed) % p256.CURVE.n;
  if (d === 0n) throw new Error("kit: derived backup key is zero (retry with a new code)");

  const priv = bigIntTo32Bytes(d);
  // isCompressed = false → uncompressed point (0x04 || X || Y, 65 bytes), so the
  // X/Y split below is correct. The default would return a 33-byte compressed
  // point and the Y half would be empty.
  const pub = p256.getPublicKey(priv, false);
  return {
    privateKey: priv,
    publicKey: { x: bytesToBigInt(pub.subarray(1, 33)), y: bytesToBigInt(pub.subarray(33, 65)) },
  };
}

/**
 * A `DeviceSigner` backed by an in-memory backup key derived from a recovery
 * code. Used transiently during recovery to sign the `add_signer` that
 * authorises a new device — it is NOT persisted and should not be reused as a
 * device signer. The key material lives only for the duration of the recovery
 * transaction.
 */
export class BackupSigner implements DeviceSigner {
  private readonly privateKey: Uint8Array;
  private readonly publicKeyValue: DevicePublicKey;

  constructor(privateKey: Uint8Array, publicKey: DevicePublicKey) {
    this.privateKey = privateKey;
    this.publicKeyValue = publicKey;
  }

  /** Build a signer from a recovery code (derive + wrap in one step). */
  static fromCode(code: string): BackupSigner {
    const { privateKey, publicKey } = deriveBackupKey(code);
    return new BackupSigner(privateKey, publicKey);
  }

  async getPublicKey(): Promise<DevicePublicKey> {
    return this.publicKeyValue;
  }

  async sign(txHash: Uint8Array): Promise<DeviceSignature> {
    // Mirror the WebCrypto path exactly: WebCrypto's `subtle.sign({ hash:
    // 'SHA-256' }, key, txHash)` hashes `txHash` with SHA-256 and signs the
    // digest. `p256.sign(msgHash)` signs the bytes it's given WITHOUT hashing,
    // so we pre-hash here to produce the same (r, s) the contract verifies.
    const digest = sha256(txHash);
    const sig = p256.sign(digest, this.privateKey);
    const yParity = recoverYParity(sig.r, sig.s, digest, this.publicKeyValue);
    return { r: sig.r, s: sig.s, yParity };
  }
}

// 256 short, unambiguous, lowercase English words. Chosen to be hard to
// misread and easy to type; not the full BIP39 list (we don't need 2048 — 8
// bits/word is plenty at 16 words). Keep this list stable: changing it changes
// the meaning of every existing recovery code. Must stay exactly 256 unique
// entries so each byte value maps to one word.
const WORDLIST = [
  "able", "acid", "amber", "apple", "arch", "arrow", "ashen", "atlas",
  "axis", "badge", "baker", "balm", "banner", "basin", "beacon", "bench",
  "beryl", "birch", "blade", "bloom", "bluer", "border", "brave", "brick",
  "brook", "cabin", "candle", "carbon", "cargo", "cedar", "chalk", "charm",
  "chrome", "cipher", "clam", "clasp", "cliff", "clock", "cobia", "comet",
  "coral", "cotton", "coves", "crane", "crest", "crow", "crystal", "curio",
  "dawn", "delta", "denim", "depth", "dewy", "digger", "docks", "dover",
  "drift", "dunes", "eagle", "ember", "echo", "eden", "elite", "ethic",
  "fable", "falcon", "fawn", "feather", "fern", "fjord", "flame", "flint",
  "forest", "forge", "frost", "garnet", "gemini", "glade", "glider", "glow",
  "granite", "grove", "guppy", "harbor", "haven", "hazel", "helio", "heron",
  "hickory", "honey", "horizon", "ivory", "jade", "jasper", "kestrel", "knot",
  "lagoon", "lattice", "laurel", "lavender", "lemon", "linden", "loon", "luger",
  "lumen", "lunar", "mango", "maple", "marble", "marsh", "meadow", "mercy",
  "mistle", "monsoon", "morning", "moss", "nacre", "nectar", "needle", "nimbus",
  "nova", "ocean", "onyx", "orbit", "otter", "palm", "panda", "pansy",
  "papaya", "passage", "pebble", "pelican", "pepper", "petal", "piano", "pierce",
  "pilot", "pioneer", "platinum", "plume", "poplar", "porpoise", "prairie", "prism",
  "pulsar", "quartz", "quasar", "quill", "quiver", "raven", "reef", "relic",
  "ridge", "ripple", "robin", "rocket", "rouge", "ruby", "saffron", "sage",
  "sail", "salmon", "sapphire", "scarab", "shadow", "shale", "sienna", "silica",
  "silver", "skyline", "slate", "sonar", "spruce", "starling", "stone", "sugar",
  "summit", "sunset", "swan", "tangent", "tarragon", "temple", "thistle", "thrush",
  "tiger", "topaz", "tundra", "turtle", "umber", "union", "valley", "vapor",
  "vector", "velvet", "violet", "vortex", "walnut", "whale", "winter", "wisp",
  "wisteria", "xenon", "yarrow", "zephyr", "zinc", "zodiac", "anchor", "basil",
  "cider", "daisy", "elfin", "ferry", "gimlet", "halcyon", "indigo", "juniper",
  "kindle", "lilac", "mantis", "nylon", "oracle", "parch", "quokka", "ramble",
  "thatch", "ultra", "vivid", "xylo", "yodel", "zesty", "arbor", "bliss",
  "calyx", "dwindle", "folio", "globe", "hymn", "ionic", "jolly", "knack",
  "lyric", "myrtle", "noble", "plumb", "quaint", "rustic", "satin", "timber",
  "urge", "vault", "whimsy", "yearn", "zenith", "ash", "beach", "dusk",
];
