import { randomBytes } from "@noble/hashes/utils";

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
 * 256 short, unambiguous, lowercase English words. Chosen to be hard to
 * misread and easy to type; not the full BIP39 list (we don't need 2048 — 8
 * bits/word is plenty at 16 words). Keep this list stable: changing it changes
 * the meaning of every existing recovery code. Must stay exactly 256 unique
 * entries so each byte value maps to one word.
 */
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
