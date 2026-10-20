/** Who pays the privacy pool fee, and in what, as the paymaster spells it. */
export type PrivacyFeeMode =
  | { mode: "sponsored"; pool_fee: { paid_by: "user"; token: string } }
  | { mode: "sponsored"; pool_fee: { paid_by: "sponsor" } }
  | { mode: "default"; gas_token: string };

export interface PrivacyRelayConfig {
  /** Paymaster that submits private transactions, so the account never appears on-chain. */
  url: string;
  fee: PrivacyFeeMode;
  /** Ceiling for a fee the relay asks for, in base units of the fee token. */
  maxFee: string;
  /** The only addresses a fee may be sent to. Also the only callers a signed relay call may name. */
  allowedFeeRecipients: string[];
}

/**
 * Everything the page must not choose: the pool, the services that see the
 * viewing key, and who is paid. In a vault it comes from the app's Cavos
 * settings, keyed by network ("sepolia", "mainnet").
 */
export interface StarknetPrivacyConfig {
  pool: string;
  prover: string;
  discovery: string;
  /** Encrypt requests to the prover and discovery service so they cannot read the viewing key. Defaults to true. */
  ohttp?: boolean;
  /** Proofs need RPC spec 0.10.1 or newer. */
  rpcUrl?: string;
  relay: PrivacyRelayConfig;
}

const TOP_KEYS = ["pool", "prover", "discovery", "ohttp", "rpcUrl", "relay"];
const RELAY_KEYS = ["url", "fee", "maxFee", "allowedFeeRecipients"];
const FELT_LIMIT = 1n << 252n;

/** Strict: unknown fields, bad URLs and malformed addresses throw an error that names the field. */
export function parseStarknetPrivacyConfig(input: unknown): StarknetPrivacyConfig {
  const config = record(input, "privacy");
  onlyKeys(config, TOP_KEYS, "privacy");
  const relay = record(config.relay, "privacy.relay");
  onlyKeys(relay, RELAY_KEYS, "privacy.relay");
  if (config.ohttp !== undefined && typeof config.ohttp !== "boolean") {
    throw invalid("privacy.ohttp", "must be true or false");
  }
  return {
    pool: address(config.pool, "privacy.pool"),
    prover: serviceUrl(config.prover, "privacy.prover"),
    discovery: serviceUrl(config.discovery, "privacy.discovery"),
    ...(config.ohttp !== undefined ? { ohttp: config.ohttp } : {}),
    ...(config.rpcUrl !== undefined ? { rpcUrl: serviceUrl(config.rpcUrl, "privacy.rpcUrl") } : {}),
    relay: {
      url: serviceUrl(relay.url, "privacy.relay.url"),
      fee: feeMode(relay.fee),
      maxFee: baseUnits(relay.maxFee, "privacy.relay.maxFee"),
      allowedFeeRecipients: recipients(relay.allowedFeeRecipients),
    },
  };
}

function feeMode(value: unknown): PrivacyFeeMode {
  const fee = record(value, "privacy.relay.fee");
  if (fee.mode === "default") {
    onlyKeys(fee, ["mode", "gas_token"], "privacy.relay.fee");
    return { mode: "default", gas_token: address(fee.gas_token, "privacy.relay.fee.gas_token") };
  }
  if (fee.mode === "sponsored") {
    onlyKeys(fee, ["mode", "pool_fee"], "privacy.relay.fee");
    const pool = record(fee.pool_fee, "privacy.relay.fee.pool_fee");
    if (pool.paid_by === "sponsor") {
      onlyKeys(pool, ["paid_by"], "privacy.relay.fee.pool_fee");
      return { mode: "sponsored", pool_fee: { paid_by: "sponsor" } };
    }
    if (pool.paid_by === "user") {
      onlyKeys(pool, ["paid_by", "token"], "privacy.relay.fee.pool_fee");
      return {
        mode: "sponsored",
        pool_fee: { paid_by: "user", token: address(pool.token, "privacy.relay.fee.pool_fee.token") },
      };
    }
    throw invalid("privacy.relay.fee.pool_fee.paid_by", 'must be "user" or "sponsor"');
  }
  throw invalid("privacy.relay.fee.mode", 'must be "sponsored" or "default"');
}

function recipients(value: unknown): string[] {
  if (!Array.isArray(value) || value.length === 0) {
    throw invalid("privacy.relay.allowedFeeRecipients", "must list at least one address, or no fee can ever be accepted");
  }
  return value.map((entry, index) => address(entry, `privacy.relay.allowedFeeRecipients[${index}]`));
}

function baseUnits(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^\d+$/.test(value)) {
    throw invalid(path, "must be a decimal string of base units, for example \"1000000\"");
  }
  return BigInt(value).toString();
}

function address(value: unknown, path: string): string {
  if (typeof value !== "string" || !/^0x[0-9a-fA-F]{1,64}$/.test(value)) {
    throw invalid(path, "must be a 0x-prefixed hex address");
  }
  const felt = BigInt(value);
  if (felt === 0n || felt >= FELT_LIMIT) throw invalid(path, "is not a valid Starknet address");
  return `0x${felt.toString(16)}`;
}

function serviceUrl(value: unknown, path: string): string {
  if (typeof value !== "string") throw invalid(path, "must be a URL");
  let url: URL;
  try {
    url = new URL(value.trim());
  } catch {
    throw invalid(path, "is not a valid URL");
  }
  const loopback = url.hostname === "localhost" || url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && loopback)) {
    throw invalid(path, "must use https (http is only accepted for localhost)");
  }
  if (url.username || url.password) throw invalid(path, "must not contain credentials");
  return url.toString().replace(/\/+$/, "");
}

function record(value: unknown, path: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw invalid(path, "must be an object");
  return value as Record<string, unknown>;
}

function onlyKeys(value: Record<string, unknown>, allowed: string[], path: string): void {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) throw invalid(`${path}.${key}`, "is not a known setting");
  }
}

function invalid(path: string, problem: string): Error {
  return new Error(`kit/starknet: ${path} ${problem}`);
}
