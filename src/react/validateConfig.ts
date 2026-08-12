import type { CavosConfig } from "./CavosProvider";

export interface CavosConfigProblem {
  /** Stable identifier so hosts can suppress or test a specific check. */
  code:
    | "missing-app-salt"
    | "app-salt-changed"
    | "missing-app-id"
    | "missing-paymaster-key"
    | "unused-paymaster-key"
    | "social-recovery-without-app-id";
  /** `error` breaks the integration; `warning` works but is probably a mistake. */
  level: "error" | "warning";
  message: string;
}

/**
 * Check a config for mistakes that are otherwise reported late, indirectly, or
 * not at all. Pure — see `checkAppSaltDrift` for the check that needs storage.
 */
export function validateCavosConfig(config: CavosConfig): CavosConfigProblem[] {
  const problems: CavosConfigProblem[] = [];
  const chain = config.chain ?? "starknet";

  if (!config.appSalt) {
    problems.push({
      code: "missing-app-salt",
      level: "error",
      message:
        "`appSalt` is required: it is mixed into every wallet address, so each app derives its own wallets. Pick one string and never change it.",
    });
  }

  if (chain === "starknet" && !config.paymasterApiKey) {
    problems.push({
      code: "missing-paymaster-key",
      level: "error",
      message:
        "Starknet needs `paymasterApiKey` to sponsor the account deploy and every transaction. Without it, connect() will throw.",
    });
  }

  if (chain !== "starknet" && config.paymasterApiKey) {
    problems.push({
      code: "unused-paymaster-key",
      level: "warning",
      message: `\`paymasterApiKey\` is ignored on ${chain} — gas is sponsored by the Cavos relayer, enabled by \`appId\`. Remove it so a Starknet key is not shipped where it is not needed.`,
    });
  }

  if (!config.appId) {
    problems.push({
      code: "missing-app-id",
      level: "warning",
      message:
        "No `appId`: hosted login, the wallet registry that recognizes a user across devices, and relayer sponsorship are all off. Expected only for fully self-hosted setups.",
    });
  }

  if ((config.socialRecovery || config.socialRecoveryAttestation) && !config.appId) {
    problems.push({
      code: "social-recovery-without-app-id",
      level: "error",
      message:
        "Social recovery needs `appId` — the enclave session is scoped to the app and its dashboard environment.",
    });
  }

  return problems;
}

const SALT_KEY = "cavos:app-salt";

function saltKeyFor(config: CavosConfig): string {
  return `${SALT_KEY}:${config.appId ?? "no-app-id"}:${config.chain ?? "starknet"}:${config.network}`;
}

/**
 * Detect an `appSalt` that changed since this browser last connected.
 *
 * Addresses are derived from the salt, so changing it silently points every
 * existing user at a brand-new empty wallet — the app keeps working, on the
 * wrong accounts, with no error anywhere. That is worth one loud warning.
 *
 * Returns the problem to report, or null. Records the salt on first sight.
 */
export function checkAppSaltDrift(
  config: CavosConfig,
  storage: Pick<Storage, "getItem" | "setItem"> | undefined = safeLocalStorage(),
): CavosConfigProblem | null {
  if (!storage || !config.appSalt) return null;
  const key = saltKeyFor(config);
  let previous: string | null = null;
  try {
    previous = storage.getItem(key);
  } catch {
    return null;
  }

  if (previous === config.appSalt) return null;

  try {
    storage.setItem(key, config.appSalt);
  } catch {
    // Storage is unavailable or full; the check is advisory either way.
  }

  if (previous === null) return null;

  return {
    code: "app-salt-changed",
    level: "error",
    message:
      `\`appSalt\` changed from "${previous}" to "${config.appSalt}". Wallet addresses are derived from it, so existing users will land on new, empty wallets and will not find their funds. ` +
      "Change it only for a deliberate migration; otherwise restore the previous value.",
  };
}

function safeLocalStorage(): Storage | undefined {
  try {
    return typeof window === "undefined" ? undefined : window.localStorage;
  } catch {
    return undefined;
  }
}

/** Format problems for the console. Exported so hosts can render them instead. */
export function formatConfigProblems(problems: CavosConfigProblem[]): string {
  return problems
    .map((p) => `  ${p.level === "error" ? "✗" : "!"} [${p.code}] ${p.message}`)
    .join("\n");
}
