import { hash as stellarHash, Networks } from "@stellar/stellar-sdk";
import { shortString } from "starknet";

/**
 * The network a signature is actually for, read from what is signed. The app
 * also says which network it connected to, but the app is what the vault
 * does not trust: Solana and Stellar keys sign the same way on every network.
 */

const STELLAR: Record<string, string> = {
  [Networks.PUBLIC]: "Stellar Mainnet",
  [Networks.TESTNET]: "Stellar Testnet",
  [Networks.FUTURENET]: "Stellar Futurenet",
};

export function stellarNetworkName(passphrase: string): string {
  const name = STELLAR[passphrase];
  if (!name) throw new Error("kit/vault: unknown Stellar network");
  return name;
}

/** Soroban auth preimages carry the network as `sha256(passphrase)`. */
export function stellarNetworkNameFromId(networkId: Uint8Array): string {
  const id = Buffer.from(networkId).toString("hex");
  for (const passphrase of Object.keys(STELLAR)) {
    if (stellarHash(Buffer.from(passphrase)).toString("hex") === id) return STELLAR[passphrase];
  }
  throw new Error("kit/vault: unknown Stellar network");
}

const STARKNET: Record<string, string> = {
  SN_MAIN: "Starknet Mainnet",
  SN_SEPOLIA: "Starknet Sepolia",
};

export function starknetNetworkName(chainId: unknown): string {
  const raw = String(chainId ?? "");
  const decoded = /^0x[0-9a-f]+$/i.test(raw) ? shortString.decodeShortString(raw) : raw;
  const name = STARKNET[decoded];
  if (!name) throw new Error("kit/vault: unknown Starknet network");
  return name;
}

const SOLANA_RPC: [string, string][] = [
  ["Solana Mainnet", "https://api.mainnet-beta.solana.com"],
  ["Solana Devnet", "https://api.devnet.solana.com"],
];

/**
 * A Solana message names no network, only a recent blockhash, so ask each
 * network whether it knows that blockhash. Only used when asking the user.
 */
export async function solanaNetworkName(recentBlockhash: string, fetchImpl: typeof fetch = fetch): Promise<string> {
  for (const [name, url] of SOLANA_RPC) {
    try {
      const res = await fetchImpl(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "isBlockhashValid", params: [recentBlockhash, { commitment: "processed" }] }),
      });
      const body = (await res.json()) as { result?: { value?: boolean } };
      if (body.result?.value === true) return name;
    } catch {
      // Try the next network.
    }
  }
  return "Solana, network not confirmed";
}
