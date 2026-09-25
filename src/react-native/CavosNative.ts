import { Cavos as CoreCavos, type CavosWallet, type ConnectOptions, type RecoveryOptions } from "../Cavos";
import type { CavosSolana, RecoverSolanaOptions } from "../chains/solana/CavosSolana";
import { NativeDeviceSigner, type MinimumKeySecurity } from "./NativeDeviceSigner";
import { NativeDeviceUnwrapKey } from "./NativeDeviceUnwrapKey";
import { nativeModule } from "./NativeModule";

export interface NativeConnectOptions extends ConnectOptions {
  minimumKeySecurity?: MinimumKeySecurity;
}

function nativeFactories(minimumKeySecurity: MinimumKeySecurity = "os-protected") {
  return {
    createSigner: (keyId: string) => NativeDeviceSigner.loadOrCreate({ keyId, minimumKeySecurity }),
    createStellarDeviceKey: (keyId: string) =>
      NativeDeviceUnwrapKey.loadOrCreate({ keyId: `${keyId}:stellar-unwrap`, minimumKeySecurity }),
  };
}

/** React Native facade with platform keys injected for every chain. */
export const Cavos = {
  connect(opts: NativeConnectOptions): Promise<CavosWallet> {
    const factories = nativeFactories(opts.minimumKeySecurity);
    return CoreCavos.connect({
      ...opts,
      createSigner: opts.createSigner ?? factories.createSigner,
      createStellarDeviceKey: opts.createStellarDeviceKey ?? factories.createStellarDeviceKey,
    });
  },

  recover(opts: RecoveryOptions & { minimumKeySecurity?: MinimumKeySecurity }) {
    const factories = nativeFactories(opts.minimumKeySecurity);
    return CoreCavos.recover({ ...opts, createSigner: opts.createSigner ?? factories.createSigner });
  },

  recoverSolana(opts: RecoverSolanaOptions & { minimumKeySecurity?: MinimumKeySecurity }) {
    return Cavos.connect({
      chain: "solana",
      network: opts.network === "solana-mainnet" ? "mainnet" : "testnet",
      appSalt: opts.appSalt,
      ...(opts.identity ? { identity: opts.identity } : {}),
      ...(opts.auth ? { auth: opts.auth } : {}),
      ...(opts.appId ? { appId: opts.appId } : {}),
      ...(opts.environment ? { environment: opts.environment } : {}),
      ...(opts.backendUrl ? { backendUrl: opts.backendUrl } : {}),
      ...(opts.rpcUrl ? { rpcUrl: opts.rpcUrl } : {}),
      ...(opts.relayer ? { relayer: opts.relayer } : {}),
      ...(opts.registry ? { registry: opts.registry } : {}),
      ...(opts.socialRecovery ? { socialRecovery: opts.socialRecovery } : {}),
      ...(opts.credential ? { socialRecoveryCredential: opts.credential } : {}),
      ...(opts.passkey ? { passkeyPrf: opts.passkey } : {}),
      minimumKeySecurity: opts.minimumKeySecurity,
    }) as Promise<CavosSolana>;
  },
};

export async function deleteDeviceKeys(keyId: string): Promise<void> {
  await nativeModule().deleteKeys(keyId);
  await nativeModule().deleteKeys(`${keyId}:stellar-unwrap`);
}
