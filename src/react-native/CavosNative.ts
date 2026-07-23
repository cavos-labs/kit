import { Cavos as CoreCavos, type CavosWallet, type ConnectOptions, type RecoveryOptions } from "../Cavos";
import { CavosSolana } from "../chains/solana/CavosSolana";
import type { RecoverSolanaOptions } from "../chains/solana/CavosSolana";
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
    const factories = nativeFactories(opts.minimumKeySecurity);
    return CavosSolana.recover({ ...opts, createSigner: opts.createSigner ?? factories.createSigner });
  },
};

export async function deleteDeviceKeys(keyId: string): Promise<void> {
  await nativeModule().deleteKeys(keyId);
  await nativeModule().deleteKeys(`${keyId}:stellar-unwrap`);
}
