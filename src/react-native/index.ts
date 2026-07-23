import "./runtime";

export { Cavos, deleteDeviceKeys } from "./CavosNative";
export type { NativeConnectOptions } from "./CavosNative";
export { CavosProvider, useCavos } from "./CavosProvider";
export type { CavosConfig, CavosModalConfig, CavosContextValue, WalletStatus } from "./CavosProvider";
export { CavosAuthModal } from "./CavosAuthModal";
export type { CavosAuthModalProps } from "./CavosAuthModal";
export { NativeCavosAuth, NativeCavosAuthError } from "./NativeCavosAuth";
export type { NativeCavosAuthOptions, NativeCavosAuthErrorCode } from "./NativeCavosAuth";
export { NativeDeviceSigner } from "./NativeDeviceSigner";
export type { NativeDeviceSignerOptions, MinimumKeySecurity } from "./NativeDeviceSigner";
export { NativeDeviceUnwrapKey } from "./NativeDeviceUnwrapKey";
export type { NativeDeviceUnwrapKeyOptions } from "./NativeDeviceUnwrapKey";
export { NativePasskeySigner, NativePasskeyPrf } from "./NativePasskeys";
export type { NativePasskeyOptions } from "./NativePasskeys";
export type { NativeSecurityLevel, NativeCapabilities } from "./NativeModule";
export { nativeModule as getCavosNativeModule } from "./NativeModule";

import { nativeModule } from "./NativeModule";
export const getNativeCapabilities = () => nativeModule().getCapabilities();

export type { CavosWallet, Chain, NetworkEnv } from "../Cavos";
export { approveDeviceEverywhere } from "../Cavos";
export type { Identity } from "../auth/AuthProvider";
