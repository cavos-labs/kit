/**
 * @cavos/kit/react — React bindings for @cavos/kit.
 *
 * Drop-in: wrap your app in <CavosProvider> (with the built-in <CavosAuthModal>)
 * and use `useCavos()` anywhere below it. React is a peerDependency — this
 * subpath is the only part of the kit that imports React, so the core stays
 * usable from React Native, Node, or plain TypeScript without it.
 */
export { CavosProvider, useCavos } from './CavosProvider';
export type {
  CavosConfig,
  CavosModalConfig,
  CavosContextValue,
  CavosProviderProps,
  WalletStatus,
  UserInfo,
} from './CavosProvider';
export { CavosAuthModal, useCavosAuth } from './CavosAuthModal';
// A device signer lives on one chain. Anything carrying a `network` — a
// revocation request, most often — has to mount the provider for that chain,
// and getting it wrong fails in a way that reads like the device is gone.
export { configForNetwork, chainForNetwork } from './configForNetwork';
// The approve/revoke pages every integrating app needs. Same flow, different
// verb; packaged because writing it by hand has traps that only show up in
// production. Pass a function as `children` to keep your own UI.
export { ApproveDevicePage, RevokeDevicePage } from './DeviceFlowPage';
export type { DeviceFlowPageProps, DeviceFlowState, DeviceFlowStatus } from './DeviceFlowPage';
export type { CavosAuthModalProps } from './CavosAuthModal';
// The provider runs these itself in development. Exported so a host can run
// the same checks in its own setup screen, tests, or CI.
export {
  validateCavosConfig,
  checkAppSaltDrift,
  formatConfigProblems,
} from './validateConfig';
export type { CavosConfigProblem } from './validateConfig';
