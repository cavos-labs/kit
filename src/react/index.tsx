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
export type { CavosAuthModalProps } from './CavosAuthModal';
