declare module "expo-modules-core" {
  export function requireNativeModule<T>(name: string): T;
}

declare module "expo-web-browser" {
  export type WebBrowserAuthSessionResult =
    | { type: "success"; url: string }
    | { type: "cancel" | "dismiss" | "locked"; url?: string };
  export function openAuthSessionAsync(url: string, redirectUrl?: string): Promise<WebBrowserAuthSessionResult>;
}

declare module "expo-linking" {
  export function createURL(path: string, options?: Record<string, unknown>): string;
}

declare module "react-native" {
  import type { ComponentType } from "react";
  export const ActivityIndicator: ComponentType<any>;
  export const Modal: ComponentType<any>;
  export const Pressable: ComponentType<any>;
  export const SafeAreaView: ComponentType<any>;
  export const Text: ComponentType<any>;
  export const TextInput: ComponentType<any>;
  export const View: ComponentType<any>;
  export const StyleSheet: { create<T extends Record<string, unknown>>(styles: T): T };
}
