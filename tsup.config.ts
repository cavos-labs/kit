import { defineConfig } from "tsup";

export default defineConfig([{
  // Two entries: the framework-agnostic core, and the (optional) React layer.
  // `src/react/index.tsx` -> `dist/react/index.{js,mjs}` (matches the
  // `./react` subpath export in package.json).
  entry: [
    "src/index.ts",
    "src/react/index.tsx",
    "src/react-native/index.ts",
    "src/starknet.ts",
    "src/solana.ts",
    "src/stellar.ts",
    "src/vault/index.ts",
  ],
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  target: "es2020",
  external: [
    "react",
    "react-dom",
    "react-native",
    "expo-modules-core",
    "expo-web-browser",
    "expo-linking",
    "react-native-get-random-values",
  ],
},
{
  // Self-contained scripts for the vault pages, served as static files so the
  // vault origin runs nothing but this code.
  entry: {
    "vault-host": "src/vault/browser/host.ts",
    "vault-confirm": "src/vault/browser/confirm.ts",
  },
  outDir: "dist/vault-browser",
  format: ["iife"],
  platform: "browser",
  target: "es2020",
  minify: true,
  clean: true,
  noExternal: [/.*/],
  inject: ["src/vault/browser/buffer.ts"],
  define: { "process.env.NODE_ENV": '"production"' },
}]);
