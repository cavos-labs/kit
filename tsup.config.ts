import { defineConfig } from "tsup";

export default defineConfig({
  // Two entries: the framework-agnostic core, and the (optional) React layer.
  // `src/react/index.tsx` -> `dist/react/index.{js,mjs}` (matches the
  // `./react` subpath export in package.json).
  entry: ["src/index.ts", "src/react/index.tsx"],
  format: ["cjs", "esm"],
  dts: true,
  sourcemap: true,
  clean: true,
  treeshake: true,
  target: "es2020",
  external: ["react", "react-dom"],
});
