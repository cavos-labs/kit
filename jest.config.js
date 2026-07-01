/** @type {import('jest').Config} */
module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  roots: ["<rootDir>/src"],
  testMatch: ["**/*.test.ts"],
  // @solana/web3.js pulls rpc-websockets -> uuid, whose `node` export condition
  // is ESM and breaks under ts-jest. Map uuid to its CJS build so it resolves.
  moduleNameMapper: {
    "^uuid$": "<rootDir>/node_modules/uuid/dist/index.js",
  },
  // @stellar/stellar-sdk (even its CJS build) transitively imports @noble/hashes
  // v2, which ships ESM-only. Transform those packages instead of ignoring them.
  transform: {
    "^.+\\.[tj]sx?$": ["ts-jest", { isolatedModules: true, tsconfig: { allowJs: true } }],
  },
  transformIgnorePatterns: [
    "node_modules/(?!(@stellar/stellar-sdk|@noble|uint8array-extras)/)",
  ],
};
