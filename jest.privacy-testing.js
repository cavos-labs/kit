const dist = "./node_modules/@starkware-libs/starknet-privacy-sdk/dist";

module.exports = {
  ...require(`${dist}/testing/mocknet.js`),
  ...require(`${dist}/testing/mock-proof-provider.js`),
  ...require(`${dist}/testing/mock-proof-invocation-factory.js`),
  ...require(`${dist}/internal/contract-discovery.js`),
};
