module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  // `@zondax/zemu` transitively imports `get-port`, which ships as pure ESM
  // (`import ... from 'node:net'`). Let Jest transform it (and other packages
  // we may need to opt in later); keep the rest of node_modules ignored.
  transformIgnorePatterns: ['node_modules/(?!(get-port)/)'],
  // Explicit .ts + .js transforms. The .js entry downlevels the ESM inside
  // the allow-listed node_modules above — plus the co-located @zondax/ledger-oasis
  // dist/*.js — to CJS so Jest's module loader can require() them. `allowJs`
  // and `isolatedModules` live in tsconfig.json per ts-jest v30 conventions.
  transform: {
    '^.+\\.ts$': ['ts-jest', {}],
    '^.+\\.js$': ['ts-jest', {}],
  },
  reporters: ['default', ['summary', { summaryThreshold: 1 }]],
  globalSetup: './globalsetup.js',
  clearMocks: true,
  resetModules: true,
  modulePathIgnorePatterns: ['<rootDir>/../tests_tools/neon/native/target/'],
}
