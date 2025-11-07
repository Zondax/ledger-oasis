module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transformIgnorePatterns: ['^.+\\.js$'],
  reporters: ['default', ['summary', { summaryThreshold: 1 }]],
  globalSetup: './globalsetup.js',
  clearMocks: true,
  resetModules: true,
  modulePathIgnorePatterns: ['<rootDir>/../tests_tools/neon/native/target/'],
}
