module.exports = {
  testEnvironment: 'node',
  testPathIgnorePatterns: ['/node_modules/', '/test.js'],
  collectCoverageFrom: [
    'core/**/*.js',
    'ai/**/*.js',
    'database/**/*.js',
    'utils/**/*.js',
    '!**/node_modules/**'
  ]
};
