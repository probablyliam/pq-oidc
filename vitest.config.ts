import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/*.test.ts', 'apps/lab/src/**/*.test.ts', 'tests/**/*.test.ts'],
    // Integration tests start real HTTP servers; give key generation and logins room.
    testTimeout: 20_000,
  },
});
