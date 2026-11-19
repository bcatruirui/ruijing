import { defineConfig } from "vitest/config";
export default defineConfig({
  test: {
    include: [
      "tests/unit/**/*.test.ts",
      "tests/network/**/*.test.ts",
      "tests/network/**/*.test.mjs",
      "tests/integration/**/*.test.ts",
    ],
    testTimeout: 15000,
    pool: "forks",
    maxWorkers: 2,
  },
});
