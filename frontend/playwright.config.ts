import { defineConfig } from "@playwright/test";

const ci = Boolean(process.env.CI);

export default defineConfig({
  testDir: "./e2e",
  timeout: 45_000,
  expect: { timeout: 10_000 },
  fullyParallel: false,
  workers: 1,
  retries: ci ? 1 : 0,
  reporter: ci
    ? [["junit", { outputFile: process.env.PLAYWRIGHT_JUNIT_OUTPUT_NAME || "/artifacts/e2e-junit.xml" }]]
    : [["list"]],
  use: {
    baseURL: process.env.E2E_BASE_URL || "http://127.0.0.1:3000",
    trace: "retain-on-failure",
    video: "off",
    screenshot: "only-on-failure",
  },
});
