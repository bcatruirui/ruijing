import { defineConfig, devices } from "@playwright/test";
import { resolve } from "node:path";
process.env.PLAYWRIGHT_BROWSERS_PATH = resolve(".cache/browsers");
process.env.TEMP = resolve(".cache/tmp");
process.env.TMP = process.env.TEMP;
export default defineConfig({
  testDir: "tests/e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30000,
  expect: { timeout: 10000 },
  outputDir: "test-results",
  reporter: [
    ["list"],
    ["json", { outputFile: "reports/e2e-results.json" }],
    ["html", { outputFolder: "reports/playwright", open: "never" }],
  ],
  use: {
    baseURL: "http://127.0.0.1:5173",
    headless: true,
    locale: "zh-CN",
    timezoneId: "Asia/Shanghai",
    colorScheme: "light",
    reducedMotion: "reduce",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chromium-desktop",
      use: {
        ...devices["Desktop Chrome"],
        viewport: { width: 1440, height: 1000 },
      },
    },
    {
      name: "chromium-mobile",
      use: {
        ...devices["Pixel 7"],
        viewport: { width: 390, height: 844 },
        defaultBrowserType: "chromium",
      },
    },
  ],
  webServer: {
    command: "npm run dev",
    url: "http://127.0.0.1:5173",
    reuseExistingServer: !process.env.CI,
    timeout: 30000,
    env: { TEMP: process.env.TEMP, TMP: process.env.TMP },
  },
});
