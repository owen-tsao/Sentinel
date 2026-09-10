import { defineConfig, devices } from "@playwright/test";

/**
 * Mocked-only Playwright config: every spec here stubs the control API with
 * page.route, so only the Next.js dev server is needed. Use this when Docker
 * (required by the real backend flow) is not running:
 *
 *   npx playwright test --config playwright.mocked.config.ts
 *
 * Port 3100 avoids colliding with any other local Next.js app on 3000.
 */
const port = process.env.SENTINEL_WEB_PORT ?? "3100";

export default defineConfig({
  testDir: "./tests/e2e",
  testIgnore: ["**/real-control-flow.spec.ts"],
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
  },
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],
  webServer: [
    {
      command: `npm run dev -- --hostname 127.0.0.1 --port ${port}`,
      url: `http://127.0.0.1:${port}`,
      reuseExistingServer: true,
      timeout: 120_000,
    },
  ],
});
