import { defineConfig, devices } from "@playwright/test";

// Override when another project already occupies 3000; the tests reuse
// whatever is on that port and would otherwise run against the wrong app.
const WEB_PORT = process.env.SENTINEL_WEB_PORT ?? "3000";
const WEB_URL = `http://127.0.0.1:${WEB_PORT}`;

export default defineConfig({
  testDir: "./tests/e2e",
  fullyParallel: false,
  retries: 0,
  reporter: "line",
  use: {
    baseURL: WEB_URL,
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
      command: "python3 ../scripts/week11_playwright_server.py",
      url: "http://127.0.0.1:8000/health",
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: `npm run dev -- --hostname 127.0.0.1 --port ${WEB_PORT}`,
      url: WEB_URL,
      reuseExistingServer: true,
      timeout: 120_000,
    },
  ],
});
