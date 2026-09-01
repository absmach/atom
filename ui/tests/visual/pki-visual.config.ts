import { defineConfig, devices } from "playwright/test";

/**
 * Playwright config for the visible PKI walkthrough. Distinct from
 * `playwright.config.ts` so that:
 * - `headless: false` is unconditional (you want to see it).
 * - `slowMo` is baked in (no per-step waits in the spec).
 * - `webServer` is intentionally omitted; the compose stack is expected to
 *   be up (`make up`), and the browser drives the compose UI on :3006.
 * - `workers: 1` keeps a single visible browser window.
 *
 * Overridable via env:
 *   UI_URL             (default http://localhost:3006)
 *   PW_SLOWMO_MS       (default 350; increase to slow it down further)
 *   PW_VIEWPORT_WIDTH  (default 1400)
 *   PW_VIEWPORT_HEIGHT (default 900)
 */
const slowMo = Number.parseInt(process.env.PW_SLOWMO_MS ?? "350", 10);
const width = Number.parseInt(process.env.PW_VIEWPORT_WIDTH ?? "1400", 10);
const height = Number.parseInt(process.env.PW_VIEWPORT_HEIGHT ?? "900", 10);

export default defineConfig({
  testDir: ".",
  timeout: 5 * 60_000,
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: process.env.UI_URL ?? "http://localhost:3006",
    // Default visible; PW_HEADLESS=1 lets CI / iteration runs stay headless.
    headless: process.env.PW_HEADLESS === "1",
    launchOptions: { slowMo },
    viewport: { width, height },
    trace: "on",
    video: "on",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "desktop", use: { ...devices["Desktop Chrome"] } }],
});
