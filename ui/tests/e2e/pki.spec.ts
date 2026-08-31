import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "playwright/test";
import { expect, test } from "playwright/test";

const env = readLocalEnv();

test("pki actions page renders all six action tabs", async ({ page }) => {
  test.skip(
    !env.ATOM_ADMIN_IDENTIFIER || !env.ATOM_ADMIN_SECRET,
    "admin credentials are not configured",
  );

  await login(page);
  await page.goto("/pki/actions");

  for (const label of [
    "Import Root",
    "Import Signed CA",
    "Provision Tenant CA",
    "Issue Certificate",
    "Revoke Certificate",
    "Retire Authority",
  ]) {
    await expect(page.getByRole("tab", { name: label })).toBeVisible();
  }

  await page.getByRole("tab", { name: "Revoke Certificate" }).click();
  await expect(page.getByLabel("Reason (RFC 5280)")).toBeVisible();
});

test("playground operations panel auto-loads and is searchable", async ({
  page,
}) => {
  test.skip(
    !env.ATOM_ADMIN_IDENTIFIER || !env.ATOM_ADMIN_SECRET,
    "admin credentials are not configured",
  );

  await login(page);
  await page.goto("/playground");

  // Operations panel is the first sidebar card; the search input should
  // reflect the introspected operation count once the schema loads.
  await expect(page.getByPlaceholder(/Search \d+ operations/)).toBeVisible({
    timeout: 10_000,
  });

  await page
    .getByPlaceholder(/Search \d+ operations/)
    .fill("revokeCertificate");
  await expect(page.getByText(/revokeCertificateV2/i).first()).toBeVisible();
});

function readLocalEnv() {
  const values: Record<string, string> = {};
  try {
    const source = readFileSync(join(process.cwd(), ".env"), "utf8");
    for (const line of source.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) {
        continue;
      }
      const [key, ...parts] = trimmed.split("=");
      values[key] = parts.join("=").replace(/^["']|["']$/g, "");
    }
  } catch {
    // Tests can still run unauthenticated smoke checks without local env.
  }
  return { ...values, ...process.env };
}

async function login(page: Page) {
  await page.goto("/login");
  await page.getByLabel("Entity name").fill(env.ATOM_ADMIN_IDENTIFIER || "");
  await page.getByLabel("Secret").fill(env.ATOM_ADMIN_SECRET || "");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/dashboard/);
}
