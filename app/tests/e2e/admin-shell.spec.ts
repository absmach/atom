import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Page } from "playwright/test";
import { expect, test } from "playwright/test";

const env = readLocalEnv();

test("unauthenticated users land on login", async ({ page }) => {
  await page.goto("/dashboard");
  await expect(page.getByText("Sign in to Atom")).toBeVisible();
});

test("login page is responsive and task-focused", async ({ page }) => {
  await page.goto("/login");
  await expect(page.getByLabel("Entity name")).toBeVisible();
  await expect(page.getByLabel("Secret")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in" })).toBeVisible();
});

test("authenticated admin can reach core workflows", async ({ page }) => {
  test.skip(
    !env.ATOM_ADMIN_IDENTIFIER || !env.ATOM_ADMIN_SECRET,
    "admin credentials are not configured",
  );

  await login(page);

  for (const route of [
    ["/tenants", "Tenants"],
    ["/entities", "Entities"],
    ["/profiles", "Profiles"],
    ["/groups", "Groups"],
    ["/resources", "Resources"],
    ["/roles", "Roles"],
    ["/capabilities", "Capabilities"],
    ["/policies", "Policy Builder Wizard"],
    ["/authz", "Authorization debugger"],
    ["/audit", "Audit Logs"],
    ["/endpoints", "API Endpoints"],
    ["/playground", "Playground"],
    ["/settings", "Session and platform settings"],
  ] as const) {
    await page.goto(route[0]);
    await expect(
      page.locator("main").getByText(route[1]).first(),
    ).toBeVisible();
    await expect(page.getByText("Application error")).toHaveCount(0);
  }
});

test("desktop CRUD controls open create and inspect sheets", async ({
  page,
}, testInfo) => {
  test.skip(
    testInfo.project.name !== "desktop",
    "table row actions are desktop-only in this scaffold",
  );
  test.skip(
    !env.ATOM_ADMIN_IDENTIFIER || !env.ATOM_ADMIN_SECRET,
    "admin credentials are not configured",
  );

  await login(page);
  await page.goto("/entities");

  await page.getByRole("button", { name: "Create" }).click();
  await expect(page.getByRole("dialog")).toContainText(
    "task-driven form maps to the GraphQL create mutation",
  );
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).toHaveCount(0);

  await page.getByRole("button", { name: "Inspect" }).first().click();
  await expect(page.getByRole("dialog")).toContainText("Read-only detail view");
  await expect(page.getByRole("dialog")).toContainText("id");
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
  await expect(page.getByText("Control plane overview")).toBeVisible();
}
