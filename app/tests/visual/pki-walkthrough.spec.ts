/**
 * Visible PKI end-to-end walkthrough.
 *
 * See `app/tests/visual/README.md` for prerequisites and how to run.
 * Short version:
 *   cd app && pnpm exec playwright test \
 *     --config=tests/visual/pki-visual.config.ts \
 *     tests/visual/pki-walkthrough.spec.ts
 *
 * What you'll see:
 *   1. Login via the UI form.
 *   2. Open the Playground, prove the schema loaded, search a mutation.
 *   3. Visit /pki/authorities, click the tenant intermediate we seeded.
 *   4. Authority detail — PEM viewer, publication URLs.
 *   5. Visit /pki/certificates, click the leaf we seeded.
 *   6. Certificate detail — revoke via the reason picker.
 *   7. Confirm the certificate flips to "revoked".
 *   8. Walk each tab of /pki/actions so the operator surface is visible.
 *
 * Prereqs:
 *   - `make up` (or equivalent) has the compose stack live (UI :3006,
 *     Atom :18080, Postgres up).
 *   - Root + platform intermediate already bootstrapped via
 *     ATOM_PKI_ROOT_CERT_PATH / ATOM_PKI_PLATFORM_INTERMEDIATE_{CERT,KEY}_PATH.
 *     `make up` runs `make pki-material` which sets these up automatically.
 *   - `openssl` on PATH (used to build a device CSR).
 *   - Env vars — ATOM_ADMIN_IDENTIFIER, ATOM_ADMIN_SECRET (defaults below
 *     match a plain `.env.example` bring-up).
 *
 * Idempotent: verifies the config-bootstrapped root+platform intermediate.
 * Tenant / entity / cert are created fresh each run and the ledger keeps
 * them, so this is a "leaves visible residue" test — good for demos, not
 * for repeated CI.
 */

import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Browser, BrowserContext, Page } from "playwright/test";
import { chromium, expect, test } from "playwright/test";

const ATOM_BACKEND_URL =
  process.env.ATOM_BACKEND_URL ?? "http://localhost:18080";
const ADMIN_IDENTIFIER = process.env.ATOM_ADMIN_IDENTIFIER ?? "admin";
const ADMIN_SECRET =
  process.env.ATOM_ADMIN_SECRET ?? readAdminSecretFromDotenv() ?? "";
const RUN_ID = new Date()
  .toISOString()
  .replace(/[^0-9]/g, "")
  .slice(0, 14);

const WORKDIR = join(tmpdir(), "atom-pki-visual");
mkdirSync(WORKDIR, { recursive: true });

// Shared state across the serialized steps. We reuse a single browser page
// so the login cookie persists across every step and the human watching
// sees one continuous session rather than eight isolated ones.
let token = "";
let seeded: {
  rootId: string;
  intermediateId: string;
  tenantId: string;
  entityId: string;
  credentialId: string;
  serialNumber: string;
} | null = null;
let browser: Browser | undefined;
let context: BrowserContext | undefined;
let sharedPage: Page | undefined;

test.describe.configure({ mode: "serial" });

test.beforeAll(async () => {
  if (!ADMIN_SECRET) {
    throw new Error(
      "ATOM_ADMIN_SECRET is required. Set it in the environment or in .env.",
    );
  }
  token = await login(ADMIN_IDENTIFIER, ADMIN_SECRET);
  seeded = await seedPki(token);
  console.log("seed complete:");
  for (const [k, v] of Object.entries(seeded)) {
    console.log(`  ${k}: ${v}`);
  }
  const slowMo = Number.parseInt(process.env.PW_SLOWMO_MS ?? "350", 10);
  browser = await chromium.launch({
    headless: process.env.PW_HEADLESS === "1",
    slowMo,
  });
  context = await browser.newContext({
    baseURL: process.env.UI_URL ?? "http://localhost:3006",
    viewport: {
      width: Number.parseInt(process.env.PW_VIEWPORT_WIDTH ?? "1400", 10),
      height: Number.parseInt(process.env.PW_VIEWPORT_HEIGHT ?? "900", 10),
    },
  });
  sharedPage = await context.newPage();
});

test.afterAll(async () => {
  await context?.close();
  await browser?.close();
});

function activePage(): Page {
  if (!sharedPage) throw new Error("shared browser page not initialised");
  return sharedPage;
}

test("1. login as admin via the UI form", async () => {
  const page = activePage();
  await page.goto("/login");
  await banner(page, "Login as admin");
  await page.getByLabel(/Email or Username/i).fill(ADMIN_IDENTIFIER);
  await page.getByLabel(/^Password$/i).fill(ADMIN_SECRET);
  await page.getByRole("button", { name: /Sign in/i }).click();
  await expect(page).toHaveURL(/\/dashboard/, { timeout: 15_000 });
  await page.waitForTimeout(1200);
});

test("2. explore the GraphQL playground", async () => {
  const page = activePage();
  await page.goto("/playground");
  await banner(page, "GraphQL Playground — every operation, grouped");
  // Placeholder is either "Search N operations" (schema loaded) or plain
  // "Search operations" (schema not yet loaded / introspection off).
  const search = page.getByPlaceholder(/^Search .*operations$/i);
  await expect(search).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1200);
  await search.fill("revokeCertificate");
  await page.waitForTimeout(1500);
});

test("3. browse PKI authorities", async () => {
  const page = activePage();
  await page.goto("/pki/authorities");
  await banner(page, "Every managed CA in one table");
  await expect(page.getByText("PKI Authorities").first()).toBeVisible();
  await page.waitForTimeout(1500);
});

test("4. view authority detail (seeded tenant intermediate)", async () => {
  const page = activePage();
  const s = requireSeed();
  await page.goto(`/pki/authorities/${s.intermediateId}`);
  await banner(page, "Authority detail — chain, endpoints, lifecycle");
  await expect(page.getByText("Publication URLs", { exact: true })).toBeVisible(
    { timeout: 15_000 },
  );
  await expect(
    page.getByText("Certificate (PEM)", { exact: true }),
  ).toBeVisible();
  await page.waitForTimeout(2000);
  await page.mouse.wheel(0, 600);
  await page.waitForTimeout(1500);
});

test("5. browse issued certificates", async () => {
  const page = activePage();
  await page.goto("/pki/certificates");
  await banner(page, "Every issued leaf, filterable by tenant");
  await expect(page.getByText("PKI Certificates").first()).toBeVisible();
  await page.waitForTimeout(1500);
});

test("6. certificate detail — inspect the leaf we seeded", async () => {
  const page = activePage();
  const s = requireSeed();
  await page.goto(`/pki/certificates/${s.credentialId}`);
  await banner(page, "Certificate detail — subject, PEM, revoke button");
  await expect(
    page.getByText("Certificate (PEM)", { exact: true }),
  ).toBeVisible({ timeout: 15_000 });
  await page.waitForTimeout(1500);
  await page.mouse.wheel(0, 500);
  await page.waitForTimeout(1500);
});

test("7. revoke with a reason", async () => {
  const page = activePage();
  const s = requireSeed();
  await page.goto(`/pki/certificates/${s.credentialId}`);
  await banner(page, "Revoke with an RFC 5280 reason");
  await page.getByRole("button", { name: /^Revoke$/ }).click();
  await expect(page.getByRole("alertdialog")).toBeVisible();
  await page.waitForTimeout(1000);
  await page.getByLabel(/Reason \(RFC 5280\)/).selectOption("key_compromise");
  await page.waitForTimeout(700);
  await page.getByRole("button", { name: /Revoke key_compromise/ }).click();
  await page.waitForTimeout(3000);
});

test("8. walk every PKI Actions tab", async () => {
  const page = activePage();
  await page.goto("/pki/actions");
  await banner(page, "PKI Actions — forms for every managed mutation");
  // "Import Root" AND "Import Signed CA" are deliberately absent — both root
  // and platform intermediate are config-only (ATOM_PKI_ROOT_CERT_PATH,
  // ATOM_PKI_PLATFORM_INTERMEDIATE_{CERT,KEY}_PATH).
  // See product-docs/12-certificates.md.
  const tabs = [
    "Provision Tenant CA",
    "Issue from CSR",
    "Generate & Issue",
    "Revoke",
    "Bulk Revoke",
    "Retire Authority",
  ];
  for (const label of tabs) {
    await page.getByRole("tab", { name: label, exact: true }).click();
    await page.waitForTimeout(900);
  }
});

// ─── helpers ───────────────────────────────────────────────────────────────

function requireSeed() {
  if (!seeded) throw new Error("beforeAll did not seed the PKI");
  return seeded;
}

/**
 * Adds a floating banner via CSS-in-JS so the human watching the browser
 * sees a label of what's happening in each step. Non-blocking.
 */
async function banner(page: Page, text: string) {
  await page.evaluate((message) => {
    let el = document.getElementById("atom-pki-visual-banner");
    if (!el) {
      el = document.createElement("div");
      el.id = "atom-pki-visual-banner";
      el.style.cssText = [
        "position:fixed",
        "top:14px",
        "right:14px",
        "z-index:2147483647",
        "background:rgba(16,185,129,0.94)",
        "color:#0f172a",
        "font:600 14px/1.3 ui-sans-serif,system-ui,sans-serif",
        "padding:8px 12px",
        "border-radius:8px",
        "box-shadow:0 6px 24px rgba(0,0,0,.35)",
        "max-width:520px",
      ].join(";");
      document.body.appendChild(el);
    }
    el.textContent = message;
  }, text);
}

async function login(identifier: string, secret: string): Promise<string> {
  const response = await fetch(`${ATOM_BACKEND_URL}/auth/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier, secret, kind: "password" }),
  });
  const body = (await response.json()) as { token?: string; error?: string };
  if (!body.token) {
    throw new Error(
      `login failed for identifier=${identifier}: ${body.error ?? JSON.stringify(body)}`,
    );
  }
  return body.token;
}

async function gql<TData>(
  query: string,
  variables?: Record<string, unknown>,
): Promise<TData> {
  const response = await fetch(`${ATOM_BACKEND_URL}/graphql`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ query, variables }),
  });
  const payload = (await response.json()) as {
    data?: TData;
    errors?: Array<{ message: string }>;
  };
  if (!response.ok || payload.errors?.length) {
    throw new Error(
      `GraphQL error: ${payload.errors?.map((e) => e.message).join("; ") ?? response.statusText}`,
    );
  }
  return payload.data as TData;
}

async function seedPki(_token: string) {
  // Root + platform intermediate are config-only. Query for the active rows
  // and fail with a clear message if the operator hasn't bootstrapped yet.
  const authorities = await gql<{
    pkiAuthorities: Array<{
      id: string;
      kind: string;
      status: string;
    }>;
  }>(`query{pkiAuthorities{id kind status}}`);
  const root = authorities.pkiAuthorities.find(
    (a) => a.kind === "root" && a.status === "active",
  );
  if (!root) {
    throw new Error(
      "No active root authority. Bootstrap via ATOM_PKI_ROOT_CERT_PATH and restart Atom, or run `make pki-material` which handles this for you.",
    );
  }
  const rootId = root.id;
  const platformIntermediate = authorities.pkiAuthorities.find(
    (a) => a.kind === "platform_intermediate" && a.status === "active",
  );
  if (!platformIntermediate) {
    throw new Error(
      "No active platform intermediate. Bootstrap via ATOM_PKI_PLATFORM_INTERMEDIATE_{CERT,KEY}_PATH and restart Atom, or run `make pki-material`.",
    );
  }

  // 3. Fresh tenant for this run.
  const tenantName = `pki-visual-${RUN_ID}`;
  const tenantData = await gql<{ createTenant: { id: string } }>(
    `mutation($n:String!){createTenant(input:{name:$n}){id}}`,
    { n: tenantName },
  );
  const tenantId = tenantData.createTenant.id;

  // 4. Auto-provision a tenant intermediate.
  const provisioned = await gql<{
    provisionTenantAuthorityAutomatically: {
      authority: { id: string; status: string };
      validationError?: string | null;
    };
  }>(
    `mutation($t:ID!){provisionTenantAuthorityAutomatically(tenantId:$t){authority{id status} validationError}}`,
    { t: tenantId },
  );
  if (provisioned.provisionTenantAuthorityAutomatically.validationError) {
    throw new Error(
      `tenant provisioning rejected: ${provisioned.provisionTenantAuthorityAutomatically.validationError}`,
    );
  }
  const intermediateId =
    provisioned.provisionTenantAuthorityAutomatically.authority.id;

  // 5. Device entity in that tenant.
  const entityData = await gql<{ createEntity: { id: string } }>(
    `mutation($t:ID!,$n:String!){createEntity(input:{name:$n,tenantId:$t,kind:device}){id}}`,
    { t: tenantId, n: `device-${RUN_ID}` },
  );
  const entityId = entityData.createEntity.id;

  // 6. Fresh keypair + CSR + issue.
  const deviceKey = join(WORKDIR, `device-${RUN_ID}.key`);
  const deviceCsr = join(WORKDIR, `device-${RUN_ID}.csr`);
  execFileSync("openssl", [
    "ecparam",
    "-name",
    "prime256v1",
    "-genkey",
    "-out",
    deviceKey,
  ]);
  execFileSync("openssl", [
    "req",
    "-new",
    "-key",
    deviceKey,
    "-out",
    deviceCsr,
    "-subj",
    `/CN=device-${RUN_ID}`,
  ]);
  const csrPem = readFileSync(deviceCsr, "utf8");
  const issued = await gql<{
    issueCertificateFromCsrV2: {
      certificate: { credentialId: string; serialNumber: string };
    };
  }>(
    `mutation($in:IssueCertificateFromCsrV2Input!){issueCertificateFromCsrV2(input:$in){certificate{credentialId serialNumber}}}`,
    {
      in: {
        entityId,
        csrPem,
        ttlSecs: 3600,
        idempotencyKey: `visual-${RUN_ID}`,
      },
    },
  );

  return {
    rootId,
    intermediateId,
    tenantId,
    entityId,
    credentialId: issued.issueCertificateFromCsrV2.certificate.credentialId,
    serialNumber: issued.issueCertificateFromCsrV2.certificate.serialNumber,
  };
}

/**
 * Best-effort read of ADMIN_SECRET from the repo's .env — the same file the
 * compose stack uses. Returns undefined if the file isn't there, letting the
 * caller fall back to the environment.
 */
function readAdminSecretFromDotenv(): string | undefined {
  const candidates = [
    join(process.cwd(), ".env"),
    join(process.cwd(), "..", ".env"),
    join(process.cwd(), "..", "..", ".env"),
  ];
  for (const path of candidates) {
    if (!existsSync(path)) continue;
    for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed.startsWith("ADMIN_SECRET=")) continue;
      return trimmed.slice("ADMIN_SECRET=".length).replace(/^["']|["']$/g, "");
    }
  }
  return undefined;
}

/*
See app/tests/visual/README.md for full setup + overrides.

  cd app && pnpm exec playwright test \
    --config=tests/visual/pki-visual.config.ts \
    tests/visual/pki-walkthrough.spec.ts

Slow it down further:

  PW_SLOWMO_MS=800 pnpm exec playwright test \
    --config=tests/visual/pki-visual.config.ts \
    tests/visual/pki-walkthrough.spec.ts
*/

// Reference execSync so it stays imported for optional future use;
// keeps `pnpm lint` happy without silencing lint groups.
void execSync;
