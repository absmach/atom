#!/usr/bin/env node
// Maintainer-only. Uploads a doc image to the shared R2 bucket and purges
// it from Cloudflare's edge cache, so it's live right after this finishes.
// Requires CLOUDFLARE_API_TOKEN (scoped: R2 Edit on websites-images + Zone
// Cache Purge on absmach.eu) and CLOUDFLARE_ZONE_ID.
//
// Usage:
//   pnpm run publish-image <local-file> <public-path>
//
// <public-path> is the path used in MDX content, starting with "img/" to
// match the route worker/index.ts serves it back on:
//   pnpm run publish-image ./roles-list.png img/user-guide/roles/roles-list-populated.png
//   -> referenced in MDX as /img/user-guide/roles/roles-list-populated.png
//   -> live at https://www.absmach.eu/docs/atom/img/user-guide/roles/roles-list-populated.png

import { execFileSync } from "node:child_process";
import { existsSync } from "node:fs";
import { extname } from "node:path";
import process from "node:process";

const BUCKET_NAME = "websites-images";
// This docs site is served under https://www.absmach.eu/docs/atom (see
// README.md, app/sitemap.ts) -- same zone as the main absmach-website repo,
// which is why CLOUDFLARE_ZONE_ID below matches that repo's.
const SITE_ORIGIN = "https://www.absmach.eu";
const BASE_PATH = "docs/atom";

// Shared bucket ("websites-images") holds assets for multiple properties;
// this prefix keeps atom-docs' objects from colliding with the others.
// Keep in sync with worker/index.ts.
const R2_KEY_PREFIX = "atom-docs";

const MIME_TYPES = {
  ".webp": "image/webp",
  ".jpg": "image/jpeg",
  ".jpeg": "image/jpeg",
  ".png": "image/png",
  ".svg": "image/svg+xml",
  ".gif": "image/gif",
  ".avif": "image/avif",
};

try {
  process.loadEnvFile(new URL("./.env.publish-image", import.meta.url));
} catch {
  // No local env file -- assume CLOUDFLARE_API_TOKEN / CLOUDFLARE_ZONE_ID
  // are already exported (e.g. in CI).
}

// pnpm forwards a leading "--" to the underlying command instead of
// stripping it (unlike npm), so tolerate it either way.
const cliArgs = process.argv.slice(2).filter((arg) => arg !== "--");
const [localFile, publicPath] = cliArgs;

if (!localFile || !publicPath) {
  console.error(
    "Usage: pnpm run publish-image <local-file> <public-path>\n" +
      "Example: pnpm run publish-image ./roles-list.png img/user-guide/roles/roles-list-populated.png",
  );
  process.exit(1);
}

if (!existsSync(localFile)) {
  console.error(`Local file not found: ${localFile}`);
  process.exit(1);
}

const destKey = publicPath.replace(/^\/+/, "");
if (!destKey.startsWith("img/") || destKey === "img/") {
  console.error(`Destination must start with "img/" and include a path, got: ${destKey}`);
  process.exit(1);
}
const restPath = destKey.slice("img/".length);

const contentType = MIME_TYPES[extname(restPath).toLowerCase()];
if (!contentType) {
  console.error(`Unrecognized file extension for: ${destKey}`);
  process.exit(1);
}

const { CLOUDFLARE_API_TOKEN, CLOUDFLARE_ZONE_ID } = process.env;
if (!CLOUDFLARE_API_TOKEN || !CLOUDFLARE_ZONE_ID) {
  console.error(
    "Missing CLOUDFLARE_API_TOKEN and/or CLOUDFLARE_ZONE_ID.\n" +
      "Copy scripts/.env.publish-image.example to scripts/.env.publish-image and fill in the token.",
  );
  process.exit(1);
}

const objectPath = `${BUCKET_NAME}/${R2_KEY_PREFIX}/${restPath}`;

console.log(`Uploading ${localFile} -> r2://${objectPath}`);
execFileSync(
  "wrangler",
  [
    "r2",
    "object",
    "put",
    objectPath,
    `--file=${localFile}`,
    `--content-type=${contentType}`,
    "--remote",
  ],
  { stdio: "inherit", env: process.env },
);

const publicUrl = `${SITE_ORIGIN}/${BASE_PATH}/${destKey}`;

console.log(`Purging edge cache for ${publicUrl}`);
const purgeResponse = await fetch(
  `https://api.cloudflare.com/client/v4/zones/${CLOUDFLARE_ZONE_ID}/purge_cache`,
  {
    method: "POST",
    headers: {
      Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ files: [publicUrl] }),
  },
);

const purgeResult = await purgeResponse.json();
if (!purgeResponse.ok || !purgeResult.success) {
  console.error("Cache purge failed:", JSON.stringify(purgeResult, null, 2));
  process.exit(1);
}

console.log(`Done. Live at ${publicUrl}`);
