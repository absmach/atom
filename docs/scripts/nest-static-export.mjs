import { promises as fs } from "node:fs";
import path from "node:path";

const outDir = path.resolve("out");
const basePath = path.join("docs", "atom");
const nestedDir = path.join(outDir, basePath);
const tempDir = path.join(outDir, ".basepath-root");
const controlFiles = new Set(["_headers", "_redirects"]);

async function pathExists(filePath) {
  try {
    await fs.access(filePath);
    return true;
  } catch {
    return false;
  }
}

if (!(await pathExists(outDir))) {
  throw new Error("Missing out/ directory. Run next build before nesting.");
}

await fs.rm(tempDir, { recursive: true, force: true });
await fs.mkdir(tempDir, { recursive: true });

for (const entry of await fs.readdir(outDir, { withFileTypes: true })) {
  if (entry.name === path.basename(tempDir) || controlFiles.has(entry.name)) {
    continue;
  }

  await fs.rename(
    path.join(outDir, entry.name),
    path.join(tempDir, entry.name),
  );
}

await fs.rm(nestedDir, { recursive: true, force: true });
await fs.mkdir(nestedDir, { recursive: true });

for (const entry of await fs.readdir(tempDir)) {
  await fs.rename(path.join(tempDir, entry), path.join(nestedDir, entry));
}

await fs.rmdir(tempDir);

// Doc images are served from R2 via worker/index.ts, not from the static
// export -- public/img is gitignored and normally won't exist at build
// time, but strip it here too in case a locally-gitignored copy (kept
// around for `next dev` previews) is still sitting in public/img when
// someone runs a build. If it survived into out/, Cloudflare would serve
// it directly as a static asset instead of falling through to the R2
// proxy Worker, silently defeating the whole point of the migration
// (stale content, no purge-on-update).
const imgDir = path.join(nestedDir, "img");
if (await pathExists(imgDir)) {
  await fs.rm(imgDir, { recursive: true, force: true });
  console.log(`Stripped ${path.join(basePath, "img")} from static export`);
}

console.log(`Nested static export under out/${basePath}`);
