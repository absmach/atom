// This site is a Next.js static export (see next.config.mjs: output:
// "export") deployed as Cloudflare Workers static assets -- there is no
// Next.js server runtime here, so no @cloudflare/next-on-pages or
// @opennextjs/cloudflare adapter, and no per-request Next.js code path to
// hang an R2 lookup off of. This tiny Worker sits in front of the static
// assets (see wrangler.jsonc: "main" + "assets.binding") purely to serve
// doc images from the shared R2 bucket instead of the git repo.
//
// Cloudflare's default asset routing (run_worker_first: false, the
// default -- see wrangler.jsonc) serves a request directly from the
// assets directory whenever a matching file exists, and only invokes this
// Worker when nothing matches. Doc images are no longer part of the
// static export output (scripts/nest-static-export.mjs strips
// out/docs/atom/img/ as a defensive measure even though public/img/ is
// gitignored and normally won't be present at build time), so every
// request under the docs img path automatically falls through to here.
// Everything else that reaches this Worker is a genuine 404, deferred to
// the assets binding's own not-found handling.
interface Env {
  ASSETS: Fetcher;
  IMAGES_BUCKET: R2Bucket;
}

// Matches the Next.js basePath ("/docs/atom", see next.config.mjs) plus
// the literal "/img/..." convention doc content already uses in
// content/docs/**/*.mdx (e.g. "![](/img/user-guide/roles/roles-list.png)").
// Keep in sync with scripts/publish-image.mjs.
const IMG_PREFIX = "/docs/atom/img/";

// Shared bucket ("websites-images") holds assets for multiple properties;
// this prefix keeps atom-docs' objects from colliding with the others.
const R2_KEY_PREFIX = "atom-docs";

function notFound(): Response {
  return new Response("Not found", {
    status: 404,
    headers: { "content-type": "text/plain", "cache-control": "no-store" },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (!url.pathname.startsWith(IMG_PREFIX)) {
      return env.ASSETS.fetch(request);
    }

    const key = `${R2_KEY_PREFIX}/${url.pathname.slice(IMG_PREFIX.length)}`;
    const object = await env.IMAGES_BUCKET.get(key);
    if (!object) return notFound();

    const headers = new Headers();
    object.writeHttpMetadata(headers);
    headers.set("etag", object.httpEtag);
    headers.set("content-length", String(object.size));
    // Short browser TTL (revalidates quickly) + long edge TTL (until
    // purged explicitly by scripts/publish-image.mjs on upload).
    headers.set("cache-control", "public, max-age=300, s-maxage=31536000");

    return new Response(object.body, { headers });
  },
};
