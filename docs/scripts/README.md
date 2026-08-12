# Publishing doc images (maintainers only)

Doc images are no longer committed to this repo. They're stored in a shared Cloudflare R2
bucket (`websites-images`, under the `atom-docs/` key prefix so they don't collide with other
properties in the same bucket) and served at their usual `/docs/atom/img/...` URLs by
[`worker/index.ts`](../worker/index.ts), a small Worker that sits in front of this site's
static assets.

## Why a Worker exists here at all

This site is a Next.js **static export** (`output: 'export'` in `next.config.mjs`) deployed
as plain Cloudflare Workers static assets -- there's no Next.js server runtime in production,
so nothing like `@cloudflare/next-on-pages` or `@opennextjs/cloudflare` applies, and no
per-request Next.js code path exists to hang an R2 lookup off of. `worker/index.ts` is a
minimal, hand-written Worker (not part of Next.js) that Cloudflare only invokes as a fallback
when a request doesn't match a static asset (`run_worker_first: false`, the default -- see
`wrangler.jsonc`). Doc images aren't part of the static export output, so every request under
`/docs/atom/img/...` falls through to it automatically; everything else (every actual page,
`_next/static`, etc.) is served directly from the assets directory without ever touching this
Worker.

## Why doc images also needed an MDX change

Fumadocs' default MDX pipeline (`remark-image`, `useImport: true`) turns
`![alt](/img/foo.png)` into a static `import` of the file from `public/`, which Next bundles
into a content-hashed `_next/static/media/<hash>.png` URL at build time. That requires the
source file on local disk at build time, and the URL changes every time the image's content
changes -- neither works once the file only lives in R2. `source.config.ts` disables that
plugin (`remarkImageOptions: false`), so `/img/...` paths in MDX stay literal, and
[`components/doc-image.tsx`](../components/doc-image.tsx) renders them as a plain, zoomable
`<img>` (`fumadocs-ui`'s `ImageZoom` wrapping a plain element, not `next/image`) -- the `src`
is still basePath-prefixed manually, same pattern as `components/search.tsx`, but there's no
width/height requirement and nothing to keep in sync when an image changes.

**Authoring is unchanged** -- MDX content already referenced doc images by their final
`/img/...` path from the start (there was never a relative-path convention to preserve here),
so nothing about how you write `![alt](/img/foo.png)` needs to change.

## One-time setup

1. Create `scripts/.env.publish-image` from the template:

   ```bash
   cp scripts/.env.publish-image.example scripts/.env.publish-image
   ```

2. Create a Cloudflare API token: dashboard -> **My Profile -> API Tokens -> Create Token ->
   Custom Token**, with both permissions on the same token:
   - `Workers R2 Storage: Edit`
   - `Zone -> Cache Purge -> Purge`, **Zone Resources** scoped to the `absmach.eu` zone

   (If you already hold the token used for the main `absmach-website` repo's
   `publish-image` script, it covers the same bucket and zone -- you can reuse it here
   instead of creating a new one.)

3. Paste the token into `CLOUDFLARE_API_TOKEN` in `scripts/.env.publish-image`. The zone ID is
   already filled in (it's not secret, safe to share/commit -- it can't authenticate anything
   by itself).

4. Sanity-check the token before first use:

   ```bash
   curl -s https://api.cloudflare.com/client/v4/user/tokens/verify \
     -H "Authorization: Bearer $CLOUDFLARE_API_TOKEN"
   ```

   Should return `"status":"active"`. If it doesn't, the token value itself is wrong (bad
   copy/paste, expired, revoked) -- fix that before troubleshooting anything else.

`scripts/.env.publish-image` is gitignored. Never commit it, never paste the token value into
a PR, issue, or chat.

## Publishing an image

```bash
pnpm run publish-image <local-file> <public-path>
```

`<public-path>` must start with `img/` and match the path already written (or about to be
written) into the MDX content, e.g.:

```bash
pnpm run publish-image ./roles-list.png img/user-guide/roles/roles-list-populated.png
# -> https://www.absmach.eu/docs/atom/img/user-guide/roles/roles-list-populated.png
# -> reference in MDX as: ![Roles list](/img/user-guide/roles/roles-list-populated.png)
```

The script does two things, in order:

1. `wrangler r2 object put ... --remote` -- uploads to the **real** bucket. `--remote` is
   required; without it, `wrangler` silently writes to a local simulated bucket and prints a
   normal-looking "Upload complete" with no error, and the object is never actually live.
2. Purges that exact URL from Cloudflare's edge cache (`POST /zones/{id}/purge_cache`), so the
   update is visible within seconds instead of waiting out the cache TTL.

If you re-run the same command for an existing path, it overwrites the object in place and
purges again -- that's the intended way to update an image without changing its URL.

## Local development

`public/img/` is gitignored. For a `next dev` preview with working images, drop the file
there locally under the same path used in MDX (e.g. `public/img/user-guide/roles/foo.png` for
`/img/user-guide/roles/foo.png`) -- Next's dev server serves `public/` under the site's
basePath automatically, so it resolves at the exact same URL production does. It just won't be
committed, and `pnpm run build`'s `nest-static-export.mjs` step strips `public/img` from the
deployed output either way, so a leftover local copy can never accidentally ship instead of
the R2-backed version.

To test the actual production path -- Worker + static assets + R2 binding together, the way
Cloudflare will actually serve it -- run:

```bash
pnpm run preview   # builds, then `wrangler dev`
```

By default this talks to a local simulated R2 bucket (empty unless you've seeded it with
`wrangler r2 object put ... --local`). Add `"remote": true` to the `r2_buckets` binding in
`wrangler.jsonc` temporarily if you want `wrangler dev` to read the real bucket instead.

## Migrating the existing images (one-time, already done)

The 88 images removed from `public/img/` have already been uploaded to the real R2 bucket and
spot-checked byte-for-byte against the originals. Nothing further to do here unless an image
needs updating -- use `publish-image` for that, same as any other image.

## Why maintainer-only

This repo is public. The risk isn't the script being visible -- it's inert without a
credential. The risk is _credential distribution_: whoever holds `CLOUDFLARE_API_TOKEN` can
write to the shared bucket. So nobody, internal or external, gets a personal R2 token. Only a
maintainer, holding this one scoped token, runs `publish-image`.

Practical flow for a PR that adds a doc image: the contributor attaches the image to the PR
description or a comment the normal GitHub way. A maintainer reviewing the PR runs
`pnpm run publish-image` locally before merging, then approves.

## Troubleshooting

- **`Local file not found: --`** -- you ran `pnpm run publish-image -- <file> <dest>`. pnpm
  forwards a leading `--` to the script literally instead of stripping it like npm does. The
  script strips it defensively now, but plain `pnpm run publish-image <file> <dest>` (no `--`)
  is the form to use.
- **`Destination must start with "img/"`** -- the second argument is the path as it appears
  after `/docs/atom/` in the final URL (and after the leading `/` in MDX `src`), e.g.
  `img/user-guide/roles/foo.png`, not `user-guide/roles/foo.png` or a full URL.
- **`Resource location: local` in the upload output** -- means `--remote` didn't get applied
  for some reason (e.g. running the underlying `wrangler` command by hand without copying the
  full flag list from the script). The object was never written to the real bucket even though
  the CLI reports success. Always use `pnpm run publish-image`, or add `--remote` yourself if
  invoking wrangler directly.
- **`Cache purge failed` / `Authentication error` (code 10000)** -- Cloudflare reuses this code
  for both "bad token" and "token valid but missing this permission." Run the token verify curl
  command above first to rule out a bad token. If that succeeds, the token is missing
  `Zone -> Cache Purge -> Purge` for the `absmach.eu` zone, or that permission's Zone Resources
  selector doesn't include it -- edit the token in the dashboard and add it.
- To confirm an object actually made it into the bucket after a `--remote` upload:

  ```bash
  wrangler r2 object get websites-images/atom-docs/<path-after-img/> --remote --file=/tmp/check
  ```
