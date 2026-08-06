import { defineDocs, defineConfig } from 'fumadocs-mdx/config';

export const { docs, meta } = defineDocs({
  dir: 'content/docs',
});

export default defineConfig({
  mdxOptions: {
    // Doc images are served from R2 via a same-origin proxy route (see
    // docs/worker/index.ts) rather than committed to public/img and bundled
    // by next/image. The default remark-image plugin needs the source file
    // on local disk (either to import it as a static asset, or just to
    // probe its dimensions) -- disabling it keeps "/img/..." src strings in
    // MDX content literal instead. Width/height come from
    // lib/image-dimensions.json instead (see components/doc-image.tsx).
    remarkImageOptions: false,
  },
});
