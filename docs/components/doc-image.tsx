import { ImageZoom } from "fumadocs-ui/components/image-zoom";
import type { ImgHTMLAttributes } from "react";

// Doc content images (content/docs/**/*.mdx) are no longer bundled by
// Next.js's image pipeline (see source.config.ts: remarkImageOptions is
// disabled). They're stored in the shared Cloudflare R2 bucket and served
// same-origin at their usual "/img/..." path -- see docs/wrangler.jsonc and
// worker/index.ts. Rendered as a plain, zoomable <img> -- no next/image, no
// width/height needed, so there's nothing to keep in sync when images
// change.
const BASE_PATH = process.env.NEXT_PUBLIC_BASE_PATH ?? "";

export function DocImage({
  src,
  alt,
  className,
  ...props
}: ImgHTMLAttributes<HTMLImageElement>) {
  if (typeof src !== "string") return null;

  const resolvedSrc = src.startsWith("/") ? `${BASE_PATH}${src}` : src;

  return (
    // src/alt passed here too, not just to the inner <img>: ImageZoom's
    // zoomed-in view reads its image from these props directly, not from
    // `children` -- omitting them renders a blank zoomed-in image even
    // though the inline thumbnail (via children) looks correct.
    <ImageZoom src={resolvedSrc} alt={alt ?? ""}>
      {/* biome-ignore lint/performance/noImgElement: doc content images are served from R2, not Next's image pipeline */}
      <img
        {...props}
        src={resolvedSrc}
        alt={alt ?? ""}
        loading="lazy"
        className={["rounded-lg", className].filter(Boolean).join(" ")}
      />
    </ImageZoom>
  );
}
