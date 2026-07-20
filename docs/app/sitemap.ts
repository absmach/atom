import { source } from '@/lib/source';

type Sitemap = {
  url: string;
  changeFrequency: 'weekly';
  priority: number;
}[];

const baseUrl =
  process.env.NEXT_PUBLIC_BASE_URL || 'https://www.absmach.eu/docs/atom';
const normalizedBaseUrl = baseUrl.replace(/\/$/, '');

export const dynamic = 'force-static';

function toSiteUrl(path: string): string {
  const url = `${normalizedBaseUrl}${path.startsWith('/') ? path : `/${path}`}`;
  return url.endsWith('/') ? url : `${url}/`;
}

export default function sitemap(): Sitemap {
  return source.getPages().map((page) => ({
    url: toSiteUrl(page.url),
    changeFrequency: 'weekly',
    priority: 0.7,
  }));
}
