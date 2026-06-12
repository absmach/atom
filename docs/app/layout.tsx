import type { ReactNode } from 'react';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { Metadata } from 'next';
import { baseOptions } from '@/app/layout.config';
import { source } from '@/lib/source';
import { Provider } from '@/components/provider';
import 'fumadocs-ui/style.css';
import './global.css';

export const metadata: Metadata = {
  title: {
    template: '%s | Atom',
    default: 'Atom Docs',
  },
  description: 'Identity and Authorization service for IoT and cloud-native systems',
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <Provider>
          <DocsLayout tree={source.pageTree} {...baseOptions}>
            {children}
          </DocsLayout>
        </Provider>
      </body>
    </html>
  );
}
