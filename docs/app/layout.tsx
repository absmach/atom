import type { ReactNode } from 'react';
import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { Metadata } from 'next';
import { Rubik } from 'next/font/google';
import { baseOptions } from '@/app/layout.config';
import { source } from '@/lib/source';
import { Provider } from '@/components/provider';
import 'fumadocs-ui/style.css';
import './global.css';

const rubik = Rubik({ subsets: ['latin'], variable: '--font-rubik' });

export const metadata: Metadata = {
  title: {
    template: '%s | Atom',
    default: 'Atom Docs',
  },
  description: 'Identity and Authorization service for IoT and cloud-native systems',
};

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" className={rubik.variable} suppressHydrationWarning>
      <body className={rubik.className}>
        <Provider>
          <DocsLayout tree={source.getPageTree()} {...baseOptions}>
            {children}
          </DocsLayout>
        </Provider>
      </body>
    </html>
  );
}
