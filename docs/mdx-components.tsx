import defaultComponents from 'fumadocs-ui/mdx';
import { Steps, Step } from 'fumadocs-ui/components/steps';
import { Card, Cards } from 'fumadocs-ui/components/card';
import { Callout } from 'fumadocs-ui/components/callout';
import { Tab, Tabs } from 'fumadocs-ui/components/tabs';
import type { MDXComponents } from 'mdx/types';
import { Mermaid } from './components/mermaid';
import { DocImage } from './components/doc-image';

export function useMDXComponents(components: MDXComponents): MDXComponents {
  return {
    ...defaultComponents,
    Steps,
    Step,
    Card,
    Cards,
    Callout,
    Mermaid,
    Tab,
    Tabs,
    // Overrides defaultComponents' next/image-backed img -- see
    // components/doc-image.tsx for why.
    img: DocImage,
    ...components,
  };
}
