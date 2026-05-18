import type { Metadata } from "next";
import { GraphqlPlayground } from "@/components/playground/graphql-playground";

export const metadata: Metadata = { title: "Playground" };

export default function DeveloperPlaygroundPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">Playground</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          Compose, run, inspect, and reuse authenticated Atom GraphQL requests.
        </p>
      </div>
      <GraphqlPlayground />
    </section>
  );
}
