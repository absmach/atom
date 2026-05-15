import type { Metadata } from "next";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export const metadata: Metadata = { title: "Playground" };

export default function DeveloperPlaygroundPage() {
  return (
    <section className="grid gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-semibold tracking-tight">Playground</h1>
        <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
          A developer request playground for testing custom endpoints will live
          here.
        </p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Coming soon</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground">
          Endpoint request execution and response inspection will be added in a
          later step.
        </CardContent>
      </Card>
    </section>
  );
}
