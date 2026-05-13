"use client";

import { useMutation } from "@tanstack/react-query";
import { AlertTriangle, CheckCircle2, Play, XCircle } from "lucide-react";
import * as React from "react";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";

const EXPLAIN_MUTATION = `
mutation Explain($input: AuthzCheckInput!) {
  authzExplain(input: $input) {
    allowed
    reason
    matchedBinding { id effect result via scopeKind scopeRef grantKind }
    evaluatedBindings { id effect result via scopeKind scopeRef grantKind reason }
  }
}
`;

type ExplainResponse = {
  authzExplain: {
    allowed: boolean;
    reason: string;
    matchedBinding?: Record<string, unknown> | null;
    evaluatedBindings: Array<Record<string, unknown>>;
  };
};

export function AuthzDebugger() {
  const [subjectId, setSubjectId] = React.useState("");
  const [action, setAction] = React.useState("publish");
  const [resourceId, setResourceId] = React.useState("");
  const [context, setContext] = React.useState('{"env":"prod"}');

  const explain = useMutation({
    mutationFn: async () =>
      graphqlClient<ExplainResponse>({
        query: EXPLAIN_MUTATION,
        variables: {
          input: {
            subjectId,
            action,
            resourceId: resourceId || null,
            context: JSON.parse(context || "{}"),
          },
        },
      }),
  });

  const result = explain.data?.authzExplain;

  return (
    <div className="grid gap-4 xl:grid-cols-[420px_1fr]">
      <Card>
        <CardHeader>
          <CardTitle>Authorization Debugger</CardTitle>
          <CardDescription>
            Ask Atom why an action is allowed or denied.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          <Field label="Subject entity ID">
            <Input
              value={subjectId}
              onChange={(event) => setSubjectId(event.target.value)}
            />
          </Field>
          <Field label="Action">
            <Input
              value={action}
              onChange={(event) => setAction(event.target.value)}
            />
          </Field>
          <Field label="Resource ID">
            <Input
              value={resourceId}
              onChange={(event) => setResourceId(event.target.value)}
            />
          </Field>
          <Field label="Context JSON">
            <Textarea
              value={context}
              onChange={(event) => setContext(event.target.value)}
              className="font-mono text-xs"
            />
          </Field>
          <Button
            onClick={() => explain.mutate()}
            disabled={!subjectId || !action || explain.isPending}
          >
            <Play />
            Run explain
          </Button>
        </CardContent>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            {result?.allowed ? (
              <CheckCircle2 className="text-primary" />
            ) : result ? (
              <XCircle className="text-destructive" />
            ) : (
              <AlertTriangle className="text-muted-foreground" />
            )}
            Decision trace
          </CardTitle>
          <CardDescription>
            DENY precedence, ABAC conditions, role expansion, and group-derived
            permissions surface here when returned by the service.
          </CardDescription>
        </CardHeader>
        <CardContent className="grid gap-4">
          {explain.isError ? (
            <Alert variant="destructive">
              <AlertTriangle className="size-4" />
              <AlertTitle>Explain failed</AlertTitle>
              <AlertDescription>{explain.error.message}</AlertDescription>
            </Alert>
          ) : null}
          {result ? (
            <>
              <div className="rounded-lg border p-4">
                <Badge variant={result.allowed ? "default" : "destructive"}>
                  {result.allowed ? "Allowed" : "Denied"}
                </Badge>
                <p className="mt-3 text-lg">{result.reason}</p>
              </div>
              <TraceList
                title="Matched policy"
                items={result.matchedBinding ? [result.matchedBinding] : []}
              />
              <TraceList
                title="Evaluated bindings"
                items={result.evaluatedBindings ?? []}
              />
            </>
          ) : (
            <div className="rounded-lg border border-dashed p-8 text-center text-sm text-muted-foreground">
              Run a check to see the policy trace.
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-2">
      <Label>{label}</Label>
      {children}
    </div>
  );
}

function TraceList({
  title,
  items,
}: {
  title: string;
  items: Array<Record<string, unknown>>;
}) {
  return (
    <div className="grid gap-2">
      <div className="text-sm font-medium">{title}</div>
      {items.length ? (
        items.map((item) => (
          <div
            key={`${title}-${String(item.id ?? item.scopeRef ?? JSON.stringify(item))}`}
            className="grid gap-1 rounded-lg border p-3 text-sm"
          >
            <div className="flex flex-wrap gap-2">
              <Badge
                variant={item.effect === "deny" ? "destructive" : "secondary"}
              >
                {String(item.effect ?? "binding")}
              </Badge>
              <Badge variant="outline">
                {String(item.result ?? "evaluated")}
              </Badge>
              {item.via ? (
                <Badge variant="outline">{String(item.via)}</Badge>
              ) : null}
            </div>
            <div className="text-muted-foreground">
              {String(item.grantKind ?? "grant")} over{" "}
              {String(item.scopeKind ?? "scope")} {String(item.scopeRef ?? "")}
            </div>
          </div>
        ))
      ) : (
        <div className="rounded-lg border border-dashed p-3 text-sm text-muted-foreground">
          No bindings returned.
        </div>
      )}
    </div>
  );
}
