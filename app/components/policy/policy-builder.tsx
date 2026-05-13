"use client";

import { Plus, ShieldAlert, ShieldCheck } from "lucide-react";
import * as React from "react";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { type PolicyDraft, summarizePolicy } from "@/lib/policy/summary";

export function PolicyBuilder() {
  const [draft, setDraft] = React.useState<PolicyDraft>({
    effect: "allow",
    subjectKind: "group",
    subjectName: "floor-sensors",
    grantKind: "capability",
    grantName: "publish",
    scopeKind: "object_type",
    scopeRef: "resource:channel",
    conditions: [
      { path: "resource.attributes.env", operator: "equals", value: "prod" },
    ],
  });

  const summary = summarizePolicy(draft);

  return (
    <Card>
      <CardHeader>
        <CardTitle>Policy Builder Wizard</CardTitle>
        <CardDescription>
          Build RBAC and ABAC bindings with guided scope, effect, and condition
          feedback.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="subject" className="grid gap-4">
          <TabsList className="grid h-auto grid-cols-2 sm:grid-cols-3 lg:grid-cols-6">
            <TabsTrigger value="subject">Subject</TabsTrigger>
            <TabsTrigger value="grant">Grant</TabsTrigger>
            <TabsTrigger value="scope">Scope</TabsTrigger>
            <TabsTrigger value="effect">Effect</TabsTrigger>
            <TabsTrigger value="conditions">Conditions</TabsTrigger>
            <TabsTrigger value="review">Review</TabsTrigger>
          </TabsList>
          <TabsContent value="subject" className="grid gap-4 sm:grid-cols-2">
            <Field label="Subject name">
              <Input
                value={draft.subjectName}
                onChange={(event) =>
                  setDraft({ ...draft, subjectName: event.target.value })
                }
              />
            </Field>
            <Field label="Subject kind">
              <Select
                value={draft.subjectKind}
                onValueChange={(value: "entity" | "group") =>
                  setDraft({ ...draft, subjectKind: value })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="entity">Entity</SelectItem>
                  <SelectItem value="group">Group</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </TabsContent>
          <TabsContent value="grant" className="grid gap-4 sm:grid-cols-2">
            <Field label="Grant">
              <Input
                value={draft.grantName}
                onChange={(event) =>
                  setDraft({ ...draft, grantName: event.target.value })
                }
              />
            </Field>
            <Field label="Grant kind">
              <Select
                value={draft.grantKind}
                onValueChange={(value: "capability" | "role") =>
                  setDraft({ ...draft, grantKind: value })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="capability">Capability</SelectItem>
                  <SelectItem value="role">Role</SelectItem>
                </SelectContent>
              </Select>
            </Field>
          </TabsContent>
          <TabsContent value="scope" className="grid gap-4 sm:grid-cols-2">
            <Field label="Scope kind">
              <Select
                value={draft.scopeKind}
                onValueChange={(value: PolicyDraft["scopeKind"]) =>
                  setDraft({ ...draft, scopeKind: value })
                }
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="platform">Platform</SelectItem>
                  <SelectItem value="tenant">Tenant</SelectItem>
                  <SelectItem value="object_kind">Object kind</SelectItem>
                  <SelectItem value="object_type">Object type</SelectItem>
                  <SelectItem value="object">Specific object</SelectItem>
                </SelectContent>
              </Select>
            </Field>
            <Field label="Scope reference">
              <Input
                value={draft.scopeRef}
                onChange={(event) =>
                  setDraft({ ...draft, scopeRef: event.target.value })
                }
              />
            </Field>
          </TabsContent>
          <TabsContent value="effect" className="grid gap-3 sm:grid-cols-2">
            <button
              type="button"
              className="rounded-lg border p-4 text-left data-[active=true]:border-primary data-[active=true]:bg-primary/5"
              data-active={draft.effect === "allow"}
              onClick={() => setDraft({ ...draft, effect: "allow" })}
            >
              <ShieldCheck className="mb-3 size-5 text-primary" />
              <div className="font-medium">Allow</div>
              <p className="text-sm text-muted-foreground">
                Grants access when scope and conditions match.
              </p>
            </button>
            <button
              type="button"
              className="rounded-lg border p-4 text-left data-[active=true]:border-destructive data-[active=true]:bg-destructive/5"
              data-active={draft.effect === "deny"}
              onClick={() => setDraft({ ...draft, effect: "deny" })}
            >
              <ShieldAlert className="mb-3 size-5 text-destructive" />
              <div className="font-medium">Deny</div>
              <p className="text-sm text-muted-foreground">
                Deny wins over any matching allow policy.
              </p>
            </button>
          </TabsContent>
          <TabsContent value="conditions" className="grid gap-3">
            {draft.conditions.map((condition, index) => (
              <div
                key={`${condition.path}-${condition.value}`}
                className="grid gap-2 rounded-lg border p-3 sm:grid-cols-[1fr_auto_1fr] sm:items-end"
              >
                <Field label="Path">
                  <Input
                    value={condition.path}
                    onChange={(event) => {
                      const conditions = [...draft.conditions];
                      conditions[index] = {
                        ...condition,
                        path: event.target.value,
                      };
                      setDraft({ ...draft, conditions });
                    }}
                  />
                </Field>
                <div className="pb-2 text-sm text-muted-foreground">equals</div>
                <Field label="Value">
                  <Input
                    value={condition.value}
                    onChange={(event) => {
                      const conditions = [...draft.conditions];
                      conditions[index] = {
                        ...condition,
                        value: event.target.value,
                      };
                      setDraft({ ...draft, conditions });
                    }}
                  />
                </Field>
              </div>
            ))}
            <Button
              type="button"
              variant="outline"
              onClick={() =>
                setDraft({
                  ...draft,
                  conditions: [
                    ...draft.conditions,
                    { path: "", operator: "equals", value: "" },
                  ],
                })
              }
            >
              <Plus />
              Add condition
            </Button>
          </TabsContent>
          <TabsContent value="review">
            <div className="rounded-lg border bg-muted/30 p-4">
              <div className="text-sm font-medium">Human-readable policy</div>
              <p className="mt-2 text-lg leading-8">{summary}</p>
              <p className="mt-3 text-sm text-muted-foreground">
                Review highlights:{" "}
                {draft.effect === "deny"
                  ? "deny precedence applies"
                  : "allow requires no matching deny"}
                . Scope and conditions are evaluated online by Atom.
              </p>
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
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
