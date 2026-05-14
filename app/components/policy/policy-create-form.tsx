"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import {
  ChevronLeft,
  ChevronRight,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import {
  PolicySummary,
  type ScopeKind,
} from "@/components/policy/policy-summary";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { graphqlClient } from "@/lib/graphql/client";

// ─── GraphQL ─────────────────────────────────────────────────────────────────

const CREATE_POLICY_MUTATION = `
  mutation CreatePolicy($input: CreatePolicyInput!) {
    createPolicy(input: $input) {
      id subjectKind subjectId grantKind grantId scopeKind scopeRef effect conditions createdAt
    }
  }
`;

const DELETE_POLICY_MUTATION = `
  mutation DeletePolicy($id: ID!) { deletePolicy(id: $id) }
`;

const ENTITIES_QUERY = `
  query PolicyFormEntities {
    entities(limit: 200, offset: 0) { items { id name kind } }
  }
`;
const GROUPS_QUERY = `
  query PolicyFormGroups {
    groups(limit: 200, offset: 0) { items { id name } }
  }
`;
const CAPABILITIES_QUERY = `
  query PolicyFormCapabilities {
    capabilities(limit: 200, offset: 0) { items { id name resourceKind } }
  }
`;
const ROLES_QUERY = `
  query PolicyFormRoles {
    roles(limit: 200, offset: 0) { items { id name } }
  }
`;
const TENANTS_QUERY = `
  query PolicyFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;
const RESOURCES_QUERY = `
  query PolicyFormResources {
    resources(limit: 200, offset: 0) { items { id name kind } }
  }
`;

// ─── Types ────────────────────────────────────────────────────────────────────

type IdName = { id: string; name: string };

type WizardState = {
  effect: "allow" | "deny";
  subjectKind: "entity" | "group";
  subjectId: string;
  subjectLabel: string;
  grantKind: "capability" | "role";
  grantId: string;
  grantLabel: string;
  scopeKind: ScopeKind;
  scopeRef: string;
  scopeLabel: string;
  conditions: Array<{ path: string; value: string }>;
};

const EMPTY: WizardState = {
  effect: "allow",
  subjectKind: "entity",
  subjectId: "",
  subjectLabel: "",
  grantKind: "capability",
  grantId: "",
  grantLabel: "",
  scopeKind: "platform",
  scopeRef: "",
  scopeLabel: "",
  conditions: [],
};

const STEPS = [
  "effect",
  "subject",
  "grant",
  "scope",
  "conditions",
  "review",
] as const;
type Step = (typeof STEPS)[number];

const STEP_LABELS: Record<Step, string> = {
  effect: "Effect",
  subject: "Subject",
  grant: "Grant",
  scope: "Scope",
  conditions: "Conditions",
  review: "Review",
};

// ─── Types ────────────────────────────────────────────────────────────────────

export type PolicyRow = {
  id: string;
  effect: string;
  subjectKind: string;
  subjectId: string;
  grantKind: string;
  grantId: string;
  scopeKind: string;
  scopeRef?: string | null;
  conditions?: unknown;
};

// ─── Component ───────────────────────────────────────────────────────────────

export function PolicyCreateForm({
  onCancel,
  onSaved,
  initialPolicy,
}: {
  onCancel: () => void;
  onSaved: () => void;
  initialPolicy?: PolicyRow;
}) {
  const isEditing = Boolean(initialPolicy);
  const [stepIdx, setStepIdx] = React.useState(0);
  const [draft, setDraft] = React.useState<WizardState>(() =>
    initialPolicy ? rowToWizardState(initialPolicy) : EMPTY,
  );
  const step = STEPS[stepIdx];

  const entitiesQ = useQuery({
    queryKey: ["policy-form-entities"],
    queryFn: ({ signal }) =>
      graphqlClient<{ entities: { items: (IdName & { kind: string })[] } }>({
        query: ENTITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const groupsQ = useQuery({
    queryKey: ["policy-form-groups"],
    queryFn: ({ signal }) =>
      graphqlClient<{ groups: { items: IdName[] } }>({
        query: GROUPS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const capsQ = useQuery({
    queryKey: ["policy-form-capabilities"],
    queryFn: ({ signal }) =>
      graphqlClient<{
        capabilities: { items: (IdName & { resourceKind: string | null })[] };
      }>({
        query: CAPABILITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const rolesQ = useQuery({
    queryKey: ["policy-form-roles"],
    queryFn: ({ signal }) =>
      graphqlClient<{ roles: { items: IdName[] } }>({
        query: ROLES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const tenantsQ = useQuery({
    queryKey: ["policy-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: IdName[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const resourcesQ = useQuery({
    queryKey: ["policy-form-resources"],
    queryFn: ({ signal }) =>
      graphqlClient<{ resources: { items: (IdName & { kind: string })[] } }>({
        query: RESOURCES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const entities = entitiesQ.data?.entities.items ?? [];
  const groups = groupsQ.data?.groups.items ?? [];
  const capabilities = capsQ.data?.capabilities.items ?? [];
  const roles = rolesQ.data?.roles.items ?? [];
  const tenants = tenantsQ.data?.tenants.items ?? [];
  const resources = resourcesQ.data?.resources.items ?? [];

  // Resolve display labels from loaded lists when in edit mode
  React.useEffect(() => {
    if (!isEditing) return;
    setDraft((prev) => {
      let next = { ...prev };
      if (!prev.subjectLabel && prev.subjectId) {
        const opts = prev.subjectKind === "entity" ? entities : groups;
        const item = opts.find((o) => o.id === prev.subjectId);
        if (item) next = { ...next, subjectLabel: item.name };
      }
      if (!prev.grantLabel && prev.grantId) {
        if (prev.grantKind === "capability") {
          const cap = capabilities.find((c) => c.id === prev.grantId);
          if (cap)
            next = {
              ...next,
              grantLabel: cap.resourceKind
                ? `${cap.name} (${cap.resourceKind})`
                : cap.name,
            };
        } else {
          const r = roles.find((r) => r.id === prev.grantId);
          if (r) next = { ...next, grantLabel: r.name };
        }
      }
      if (!prev.scopeLabel && prev.scopeRef) {
        if (prev.scopeKind === "tenant") {
          const t = tenants.find((t) => t.id === prev.scopeRef);
          if (t) next = { ...next, scopeLabel: t.name };
        } else if (prev.scopeKind === "object") {
          const res = resources.find((r) => r.id === prev.scopeRef);
          if (res) next = { ...next, scopeLabel: `${res.name} (${res.kind})` };
        } else {
          next = { ...next, scopeLabel: prev.scopeRef };
        }
      }
      return next;
    });
  }, [entities, groups, capabilities, roles, tenants, resources, isEditing]);

  const resourceKinds = [
    ...new Set(resources.map((r) => r.kind).filter(Boolean)),
  ].sort();

  const save = useMutation({
    mutationFn: async () => {
      const conditions =
        draft.conditions.filter((c) => c.path && c.value).length > 0
          ? draft.conditions
              .filter((c) => c.path && c.value)
              .map((c) => ({
                path: c.path,
                operator: "equals",
                value: c.value,
              }))
          : undefined;

      if (isEditing && initialPolicy) {
        await graphqlClient({
          query: DELETE_POLICY_MUTATION,
          variables: { id: initialPolicy.id },
        });
      }

      return graphqlClient({
        query: CREATE_POLICY_MUTATION,
        variables: {
          input: {
            subjectKind: draft.subjectKind,
            subjectId: draft.subjectId,
            grantKind: draft.grantKind,
            grantId: draft.grantId,
            scopeKind: draft.scopeKind,
            scopeRef: draft.scopeRef || undefined,
            effect: draft.effect,
            conditions: conditions ? JSON.stringify(conditions) : undefined,
          },
        },
      });
    },
    onSuccess: () => {
      toast.success(
        isEditing ? "Policy binding updated" : "Policy binding created",
      );
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  function canAdvance() {
    if (step === "subject") return Boolean(draft.subjectId);
    if (step === "grant") return Boolean(draft.grantId);
    if (step === "scope") {
      if (draft.scopeKind === "platform") return true;
      return Boolean(draft.scopeRef);
    }
    return true;
  }

  const isFirst = stepIdx === 0;
  const isLast = stepIdx === STEPS.length - 1;

  return (
    <div className="grid gap-6">
      {/* Step indicator */}
      <div className="flex items-center gap-1">
        {STEPS.map((s, i) => (
          <React.Fragment key={s}>
            <button
              type="button"
              onClick={() => i < stepIdx && setStepIdx(i)}
              className={[
                "flex h-7 min-w-7 items-center justify-center rounded-full px-2 text-xs font-medium transition-colors",
                i === stepIdx
                  ? "bg-primary text-primary-foreground"
                  : i < stepIdx
                    ? "cursor-pointer bg-primary/20 text-primary hover:bg-primary/30"
                    : "bg-muted text-muted-foreground",
              ].join(" ")}
            >
              {i < stepIdx ? "✓" : i + 1}
            </button>
            <span
              className={[
                "text-xs",
                i === stepIdx ? "font-medium" : "text-muted-foreground",
              ].join(" ")}
            >
              {STEP_LABELS[s]}
            </span>
            {i < STEPS.length - 1 && (
              <div className="mx-1 h-px flex-1 bg-border" />
            )}
          </React.Fragment>
        ))}
      </div>

      {/* Step content */}
      <div className="min-h-48">
        {step === "effect" && <EffectStep draft={draft} onChange={setDraft} />}
        {step === "subject" && (
          <SubjectStep
            draft={draft}
            onChange={setDraft}
            entities={entities}
            groups={groups}
          />
        )}
        {step === "grant" && (
          <GrantStep
            draft={draft}
            onChange={setDraft}
            capabilities={capabilities}
            roles={roles}
          />
        )}
        {step === "scope" && (
          <ScopeStep
            draft={draft}
            onChange={setDraft}
            tenants={tenants}
            resources={resources}
            resourceKinds={resourceKinds}
          />
        )}
        {step === "conditions" && (
          <ConditionsStep draft={draft} onChange={setDraft} />
        )}
        {step === "review" && <ReviewStep draft={draft} />}
      </div>

      {/* Navigation */}
      <div className="flex justify-between gap-2">
        <Button
          type="button"
          variant="outline"
          onClick={isFirst ? onCancel : () => setStepIdx((i) => i - 1)}
        >
          {isFirst ? (
            "Cancel"
          ) : (
            <>
              <ChevronLeft className="size-4" />
              Back
            </>
          )}
        </Button>
        {isLast ? (
          <Button
            type="button"
            disabled={save.isPending}
            onClick={() => save.mutate()}
          >
            {isEditing ? "Save changes" : "Create policy"}
          </Button>
        ) : (
          <Button
            type="button"
            disabled={!canAdvance()}
            onClick={() => setStepIdx((i) => i + 1)}
          >
            Next
            <ChevronRight className="size-4" />
          </Button>
        )}
      </div>
    </div>
  );
}

// ─── Step: Effect ─────────────────────────────────────────────────────────────

function EffectStep({
  draft,
  onChange,
}: {
  draft: WizardState;
  onChange: (d: WizardState) => void;
}) {
  return (
    <div className="grid gap-3 sm:grid-cols-2">
      <button
        type="button"
        className="rounded-lg border p-4 text-left transition-colors data-[active=true]:border-primary data-[active=true]:bg-primary/5"
        data-active={draft.effect === "allow"}
        onClick={() => onChange({ ...draft, effect: "allow" })}
      >
        <ShieldCheck className="mb-3 size-5 text-primary" />
        <div className="font-medium">Allow</div>
        <p className="text-sm text-muted-foreground">
          Grants access when scope and conditions match.
        </p>
      </button>
      <button
        type="button"
        className="rounded-lg border p-4 text-left transition-colors data-[active=true]:border-destructive data-[active=true]:bg-destructive/5"
        data-active={draft.effect === "deny"}
        onClick={() => onChange({ ...draft, effect: "deny" })}
      >
        <ShieldAlert className="mb-3 size-5 text-destructive" />
        <div className="font-medium">Deny</div>
        <p className="text-sm text-muted-foreground">
          Deny wins over any matching allow policy.
        </p>
      </button>
    </div>
  );
}

// ─── Step: Subject ────────────────────────────────────────────────────────────

function SubjectStep({
  draft,
  onChange,
  entities,
  groups,
}: {
  draft: WizardState;
  onChange: (d: WizardState) => void;
  entities: (IdName & { kind: string })[];
  groups: IdName[];
}) {
  const options = draft.subjectKind === "entity" ? entities : groups;

  return (
    <div className="grid gap-4">
      <FormRow label="Subject kind">
        <Select
          value={draft.subjectKind}
          onValueChange={(v: "entity" | "group") =>
            onChange({
              ...draft,
              subjectKind: v,
              subjectId: "",
              subjectLabel: "",
            })
          }
        >
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="entity">Entity</SelectItem>
            <SelectItem value="group">Group</SelectItem>
          </SelectContent>
        </Select>
      </FormRow>
      <FormRow label={draft.subjectKind === "entity" ? "Entity" : "Group"}>
        <Select
          value={draft.subjectId || undefined}
          onValueChange={(id) => {
            const item = options.find((o) => o.id === id);
            onChange({
              ...draft,
              subjectId: id,
              subjectLabel: item?.name ?? id,
            });
          }}
        >
          <SelectTrigger className="w-full">
            <SelectValue placeholder={`— select ${draft.subjectKind} —`} />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o.id} value={o.id}>
                {"kind" in o
                  ? `${o.name} (${(o as { kind: string }).kind})`
                  : o.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FormRow>
    </div>
  );
}

// ─── Step: Grant ──────────────────────────────────────────────────────────────

function GrantStep({
  draft,
  onChange,
  capabilities,
  roles,
}: {
  draft: WizardState;
  onChange: (d: WizardState) => void;
  capabilities: (IdName & { resourceKind: string | null })[];
  roles: IdName[];
}) {
  const options = draft.grantKind === "capability" ? capabilities : roles;

  return (
    <div className="grid gap-4">
      <FormRow label="Grant kind">
        <Select
          value={draft.grantKind}
          onValueChange={(v: "capability" | "role") =>
            onChange({ ...draft, grantKind: v, grantId: "", grantLabel: "" })
          }
        >
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="capability">Capability</SelectItem>
            <SelectItem value="role">Role</SelectItem>
          </SelectContent>
        </Select>
      </FormRow>
      <FormRow label={draft.grantKind === "capability" ? "Capability" : "Role"}>
        <Select
          value={draft.grantId || undefined}
          onValueChange={(id) => {
            const item = options.find((o) => o.id === id);
            const cap =
              draft.grantKind === "capability" && item
                ? capabilities.find((c) => c.id === id)
                : undefined;
            const label = cap
              ? `${cap.name}${cap.resourceKind ? ` (${cap.resourceKind})` : ""}`
              : (item?.name ?? id);
            onChange({ ...draft, grantId: id, grantLabel: label });
          }}
        >
          <SelectTrigger className="w-full">
            <SelectValue placeholder={`— select ${draft.grantKind} —`} />
          </SelectTrigger>
          <SelectContent>
            {options.map((o) => (
              <SelectItem key={o.id} value={o.id}>
                {"resourceKind" in o &&
                (o as { resourceKind: string | null }).resourceKind
                  ? `${o.name} (${(o as { resourceKind: string | null }).resourceKind})`
                  : o.name}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </FormRow>
    </div>
  );
}

// ─── Step: Scope ──────────────────────────────────────────────────────────────

function ScopeStep({
  draft,
  onChange,
  tenants,
  resources,
  resourceKinds,
}: {
  draft: WizardState;
  onChange: (d: WizardState) => void;
  tenants: IdName[];
  resources: (IdName & { kind: string })[];
  resourceKinds: string[];
}) {
  const needsRef = draft.scopeKind !== "platform";
  const isTextRef =
    draft.scopeKind === "object_kind" || draft.scopeKind === "object_type";

  return (
    <div className="grid gap-4">
      <FormRow label="Scope kind">
        <Select
          value={draft.scopeKind}
          onValueChange={(v: ScopeKind) =>
            onChange({ ...draft, scopeKind: v, scopeRef: "", scopeLabel: "" })
          }
        >
          <SelectTrigger className="w-full">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="platform">
              Platform — applies everywhere
            </SelectItem>
            <SelectItem value="tenant">Tenant — scoped to a tenant</SelectItem>
            <SelectItem value="object_kind">
              Object kind — all objects of a kind
            </SelectItem>
            <SelectItem value="object_type">
              Object type — all resources of a type
            </SelectItem>
            <SelectItem value="object">
              Specific object — one resource
            </SelectItem>
          </SelectContent>
        </Select>
      </FormRow>

      {draft.scopeKind === "tenant" && (
        <FormRow label="Tenant">
          <Select
            value={draft.scopeRef || undefined}
            onValueChange={(id) => {
              const t = tenants.find((t) => t.id === id);
              onChange({ ...draft, scopeRef: id, scopeLabel: t?.name ?? id });
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="— select tenant —" />
            </SelectTrigger>
            <SelectContent>
              {tenants.map((t) => (
                <SelectItem key={t.id} value={t.id}>
                  {t.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FormRow>
      )}

      {isTextRef && (
        <FormRow label="Resource kind">
          <Select
            value={draft.scopeRef || undefined}
            onValueChange={(v) => {
              onChange({ ...draft, scopeRef: v, scopeLabel: v });
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="— select resource kind —" />
            </SelectTrigger>
            <SelectContent>
              {resourceKinds.map((k) => (
                <SelectItem key={k} value={k}>
                  {k}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FormRow>
      )}

      {draft.scopeKind === "object" && (
        <FormRow label="Resource">
          <Select
            value={draft.scopeRef || undefined}
            onValueChange={(id) => {
              const r = resources.find((r) => r.id === id);
              onChange({
                ...draft,
                scopeRef: id,
                scopeLabel: r ? `${r.name} (${r.kind})` : id,
              });
            }}
          >
            <SelectTrigger className="w-full">
              <SelectValue placeholder="— select resource —" />
            </SelectTrigger>
            <SelectContent>
              {resources.map((r) => (
                <SelectItem key={r.id} value={r.id}>
                  {r.name} ({r.kind})
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </FormRow>
      )}

      {!needsRef && (
        <p className="text-sm text-muted-foreground">
          Platform scope applies the policy across the entire system.
        </p>
      )}
    </div>
  );
}

// ─── Step: Conditions ─────────────────────────────────────────────────────────

function ConditionsStep({
  draft,
  onChange,
}: {
  draft: WizardState;
  onChange: (d: WizardState) => void;
}) {
  function update(index: number, field: "path" | "value", val: string) {
    const conditions = [...draft.conditions];
    conditions[index] = { ...conditions[index], [field]: val };
    onChange({ ...draft, conditions });
  }

  function remove(index: number) {
    onChange({
      ...draft,
      conditions: draft.conditions.filter((_, i) => i !== index),
    });
  }

  return (
    <div className="grid gap-3">
      <p className="text-sm text-muted-foreground">
        Optional ABAC conditions evaluated against the request context.
      </p>
      {draft.conditions.map((condition, index) => (
        <div
          key={index}
          className="grid gap-2 rounded-lg border p-3 sm:grid-cols-[1fr_auto_1fr_auto] sm:items-end"
        >
          <FormRow label="Path">
            <Input
              placeholder="e.g. resource.attributes.env"
              value={condition.path}
              onChange={(e) => update(index, "path", e.target.value)}
            />
          </FormRow>
          <div className="pb-2 text-center text-sm text-muted-foreground">
            equals
          </div>
          <FormRow label="Value">
            <Input
              placeholder="e.g. prod"
              value={condition.value}
              onChange={(e) => update(index, "value", e.target.value)}
            />
          </FormRow>
          <Button
            type="button"
            variant="ghost"
            size="sm"
            className="mb-0.5 self-end text-muted-foreground hover:text-destructive"
            onClick={() => remove(index)}
          >
            Remove
          </Button>
        </div>
      ))}
      <Button
        type="button"
        variant="outline"
        onClick={() =>
          onChange({
            ...draft,
            conditions: [...draft.conditions, { path: "", value: "" }],
          })
        }
      >
        Add condition
      </Button>
    </div>
  );
}

// ─── Step: Review ─────────────────────────────────────────────────────────────

function ReviewStep({ draft }: { draft: WizardState }) {
  const conditions = draft.conditions.filter((c) => c.path && c.value);

  return (
    <div className="rounded-lg border bg-muted/30 p-4">
      <div className="mb-3 text-xs font-medium uppercase tracking-wide text-muted-foreground">
        Summary
      </div>
      <PolicySummary
        effect={draft.effect}
        subjectKind={draft.subjectKind}
        subjectName={draft.subjectLabel || draft.subjectId}
        grantKind={draft.grantKind}
        grantLabel={draft.grantLabel || draft.grantId}
        scopeKind={draft.scopeKind}
        scopeRef={draft.scopeLabel || draft.scopeRef || undefined}
        conditions={conditions}
      />
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function rowToWizardState(row: PolicyRow): WizardState {
  return {
    effect: (row.effect === "deny" ? "deny" : "allow") as "allow" | "deny",
    subjectKind: (row.subjectKind === "group" ? "group" : "entity") as
      | "entity"
      | "group",
    subjectId: row.subjectId,
    subjectLabel: "",
    grantKind: (row.grantKind === "role" ? "role" : "capability") as
      | "capability"
      | "role",
    grantId: row.grantId,
    grantLabel: "",
    scopeKind: (row.scopeKind ?? "platform") as ScopeKind,
    scopeRef: row.scopeRef ?? "",
    scopeLabel: "",
    conditions: parseConditions(row.conditions),
  };
}

function parseConditions(raw: unknown): Array<{ path: string; value: string }> {
  if (!raw) return [];
  try {
    const arr = Array.isArray(raw) ? raw : JSON.parse(String(raw));
    if (!Array.isArray(arr)) return [];
    return arr
      .filter((c) => c && typeof c === "object")
      .map((c: Record<string, string>) => ({
        path: String(c.path ?? ""),
        value: String(c.value ?? ""),
      }));
  } catch {
    return [];
  }
}

function FormRow({
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
