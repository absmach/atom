"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Check } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { graphqlClient } from "@/lib/graphql/client";
import { cn } from "@/lib/utils";

const TENANT_NONE = "__none__";
const STEPS = ["Tenant", "Subject", "Permission block", "Review"] as const;

const TENANTS_QUERY = `
  query DirectPolicyFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;

const ENTITIES_QUERY = `
  query DirectPolicyFormEntities($tenantId: ID) {
    entities(tenantId: $tenantId, limit: 300, offset: 0) {
      items { id name kind tenantId }
    }
  }
`;

const PRINCIPAL_GROUPS_QUERY = `
  query DirectPolicyFormPrincipalGroups($tenantId: ID) {
    principalGroups(tenantId: $tenantId, limit: 300, offset: 0) {
      items { id name tenantId }
    }
  }
`;

const PERMISSION_BLOCKS_QUERY = `
  query DirectPolicyFormPermissionBlocks($tenantId: ID) {
    permissionBlocks(tenantId: $tenantId, limit: 500, offset: 0) {
      items {
        id
        tenantId
        scopeMode
        objectKind
        objectType
        objectId
        groupId
        effect
        actions { id name }
      }
    }
  }
`;

const CREATE_DIRECT_POLICY_MUTATION = `
  mutation CreateDirectPolicy($input: CreateDirectPolicyInput!) {
    createDirectPolicy(input: $input) {
      id tenantId subjectKind subjectId permissionBlockId createdAt
    }
  }
`;

const DELETE_DIRECT_POLICY_MUTATION = `
  mutation DeleteDirectPolicy($id: ID!) {
    deleteDirectPolicy(id: $id)
  }
`;

type IdName = { id: string; name: string };
type EntityOption = IdName & { kind: string; tenantId?: string | null };
type GroupOption = IdName & { tenantId?: string | null };
type PermissionBlockOption = {
  id: string;
  tenantId?: string | null;
  scopeMode: string;
  objectKind?: string | null;
  objectType?: string | null;
  objectId?: string | null;
  groupId?: string | null;
  effect: string;
  actions: { id: string; name: string }[];
};

export type PolicyRow = {
  id: string;
  tenantId?: string | null;
  subjectKind: string;
  subjectId: string;
  permissionBlockId: string;
};

type Draft = {
  tenantId: string;
  subjectKind: "entity" | "group";
  subjectId: string;
  permissionBlockId: string;
};

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
  const [draft, setDraft] = React.useState<Draft>({
    tenantId: initialPolicy?.tenantId ?? "",
    subjectKind: initialPolicy?.subjectKind === "group" ? "group" : "entity",
    subjectId: initialPolicy?.subjectId ?? "",
    permissionBlockId: initialPolicy?.permissionBlockId ?? "",
  });

  const tenantsQ = useQuery({
    queryKey: ["direct-policy-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: IdName[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const entitiesQ = useQuery({
    queryKey: ["direct-policy-form-entities", draft.tenantId || "platform"],
    queryFn: ({ signal }) =>
      graphqlClient<{ entities: { items: EntityOption[] } }>({
        query: ENTITIES_QUERY,
        variables: { tenantId: draft.tenantId || undefined },
        signal,
      }),
    staleTime: 30_000,
  });

  const groupsQ = useQuery({
    queryKey: [
      "direct-policy-form-principal-groups",
      draft.tenantId || "platform",
    ],
    queryFn: ({ signal }) =>
      graphqlClient<{ principalGroups: { items: GroupOption[] } }>({
        query: PRINCIPAL_GROUPS_QUERY,
        variables: { tenantId: draft.tenantId || undefined },
        signal,
      }),
    staleTime: 30_000,
  });

  const permissionBlocksQ = useQuery({
    queryKey: [
      "direct-policy-form-permission-blocks",
      draft.tenantId || "platform",
    ],
    queryFn: ({ signal }) =>
      graphqlClient<{ permissionBlocks: { items: PermissionBlockOption[] } }>({
        query: PERMISSION_BLOCKS_QUERY,
        variables: { tenantId: draft.tenantId || undefined },
        signal,
      }),
    staleTime: 30_000,
  });

  const tenants = tenantsQ.data?.tenants.items ?? [];
  const entities = entitiesQ.data?.entities.items ?? [];
  const groups = groupsQ.data?.principalGroups.items ?? [];
  const permissionBlocks = permissionBlocksQ.data?.permissionBlocks.items ?? [];
  const subjects = draft.subjectKind === "entity" ? entities : groups;
  const selectedSubject = subjects.find(
    (subject) => subject.id === draft.subjectId,
  );
  const selectedBlock = permissionBlocks.find(
    (block) => block.id === draft.permissionBlockId,
  );

  const savePolicy = useMutation({
    mutationFn: async () => {
      const input = {
        tenantId: draft.tenantId || undefined,
        subjectKind: draft.subjectKind,
        subjectId: draft.subjectId,
        permissionBlockId: draft.permissionBlockId,
      };
      await graphqlClient({
        query: CREATE_DIRECT_POLICY_MUTATION,
        variables: { input },
      });
      if (initialPolicy?.id) {
        await graphqlClient({
          query: DELETE_DIRECT_POLICY_MUTATION,
          variables: { id: initialPolicy.id },
        });
      }
    },
    onSuccess: () => {
      toast.success(
        isEditing ? "Direct policy replaced" : "Direct policy created",
      );
      onSaved();
    },
    onError: (error) => toast.error(error.message),
  });

  function nextStep() {
    const error = stepError(stepIdx, draft);
    if (error) {
      toast.error(error);
      return;
    }
    setStepIdx((prev) => Math.min(prev + 1, STEPS.length - 1));
  }

  function previousStep() {
    setStepIdx((prev) => Math.max(prev - 1, 0));
  }

  function save() {
    const error = stepError(3, draft);
    if (error) {
      toast.error(error);
      return;
    }
    savePolicy.mutate();
  }

  return (
    <div className="grid gap-5">
      <Stepper current={stepIdx} />

      {stepIdx === 0 ? (
        <Field label="Tenant boundary">
          <Select
            value={draft.tenantId || TENANT_NONE}
            onValueChange={(value) =>
              setDraft((prev) => ({
                ...prev,
                tenantId: value === TENANT_NONE ? "" : value,
                subjectId: "",
                permissionBlockId: "",
              }))
            }
          >
            <SelectTrigger>
              <SelectValue placeholder="Choose tenant boundary" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value={TENANT_NONE}>Platform</SelectItem>
              {tenants.map((tenant) => (
                <SelectItem key={tenant.id} value={tenant.id}>
                  {tenant.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Tenant must match both the subject and permission block for
            tenant-scoped policies.
          </p>
        </Field>
      ) : null}

      {stepIdx === 1 ? (
        <div className="grid gap-4">
          <Field label="Subject kind">
            <Select
              value={draft.subjectKind}
              onValueChange={(value: "entity" | "group") =>
                setDraft((prev) => ({
                  ...prev,
                  subjectKind: value,
                  subjectId: "",
                }))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="entity">Entity</SelectItem>
                <SelectItem value="group">Principal group</SelectItem>
              </SelectContent>
            </Select>
          </Field>

          <Field label="Subject">
            <Select
              value={draft.subjectId}
              onValueChange={(subjectId) =>
                setDraft((prev) => ({ ...prev, subjectId }))
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="Choose subject" />
              </SelectTrigger>
              <SelectContent>
                {subjects.length === 0 ? (
                  <SelectItem disabled value="__empty__">
                    No subjects available
                  </SelectItem>
                ) : (
                  subjects.map((subject) => (
                    <SelectItem key={subject.id} value={subject.id}>
                      {"kind" in subject
                        ? `${subject.name} (${subject.kind})`
                        : subject.name}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </Field>
        </div>
      ) : null}

      {stepIdx === 2 ? (
        <Field label="Permission block">
          <Select
            value={draft.permissionBlockId}
            onValueChange={(permissionBlockId) =>
              setDraft((prev) => ({ ...prev, permissionBlockId }))
            }
          >
            <SelectTrigger className="h-auto min-h-10 whitespace-normal py-2 [&>span]:line-clamp-none [&>span]:wrap-break-word [&>span]:text-left">
              <SelectValue placeholder="Choose permission block" />
            </SelectTrigger>
            <SelectContent className="max-w-xs">
              {permissionBlocks.length === 0 ? (
                <SelectItem disabled value="__empty__">
                  No permission blocks available
                </SelectItem>
              ) : (
                permissionBlocks.map((block) => (
                  <SelectItem
                    key={block.id}
                    value={block.id}
                    className="whitespace-normal"
                  >
                    {permissionBlockLabel(block)}
                  </SelectItem>
                ))
              )}
            </SelectContent>
          </Select>
          <p className="text-xs text-muted-foreground">
            Direct policies are advanced grants. Prefer role assignments for
            normal administrator workflows.
          </p>
        </Field>
      ) : null}

      {stepIdx === 3 ? (
        <div className="grid gap-3 rounded-lg border bg-background p-4">
          <ReviewRow label="Tenant">
            {draft.tenantId
              ? (tenants.find((tenant) => tenant.id === draft.tenantId)?.name ??
                draft.tenantId)
              : "Platform"}
          </ReviewRow>
          <ReviewRow label="Subject">
            {selectedSubject
              ? "kind" in selectedSubject
                ? `${selectedSubject.name} (${selectedSubject.kind})`
                : selectedSubject.name
              : "—"}
          </ReviewRow>
          <ReviewRow label="Permission block">
            {selectedBlock ? permissionBlockLabel(selectedBlock) : "—"}
          </ReviewRow>
          {selectedBlock ? (
            <div className="flex flex-wrap gap-1">
              {selectedBlock.actions.map((action) => (
                <Badge key={action.id} variant="secondary">
                  {action.name}
                </Badge>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-2 pt-2">
        <Button
          disabled={savePolicy.isPending}
          type="button"
          variant="ghost"
          onClick={stepIdx === 0 ? onCancel : previousStep}
        >
          {stepIdx === 0 ? "Cancel" : "Back"}
        </Button>
        {stepIdx < STEPS.length - 1 ? (
          <Button type="button" onClick={nextStep}>
            Next
          </Button>
        ) : (
          <Button disabled={savePolicy.isPending} type="button" onClick={save}>
            {savePolicy.isPending
              ? "Saving…"
              : isEditing
                ? "Replace policy"
                : "Create policy"}
          </Button>
        )}
      </div>
    </div>
  );
}

function Stepper({ current }: { current: number }) {
  return (
    <div className="flex flex-wrap gap-2">
      {STEPS.map((step, index) => {
        const done = index < current;
        const active = index === current;
        return (
          <div
            className={cn(
              "flex items-center gap-2 rounded-full border px-3 py-1.5 text-sm",
              active
                ? "border-primary bg-primary text-primary-foreground"
                : done
                  ? "border-primary/40 bg-primary/10 text-primary"
                  : "text-muted-foreground",
            )}
            key={step}
          >
            {done ? <Check className="size-4" /> : <span>{index + 1}</span>}
            <span>{step}</span>
          </div>
        );
      })}
    </div>
  );
}

function Field({
  children,
  label,
}: {
  children: React.ReactNode;
  label: string;
}) {
  return (
    <div className="grid gap-2">
      <Label>{label}</Label>
      {children}
    </div>
  );
}

function ReviewRow({
  children,
  label,
}: {
  children: React.ReactNode;
  label: string;
}) {
  return (
    <div className="grid gap-1">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div className="text-sm">{children}</div>
    </div>
  );
}

function stepError(step: number, draft: Draft) {
  if (step >= 1 && !draft.subjectId) return "Subject is required";
  if (step >= 2 && !draft.permissionBlockId)
    return "Permission block is required";
  return null;
}

function permissionBlockLabel(block: PermissionBlockOption) {
  const actions =
    block.actions.length > 0
      ? block.actions.map((action) => action.name).join(", ")
      : "no actions";
  return `${scopeLabel(block)} · ${block.effect} · ${actions}`;
}

function scopeLabel(block: PermissionBlockOption) {
  switch (block.scopeMode) {
    case "platform":
      return "Platform";
    case "tenant":
      return "Tenant";
    case "object_kind":
      return `All ${block.objectKind ?? "objects"}`;
    case "object_type":
      return `All ${block.objectKind ?? "objects"}:${block.objectType ?? "*"}`;
    case "object":
      return `${block.objectKind ?? "object"} ${block.objectId ?? ""}`.trim();
    case "group":
      return `Object group ${block.groupId ?? ""}`.trim();
    case "group_direct_objects":
      return `Direct ${block.objectKind ?? "objects"} in group ${block.groupId ?? ""}`.trim();
    case "group_descendant_objects":
      return `Descendant ${block.objectKind ?? "objects"} in group ${block.groupId ?? ""}`.trim();
    case "group_child_groups":
      return `Direct child groups of ${block.groupId ?? ""}`.trim();
    case "group_descendant_groups":
      return `Descendant groups of ${block.groupId ?? ""}`.trim();
    default:
      return block.scopeMode;
  }
}
