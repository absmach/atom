"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Check } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import { GLOBAL_TENANT } from "@/lib/tenant/context";
import { cn } from "@/lib/utils";

const TENANT_NONE = "__platform__";
const STEPS = ["Boundary", "Scope", "Actions", "Conditions", "Review"] as const;

const TENANTS_QUERY = `
  query PermissionBlockFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;

const OBJECT_GROUPS_QUERY = `
  query PermissionBlockFormObjectGroups($tenantId: ID) {
    objectGroups(tenantId: $tenantId, limit: 300, offset: 0) {
      items { id name tenantId }
    }
  }
`;

const ACTIONS_QUERY = `
  query PermissionBlockFormActions($tenantId: ID, $objectKind: String, $objectType: String) {
    actions(tenantId: $tenantId, objectKind: $objectKind, objectType: $objectType, limit: 500, offset: 0) {
      items { id name description }
    }
  }
`;

const CREATE_PERMISSION_BLOCK_MUTATION = `
  mutation CreatePermissionBlock($input: CreatePermissionBlockInput!) {
    createPermissionBlock(input: $input) {
      id
      tenantId
      scopeMode
      objectKind
      objectType
      objectId
      groupId
      effect
      createdAt
      updatedAt
    }
  }
`;

const OBJECT_KINDS = [
  { value: "entity", label: "Entity" },
  { value: "resource", label: "Resource" },
  { value: "group", label: "Object group" },
  { value: "tenant", label: "Tenant" },
  { value: "role", label: "Role" },
  { value: "policy", label: "Policy" },
  { value: "credential", label: "Credential" },
  { value: "audit_log", label: "Audit log" },
  { value: "signing_key", label: "Signing key" },
] as const;

const SCOPE_MODES = [
  {
    value: "platform",
    label: "Platform",
    description: "Applies globally. No tenant boundary.",
  },
  {
    value: "tenant",
    label: "Tenant itself",
    description: "Applies to the selected tenant/domain object.",
  },
  {
    value: "object_kind",
    label: "All objects of a kind",
    description: "Example: every resource in the selected tenant.",
  },
  {
    value: "object_type",
    label: "All objects of a type",
    description: "Example: every channel resource in the selected tenant.",
  },
  {
    value: "object",
    label: "Exact object",
    description:
      "Applies to one entity, resource, group, tenant, role, or policy.",
  },
  {
    value: "group",
    label: "Object group itself",
    description: "Applies to the object group record, not its contents.",
  },
  {
    value: "group_direct_objects",
    label: "Direct objects in object group",
    description: "Applies to clients/channels directly inside the group.",
  },
  {
    value: "group_descendant_objects",
    label: "Objects in subgroups",
    description:
      "Applies to clients/channels inside child or deeper groups only.",
  },
  {
    value: "group_child_groups",
    label: "Direct child object groups",
    description: "Applies to immediate child groups themselves.",
  },
  {
    value: "group_descendant_groups",
    label: "Descendant object groups",
    description: "Applies to child or deeper group records themselves.",
  },
] as const;

type ScopeMode = (typeof SCOPE_MODES)[number]["value"];
type Effect = "allow" | "deny";

type TenantOption = { id: string; name: string };
type ObjectGroupOption = { id: string; name: string; tenantId?: string | null };
type ActionOption = { id: string; name: string; description?: string | null };

type Draft = {
  tenantId: string;
  scopeMode: ScopeMode;
  objectKind: string;
  objectType: string;
  objectId: string;
  groupId: string;
  effect: Effect;
  conditions: string;
  actionIds: string[];
};

export function PermissionBlockCreateForm({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => void;
}) {
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;
  const [stepIdx, setStepIdx] = React.useState(0);
  const [draft, setDraft] = React.useState<Draft>({
    tenantId: isTenantScoped ? selection.id : "",
    scopeMode: isTenantScoped ? "tenant" : "platform",
    objectKind: "",
    objectType: "",
    objectId: "",
    groupId: "",
    effect: "allow",
    conditions: "{}",
    actionIds: [],
  });

  React.useEffect(() => {
    if (!isTenantScoped) return;
    setDraft((prev) => ({
      ...prev,
      tenantId: selection.id,
      scopeMode: prev.scopeMode === "platform" ? "tenant" : prev.scopeMode,
    }));
  }, [isTenantScoped, selection.id]);

  const tenantsQ = useQuery({
    queryKey: ["permission-block-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: TenantOption[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const objectGroupsQ = useQuery({
    enabled: draft.scopeMode.startsWith("group") && Boolean(draft.tenantId),
    queryKey: ["permission-block-form-object-groups", draft.tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ objectGroups: { items: ObjectGroupOption[] } }>({
        query: OBJECT_GROUPS_QUERY,
        variables: { tenantId: draft.tenantId || undefined },
        signal,
      }),
    staleTime: 30_000,
  });

  const actionTarget = actionFilterForScope(draft);
  const actionsQ = useQuery({
    queryKey: [
      "permission-block-form-actions",
      draft.tenantId || "platform",
      actionTarget.objectKind ?? "*",
      actionTarget.objectType ?? "*",
    ],
    queryFn: ({ signal }) =>
      graphqlClient<{ actions: { items: ActionOption[] } }>({
        query: ACTIONS_QUERY,
        variables: {
          tenantId: draft.tenantId || undefined,
          objectKind: actionTarget.objectKind,
          objectType: actionTarget.objectType,
        },
        signal,
      }),
    staleTime: 30_000,
  });

  const tenants = tenantsQ.data?.tenants.items ?? [];
  const objectGroups = objectGroupsQ.data?.objectGroups.items ?? [];
  const actions = actionsQ.data?.actions.items ?? [];
  const selectedActions = actions.filter((action) =>
    draft.actionIds.includes(action.id),
  );
  const selectedTenant = tenants.find((tenant) => tenant.id === draft.tenantId);
  const selectedGroup = objectGroups.find(
    (group) => group.id === draft.groupId,
  );

  React.useEffect(() => {
    setDraft((prev) => ({
      ...prev,
      actionIds: prev.actionIds.filter((id) =>
        actions.some((action) => action.id === id),
      ),
    }));
  }, [actions]);

  const saveBlock = useMutation({
    mutationFn: () => {
      const conditions = parseConditions(draft.conditions);
      if (!conditions.ok) throw new Error(conditions.error);
      return graphqlClient({
        query: CREATE_PERMISSION_BLOCK_MUTATION,
        variables: {
          input: {
            tenantId: draft.tenantId || undefined,
            scopeMode: draft.scopeMode,
            objectKind: draft.objectKind || undefined,
            objectType: draft.objectType || undefined,
            objectId: draft.objectId || undefined,
            groupId: draft.groupId || undefined,
            effect: draft.effect,
            conditions: conditions.value,
            actionIds: draft.actionIds,
          },
        },
      });
    },
    onSuccess: () => {
      toast.success("Permission block created");
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
    const error = stepError(STEPS.length - 1, draft);
    if (error) {
      toast.error(error);
      return;
    }
    saveBlock.mutate();
  }

  return (
    <div className="grid gap-5">
      <Stepper current={stepIdx} />

      {stepIdx === 0 ? (
        <div className="grid gap-4">
          <Field label="Tenant boundary">
            <Select
              value={draft.tenantId || TENANT_NONE}
              onValueChange={(value) =>
                setDraft((prev) => ({
                  ...prev,
                  tenantId: value === TENANT_NONE ? "" : value,
                  scopeMode:
                    value === TENANT_NONE && prev.scopeMode !== "platform"
                      ? "platform"
                      : value !== TENANT_NONE && prev.scopeMode === "platform"
                        ? "tenant"
                        : prev.scopeMode,
                  groupId: "",
                  actionIds: [],
                }))
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="Choose boundary" />
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
              Non-platform permission blocks must belong to one tenant.
            </p>
          </Field>

          <Field label="Effect">
            <Select
              value={draft.effect}
              onValueChange={(effect: Effect) =>
                setDraft((prev) => ({ ...prev, effect }))
              }
            >
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="allow">allow</SelectItem>
                <SelectItem value="deny">deny</SelectItem>
              </SelectContent>
            </Select>
          </Field>
        </div>
      ) : null}

      {stepIdx === 1 ? (
        <div className="grid gap-4">
          <Field label="Scope mode">
            <Select
              value={draft.scopeMode}
              onValueChange={(scopeMode: ScopeMode) =>
                setDraft((prev) => resetScopeFields(prev, scopeMode))
              }
            >
              <SelectTrigger className="**:data-description:hidden">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {SCOPE_MODES.filter((mode) =>
                  draft.tenantId
                    ? mode.value !== "platform"
                    : mode.value === "platform",
                ).map((mode) => (
                  <SelectItem key={mode.value} value={mode.value}>
                    <span className="grid gap-0.5">
                      <span>{mode.label}</span>
                      <span
                        data-description=""
                        className="text-muted-foreground text-xs"
                      >
                        {mode.description}
                      </span>
                    </span>
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </Field>

          {needsObjectKind(draft.scopeMode) ? (
            <Field label="Object kind">
              <Select
                value={draft.objectKind}
                onValueChange={(objectKind) =>
                  setDraft((prev) => ({
                    ...prev,
                    objectKind,
                    objectType: "",
                    actionIds: [],
                  }))
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Choose object kind" />
                </SelectTrigger>
                <SelectContent>
                  {objectKindOptions(draft.scopeMode).map((kind) => (
                    <SelectItem key={kind.value} value={kind.value}>
                      {kind.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </Field>
          ) : null}

          {needsObjectType(draft.scopeMode, draft.objectKind) ? (
            <Field label="Object type">
              <Input
                value={draft.objectType}
                onChange={(event) =>
                  setDraft((prev) => ({
                    ...prev,
                    objectType: event.target.value,
                    actionIds: [],
                  }))
                }
                placeholder={
                  draft.objectKind === "entity"
                    ? "e.g. entity:human"
                    : "e.g. resource:invoice"
                }
              />
              <p className="text-xs text-muted-foreground">
                Stored as a namespaced value, e.g. `resource:invoice` or
                `entity:human`.
              </p>
            </Field>
          ) : null}

          {draft.scopeMode === "object" ? (
            <Field label="Exact object ID">
              <Input
                value={draft.objectId}
                onChange={(event) =>
                  setDraft((prev) => ({
                    ...prev,
                    objectId: event.target.value.trim(),
                  }))
                }
                placeholder="UUID of the protected object"
              />
            </Field>
          ) : null}

          {needsGroup(draft.scopeMode) ? (
            <Field label="Object group boundary">
              <Select
                value={draft.groupId}
                onValueChange={(groupId) =>
                  setDraft((prev) => ({ ...prev, groupId }))
                }
              >
                <SelectTrigger>
                  <SelectValue placeholder="Choose object group" />
                </SelectTrigger>
                <SelectContent>
                  {objectGroups.length === 0 ? (
                    <SelectItem disabled value="__empty__">
                      No object groups available
                    </SelectItem>
                  ) : (
                    objectGroups.map((group) => (
                      <SelectItem key={group.id} value={group.id}>
                        {group.name}
                      </SelectItem>
                    ))
                  )}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                Group scopes use object groups as a where-boundary.
              </p>
            </Field>
          ) : null}
        </div>
      ) : null}

      {stepIdx === 2 ? (
        <Field label="Actions">
          <div className="max-h-96 overflow-y-auto rounded-md border">
            {actionsQ.isFetching ? (
              <p className="p-4 text-sm text-muted-foreground">
                Loading actions...
              </p>
            ) : actions.length === 0 ? (
              <p className="p-4 text-sm text-muted-foreground">
                No actions are applicable to this scope yet.
              </p>
            ) : (
              <div className="grid divide-y">
                {actions.map((action) => {
                  const checked = draft.actionIds.includes(action.id);
                  const checkboxId = `permission-block-action-${action.id}`;
                  return (
                    <label
                      className="flex cursor-pointer items-start gap-3 p-3 hover:bg-muted/50"
                      htmlFor={checkboxId}
                      key={action.id}
                    >
                      <Checkbox
                        checked={checked}
                        id={checkboxId}
                        onCheckedChange={(next) =>
                          setDraft((prev) => ({
                            ...prev,
                            actionIds: next
                              ? [...prev.actionIds, action.id]
                              : prev.actionIds.filter((id) => id !== action.id),
                          }))
                        }
                      />
                      <span className="grid gap-1">
                        <span className="font-medium text-sm">
                          {action.name}
                        </span>
                        {action.description ? (
                          <span className="text-muted-foreground text-xs">
                            {action.description}
                          </span>
                        ) : null}
                      </span>
                    </label>
                  );
                })}
              </div>
            )}
          </div>
          {selectedActions.length > 0 ? (
            <div className="flex flex-wrap gap-1">
              {selectedActions.map((action) => (
                <Badge key={action.id} variant="secondary">
                  {action.name}
                </Badge>
              ))}
            </div>
          ) : null}
        </Field>
      ) : null}

      {stepIdx === 3 ? (
        <Field label="Conditions JSON">
          <Textarea
            className="min-h-36 font-mono text-xs"
            value={draft.conditions}
            onChange={(event) =>
              setDraft((prev) => ({ ...prev, conditions: event.target.value }))
            }
          />
          <p className="text-xs text-muted-foreground">
            Use `{}` for no conditions. The value must be a JSON object.
          </p>
        </Field>
      ) : null}

      {stepIdx === 4 ? (
        <div className="grid gap-3 rounded-lg border bg-background p-4">
          <ReviewRow label="tenant_id">
            {draft.tenantId ? (selectedTenant?.name ?? draft.tenantId) : "NULL"}
          </ReviewRow>
          <ReviewRow label="scope_mode">{draft.scopeMode}</ReviewRow>
          <ReviewRow label="object_kind">
            {draft.objectKind || "NULL"}
          </ReviewRow>
          <ReviewRow label="object_type">
            {draft.objectType || "NULL"}
          </ReviewRow>
          <ReviewRow label="object_id">{draft.objectId || "NULL"}</ReviewRow>
          <ReviewRow label="group_id">
            {draft.groupId ? (selectedGroup?.name ?? draft.groupId) : "NULL"}
          </ReviewRow>
          <ReviewRow label="effect">{draft.effect}</ReviewRow>
          <ReviewRow label="actions">
            <div className="flex flex-wrap gap-1">
              {selectedActions.map((action) => (
                <Badge key={action.id} variant="secondary">
                  {action.name}
                </Badge>
              ))}
            </div>
          </ReviewRow>
          <ReviewRow label="conditions">
            <pre className="max-h-40 overflow-auto rounded-md bg-muted p-2 text-xs">
              {formatJson(draft.conditions)}
            </pre>
          </ReviewRow>
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-2 pt-2">
        <Button
          disabled={saveBlock.isPending}
          type="button"
          variant="secondary"
          onClick={stepIdx === 0 ? onCancel : previousStep}
        >
          {stepIdx === 0 ? "Cancel" : "Back"}
        </Button>
        {stepIdx < STEPS.length - 1 ? (
          <Button type="button" onClick={nextStep}>
            Next
          </Button>
        ) : (
          <Button disabled={saveBlock.isPending} type="button" onClick={save}>
            {saveBlock.isPending ? "Saving..." : "Create permission block"}
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

function resetScopeFields(draft: Draft, scopeMode: ScopeMode): Draft {
  return {
    ...draft,
    scopeMode,
    objectKind:
      scopeMode === "group_child_groups" ||
      scopeMode === "group_descendant_groups"
        ? ""
        : draft.objectKind,
    objectType: "",
    objectId: "",
    groupId: needsGroup(scopeMode) ? draft.groupId : "",
    actionIds: [],
  };
}

function needsObjectKind(scopeMode: ScopeMode) {
  return [
    "object_kind",
    "object_type",
    "object",
    "group_direct_objects",
    "group_descendant_objects",
  ].includes(scopeMode);
}

function needsObjectType(scopeMode: ScopeMode, objectKind: string) {
  if (!["entity", "resource"].includes(objectKind)) return false;
  return [
    "object_type",
    "object",
    "group_direct_objects",
    "group_descendant_objects",
  ].includes(scopeMode);
}

function needsGroup(scopeMode: ScopeMode) {
  return [
    "group",
    "group_direct_objects",
    "group_descendant_objects",
    "group_child_groups",
    "group_descendant_groups",
  ].includes(scopeMode);
}

function objectKindOptions(scopeMode: ScopeMode) {
  if (
    ["group_direct_objects", "group_descendant_objects"].includes(scopeMode)
  ) {
    return OBJECT_KINDS.filter((kind) =>
      ["entity", "resource"].includes(kind.value),
    );
  }
  return OBJECT_KINDS;
}

function actionFilterForScope(draft: Draft) {
  switch (draft.scopeMode) {
    case "object_kind":
      return {
        objectKind: draft.objectKind || undefined,
        objectType: undefined,
      };
    case "object_type":
    case "object":
    case "group_direct_objects":
    case "group_descendant_objects":
      return {
        objectKind: draft.objectKind || undefined,
        objectType: draft.objectType || undefined,
      };
    case "group":
    case "group_child_groups":
    case "group_descendant_groups":
      return { objectKind: "group", objectType: undefined };
    case "platform":
    case "tenant":
      return { objectKind: undefined, objectType: undefined };
    default:
      return { objectKind: undefined, objectType: undefined };
  }
}

function stepError(step: number, draft: Draft) {
  if (step >= 0 && draft.scopeMode !== "platform" && !draft.tenantId) {
    return "Tenant boundary is required for this scope";
  }
  if (step >= 1) {
    if (needsObjectKind(draft.scopeMode) && !draft.objectKind) {
      return "Object kind is required";
    }
    if (
      needsObjectType(draft.scopeMode, draft.objectKind) &&
      !draft.objectType
    ) {
      return "Object type is required";
    }
    if (draft.scopeMode === "object" && !draft.objectId) {
      return "Exact object ID is required";
    }
    if (needsGroup(draft.scopeMode) && !draft.groupId) {
      return "Object group boundary is required";
    }
  }
  if (step >= 2 && draft.actionIds.length === 0) {
    return "Select at least one action";
  }
  if (step >= 3) {
    const conditions = parseConditions(draft.conditions);
    if (!conditions.ok) return conditions.error;
  }
  return null;
}

function parseConditions(
  value: string,
): { ok: true; value: Record<string, unknown> } | { ok: false; error: string } {
  try {
    const parsed = JSON.parse(value || "{}");
    if (
      parsed === null ||
      Array.isArray(parsed) ||
      typeof parsed !== "object"
    ) {
      return { ok: false, error: "Conditions must be a JSON object" };
    }
    return { ok: true, value: parsed as Record<string, unknown> };
  } catch {
    return { ok: false, error: "Conditions must be valid JSON" };
  }
}

function formatJson(value: string) {
  const parsed = parseConditions(value);
  if (!parsed.ok) return value;
  return JSON.stringify(parsed.value, null, 2);
}
