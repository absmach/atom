"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import { Check, X } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { Badge } from "@/components/ui/badge";
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
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import { GLOBAL_TENANT } from "@/lib/tenant/context";
import { cn } from "@/lib/utils";

const TENANT_NONE = "__none__";
const STEPS = ["Basics", "Permission blocks", "Review"] as const;

const TENANTS_QUERY = `
  query RoleFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;

const PERMISSION_BLOCKS_QUERY = `
  query RoleFormPermissionBlocks($tenantId: ID) {
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

const ROLE_DETAIL_QUERY = `
  query RoleFormRoleDetail($roleId: ID!) {
    role(id: $roleId) {
      id
      name
      tenantId
      description
      permissionBlocks {
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

const CREATE_ROLE_MUTATION = `
  mutation CreateRole($input: CreateRoleInput!) {
    createRole(input: $input) { id name tenantId description createdAt updatedAt }
  }
`;

const UPDATE_ROLE_MUTATION = `
  mutation UpdateRole($id: ID!, $input: UpdateRoleInput!) {
    updateRole(id: $id, input: $input) { id name tenantId description createdAt updatedAt }
  }
`;

const REPLACE_PERMISSION_BLOCKS_MUTATION = `
  mutation ReplaceRolePermissionBlocks($roleId: ID!, $permissionBlockIds: [ID!]!) {
    replaceRolePermissionBlocks(roleId: $roleId, permissionBlockIds: $permissionBlockIds)
  }
`;

type TenantOption = { id: string; name: string };

type PermissionBlockOption = {
  id: string;
  tenantId?: string | null;
  scopeMode: string;
  objectKind?: string | null;
  objectType?: string | null;
  objectId?: string | null;
  groupId?: string | null;
  effect: "allow" | "deny" | string;
  actions: { id: string; name: string }[];
};

export type RoleFormInitialValues = {
  id: string;
  name: string;
  tenantId: string;
  description: string;
};

type Draft = {
  name: string;
  tenantId: string;
  description: string;
  permissionBlockIds: string[];
};

export function RoleCreateForm({
  role,
  onCancel,
  onSaved,
}: {
  role?: RoleFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const isEditing = Boolean(role);
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;
  const [stepIdx, setStepIdx] = React.useState(0);
  const [draft, setDraft] = React.useState<Draft>({
    name: role?.name ?? "",
    tenantId: role?.tenantId ?? (isTenantScoped ? selection.id : ""),
    description: role?.description ?? "",
    permissionBlockIds: [],
  });
  const hydratedRoleId = React.useRef<string | null>(null);

  React.useEffect(() => {
    if (!role && isTenantScoped) {
      setDraft((prev) => ({ ...prev, tenantId: selection.id }));
    }
  }, [isTenantScoped, role, selection.id]);

  const tenantsQuery = useQuery({
    queryKey: ["role-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: TenantOption[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const permissionBlocksQuery = useQuery({
    queryKey: ["role-form-permission-blocks", draft.tenantId || "platform"],
    queryFn: ({ signal }) =>
      graphqlClient<{ permissionBlocks: { items: PermissionBlockOption[] } }>({
        query: PERMISSION_BLOCKS_QUERY,
        variables: { tenantId: draft.tenantId || undefined },
        signal,
      }),
    staleTime: 30_000,
  });

  const roleDetailQuery = useQuery({
    enabled: Boolean(role?.id),
    queryKey: ["role-form-detail", role?.id],
    queryFn: ({ signal }) =>
      graphqlClient<{
        role: {
          id: string;
          name: string;
          tenantId?: string | null;
          description?: string | null;
          permissionBlocks: PermissionBlockOption[];
        };
      }>({
        query: ROLE_DETAIL_QUERY,
        variables: { roleId: role?.id },
        signal,
      }),
    staleTime: 0,
  });

  React.useEffect(() => {
    if (!role?.id || !roleDetailQuery.data) return;
    if (hydratedRoleId.current === role.id) return;
    hydratedRoleId.current = role.id;
    const current = roleDetailQuery.data.role;
    setDraft({
      name: current.name,
      tenantId: current.tenantId ?? "",
      description: current.description ?? "",
      permissionBlockIds: current.permissionBlocks.map((block) => block.id),
    });
  }, [role?.id, roleDetailQuery.data]);

  const tenants = tenantsQuery.data?.tenants.items ?? [];
  const permissionBlocks =
    permissionBlocksQuery.data?.permissionBlocks.items ?? [];
  const selectedBlocks = permissionBlocks.filter((block) =>
    draft.permissionBlockIds.includes(block.id),
  );
  const availableBlocks = permissionBlocks.filter(
    (block) => !draft.permissionBlockIds.includes(block.id),
  );
  const validation = validateDraft(draft);
  const isSaving = false;

  const saveRole = useMutation({
    mutationFn: async () => {
      const input = {
        name: draft.name.trim(),
        tenantId: draft.tenantId || undefined,
        description: draft.description.trim() || undefined,
      };

      const roleId = role?.id
        ? role.id
        : (
            await graphqlClient<{
              createRole: { id: string };
            }>({
              query: CREATE_ROLE_MUTATION,
              variables: { input },
            })
          ).createRole.id;

      if (role?.id) {
        await graphqlClient({
          query: UPDATE_ROLE_MUTATION,
          variables: {
            id: role.id,
            input: {
              name: input.name,
              description: input.description,
            },
          },
        });
      }

      await graphqlClient({
        query: REPLACE_PERMISSION_BLOCKS_MUTATION,
        variables: {
          roleId,
          permissionBlockIds: draft.permissionBlockIds,
        },
      });
    },
    onSuccess: () => {
      toast.success(isEditing ? "Role updated" : "Role created");
      onSaved();
    },
    onError: (error) => toast.error(error.message),
  });

  function nextStep() {
    if (stepIdx === 0 && !draft.name.trim()) {
      toast.error("Role name is required");
      return;
    }
    setStepIdx((prev) => Math.min(prev + 1, STEPS.length - 1));
  }

  function previousStep() {
    setStepIdx((prev) => Math.max(prev - 1, 0));
  }

  function save() {
    if (validation.length > 0) {
      toast.error(validation[0]);
      return;
    }
    saveRole.mutate();
  }

  return (
    <div className="grid gap-5">
      <Stepper current={stepIdx} />

      {roleDetailQuery.isFetching && role && !roleDetailQuery.data ? (
        <p className="text-sm text-muted-foreground">Loading role…</p>
      ) : null}

      {stepIdx === 0 ? (
        <div className="grid gap-4">
          <Field label="Tenant">
            <Select
              disabled={isEditing}
              value={draft.tenantId || TENANT_NONE}
              onValueChange={(value) =>
                setDraft((prev) => ({
                  ...prev,
                  tenantId: value === TENANT_NONE ? "" : value,
                  permissionBlockIds: [],
                }))
              }
            >
              <SelectTrigger>
                <SelectValue placeholder="Select tenant" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value={TENANT_NONE}>Platform role</SelectItem>
                {tenants.map((tenant) => (
                  <SelectItem key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <p className="text-xs text-muted-foreground">
              Tenant chooses where this role metadata lives. Permission blocks
              decide where access applies.
            </p>
          </Field>

          <Field label="Role name" required>
            <Input
              placeholder="e.g. channel-operator"
              value={draft.name}
              onChange={(event) =>
                setDraft((prev) => ({ ...prev, name: event.target.value }))
              }
            />
          </Field>

          <Field label="Description">
            <Textarea
              placeholder="Optional note for operators"
              value={draft.description}
              onChange={(event) =>
                setDraft((prev) => ({
                  ...prev,
                  description: event.target.value,
                }))
              }
            />
          </Field>
        </div>
      ) : null}

      {stepIdx === 1 ? (
        <div className="grid gap-4">
          <div className="rounded-lg border bg-muted/30 p-3 text-sm text-muted-foreground">
            A role is a named collection of permission blocks. Create reusable
            permission blocks first, then attach them here.
          </div>
          <Field label="Permission blocks">
            {selectedBlocks.length > 0 ? (
              <div className="grid gap-2">
                {selectedBlocks.map((block) => (
                  <div
                    className="flex items-start justify-between gap-3 rounded-md border p-2"
                    key={block.id}
                  >
                    <div className="min-w-0">
                      <div className="text-sm font-medium">
                        {permissionBlockLabel(block)}
                      </div>
                      <div className="mt-1 flex flex-wrap gap-1">
                        {block.actions.map((action) => (
                          <Badge key={action.id} variant="secondary">
                            {action.name}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <Button
                      className="h-7 w-7 shrink-0"
                      size="icon"
                      type="button"
                      variant="ghost"
                      onClick={() =>
                        setDraft((prev) => ({
                          ...prev,
                          permissionBlockIds: prev.permissionBlockIds.filter(
                            (id) => id !== block.id,
                          ),
                        }))
                      }
                    >
                      <X className="size-4" />
                    </Button>
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-sm text-muted-foreground">
                No permission blocks selected.
              </p>
            )}
            <Select
              value=""
              onValueChange={(id) => {
                if (!id) return;
                setDraft((prev) => ({
                  ...prev,
                  permissionBlockIds: [...prev.permissionBlockIds, id],
                }));
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="Add permission block" />
              </SelectTrigger>
              <SelectContent>
                {availableBlocks.length === 0 ? (
                  <SelectItem disabled value="__empty__">
                    No matching permission blocks
                  </SelectItem>
                ) : (
                  availableBlocks.map((block) => (
                    <SelectItem key={block.id} value={block.id}>
                      {permissionBlockLabel(block)}
                    </SelectItem>
                  ))
                )}
              </SelectContent>
            </Select>
          </Field>
        </div>
      ) : null}

      {stepIdx === 2 ? (
        <div className="grid gap-3 rounded-lg border bg-background p-4">
          <ReviewRow label="Tenant">
            {draft.tenantId
              ? (tenants.find((tenant) => tenant.id === draft.tenantId)?.name ??
                draft.tenantId)
              : "Platform"}
          </ReviewRow>
          <ReviewRow label="Name">{draft.name || "—"}</ReviewRow>
          <ReviewRow label="Description">
            {draft.description || "No description"}
          </ReviewRow>
          <div className="grid gap-1">
            <div className="text-xs font-medium uppercase text-muted-foreground">
              Permission blocks
            </div>
            {selectedBlocks.length > 0 ? (
              <div className="grid gap-2 pt-1">
                {selectedBlocks.map((block) => (
                  <div
                    key={block.id}
                    className="rounded-md border bg-muted/30 p-2"
                  >
                    <div className="text-sm font-medium">
                      {permissionBlockLabel(block)}
                    </div>
                    <div className="mt-1 flex flex-wrap gap-1">
                      {block.actions.map((action) => (
                        <Badge key={action.id} variant="secondary">
                          {action.name}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-sm text-muted-foreground">None</div>
            )}
          </div>
        </div>
      ) : null}

      <div className="flex items-center justify-between gap-2 pt-2">
        <Button
          disabled={saveRole.isPending}
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
          <Button
            disabled={saveRole.isPending || isSaving}
            type="button"
            onClick={save}
          >
            {saveRole.isPending
              ? "Saving…"
              : isEditing
                ? "Save role"
                : "Create role"}
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
  required,
}: {
  children: React.ReactNode;
  label: string;
  required?: boolean;
}) {
  return (
    <div className="grid gap-2">
      <Label>
        {label}
        {required ? <span className="ml-1 text-destructive">*</span> : null}
      </Label>
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

function validateDraft(draft: Draft) {
  const errors: string[] = [];
  if (!draft.name.trim()) errors.push("Role name is required");
  return errors;
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
