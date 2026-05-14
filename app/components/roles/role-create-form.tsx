"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Button } from "@/components/ui/button";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
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
import { GLOBAL_TENANT } from "@/lib/tenant/context";
import { CapabilityPicker } from "./capability-picker";

const TENANT_NONE = "__none__";

// ─── GraphQL ─────────────────────────────────────────────────────────────────

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

const ADD_CAPABILITY_MUTATION = `
  mutation AddRoleCapability($roleId: ID!, $capabilityId: ID!) {
    addRoleCapability(roleId: $roleId, capabilityId: $capabilityId)
  }
`;

const REMOVE_CAPABILITY_MUTATION = `
  mutation RemoveRoleCapability($roleId: ID!, $capabilityId: ID!) {
    removeRoleCapability(roleId: $roleId, capabilityId: $capabilityId)
  }
`;

const CAPABILITIES_QUERY = `
  query RoleFormCapabilities {
    capabilities(limit: 200, offset: 0) { items { id name resourceKind } }
  }
`;

const ROLE_CAPABILITIES_QUERY = `
  query RoleFormRoleCapabilities($roleId: ID!) {
    roleCapabilities(roleId: $roleId) { id name resourceKind }
  }
`;

const TENANTS_QUERY = `
  query RoleFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;

// ─── Types ────────────────────────────────────────────────────────────────────

type GqlCapability = {
  id: string;
  name: string;
  resourceKind: string | null;
};

export type RoleFormInitialValues = {
  id: string;
  name: string;
  tenantId: string;
  description: string;
};

// ─── Schemas ─────────────────────────────────────────────────────────────────

const createSchema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  tenantId: z.string(),
  description: z.string().trim(),
});

const editSchema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  description: z.string().trim(),
});

type CreateFormValues = z.infer<typeof createSchema>;
type EditFormValues = z.infer<typeof editSchema>;

// ─── Entry point ─────────────────────────────────────────────────────────────

export function RoleCreateForm({
  role,
  onCancel,
  onSaved,
}: {
  role?: RoleFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  return role ? (
    <EditForm role={role} onCancel={onCancel} onSaved={onSaved} />
  ) : (
    <CreateForm onCancel={onCancel} onSaved={onSaved} />
  );
}

// ─── Create form ─────────────────────────────────────────────────────────────

function CreateForm({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => void;
}) {
  const { tenants, capabilities } = usePickerData();
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;
  const [selectedCapIds, setSelectedCapIds] = React.useState<string[]>([]);

  const form = useForm<CreateFormValues>({
    resolver: zodResolver(createSchema),
    defaultValues: { name: "", tenantId: "", description: "" },
  });

  React.useEffect(() => {
    if (isTenantScoped) form.setValue("tenantId", selection.id);
  }, [isTenantScoped, selection.id, form]);

  const addCap = useMutation({
    mutationFn: ({
      roleId,
      capabilityId,
    }: {
      roleId: string;
      capabilityId: string;
    }) =>
      graphqlClient({
        query: ADD_CAPABILITY_MUTATION,
        variables: { roleId, capabilityId },
      }),
  });

  const save = useMutation({
    mutationFn: async (values: CreateFormValues) => {
      const result = await graphqlClient<{ createRole: { id: string } }>({
        query: CREATE_ROLE_MUTATION,
        variables: {
          input: {
            name: values.name,
            tenantId: values.tenantId || undefined,
            description: values.description || undefined,
          },
        },
      });
      const roleId = result.createRole.id;
      await Promise.all(
        selectedCapIds.map((capabilityId) =>
          addCap.mutateAsync({ roleId, capabilityId }),
        ),
      );
      return result;
    },
    onSuccess: () => {
      toast.success("Role created");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((v) => save.mutate(v))}
      >
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>Name</RequiredFormLabel>
              <FormControl>
                <Input placeholder="e.g. publisher" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {isTenantScoped ? (
          <div className="grid gap-2">
            <Label>Tenant</Label>
            <div className="text-sm text-muted-foreground">
              {selection.name}
            </div>
          </div>
        ) : (
          <FormField
            control={form.control}
            name="tenantId"
            render={({ field }) => (
              <FormItem>
                <FormLabel>Tenant</FormLabel>
                <Select
                  value={field.value || TENANT_NONE}
                  onValueChange={(v) =>
                    field.onChange(v === TENANT_NONE ? "" : v)
                  }
                >
                  <FormControl>
                    <SelectTrigger className="w-full">
                      <SelectValue />
                    </SelectTrigger>
                  </FormControl>
                  <SelectContent>
                    <SelectItem value={TENANT_NONE}>
                      — none (platform) —
                    </SelectItem>
                    {tenants.map((t) => (
                      <SelectItem key={t.id} value={t.id}>
                        {t.name}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <FormMessage />
              </FormItem>
            )}
          />
        )}
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <CapabilityPicker
          all={capabilities}
          selected={selectedCapIds}
          onAdd={(id) =>
            setSelectedCapIds((prev) =>
              prev.includes(id) ? prev : [...prev, id],
            )
          }
          onRemove={(id) =>
            setSelectedCapIds((prev) => prev.filter((c) => c !== id))
          }
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={save.isPending} type="submit">
            Create role
          </Button>
        </div>
      </form>
    </Form>
  );
}

// ─── Edit form ────────────────────────────────────────────────────────────────

function EditForm({
  role,
  onCancel,
  onSaved,
}: {
  role: RoleFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const { capabilities } = usePickerData();

  const roleCapsQuery = useQuery({
    queryKey: ["role-caps-form", role.id],
    queryFn: ({ signal }) =>
      graphqlClient<{ roleCapabilities: GqlCapability[] }>({
        query: ROLE_CAPABILITIES_QUERY,
        variables: { roleId: role.id },
        signal,
      }),
    staleTime: 0,
  });
  const roleCaps: GqlCapability[] = roleCapsQuery.data?.roleCapabilities ?? [];
  const roleCapsIds = roleCaps.map((c) => c.id);

  const addCap = useMutation({
    mutationFn: (capabilityId: string) =>
      graphqlClient({
        query: ADD_CAPABILITY_MUTATION,
        variables: { roleId: role.id, capabilityId },
      }),
    onSuccess: () => roleCapsQuery.refetch(),
    onError: (err) => toast.error(err.message),
  });

  const removeCap = useMutation({
    mutationFn: (capabilityId: string) =>
      graphqlClient({
        query: REMOVE_CAPABILITY_MUTATION,
        variables: { roleId: role.id, capabilityId },
      }),
    onSuccess: () => roleCapsQuery.refetch(),
    onError: (err) => toast.error(err.message),
  });

  const form = useForm<EditFormValues>({
    resolver: zodResolver(editSchema),
    defaultValues: { name: role.name, description: role.description },
  });

  const save = useMutation({
    mutationFn: (values: EditFormValues) =>
      graphqlClient({
        query: UPDATE_ROLE_MUTATION,
        variables: {
          id: role.id,
          input: {
            name: values.name,
            description: values.description || undefined,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Role updated");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  const capsMutating = addCap.isPending || removeCap.isPending;

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((v) => save.mutate(v))}
      >
        <ReadOnlyField label="Tenant" value={role.tenantId || "— platform —"} />
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>Name</RequiredFormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        {roleCapsQuery.isFetching && roleCaps.length === 0 ? (
          <p className="text-xs text-muted-foreground">Loading capabilities…</p>
        ) : (
          <CapabilityPicker
            all={capabilities}
            selected={roleCapsIds}
            onAdd={(id) => addCap.mutate(id)}
            onRemove={(id) => removeCap.mutate(id)}
            disabled={capsMutating}
          />
        )}
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={save.isPending} type="submit">
            Save changes
          </Button>
        </div>
      </form>
    </Form>
  );
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ReadOnlyField({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid gap-1 rounded-lg border bg-muted/30 px-3 py-2">
      <span className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </span>
      <span className="text-sm">{value}</span>
    </div>
  );
}

function usePickerData() {
  const tenantsQuery = useQuery({
    queryKey: ["role-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: { id: string; name: string }[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const capsQuery = useQuery({
    queryKey: ["role-form-capabilities"],
    queryFn: ({ signal }) =>
      graphqlClient<{ capabilities: { items: GqlCapability[] } }>({
        query: CAPABILITIES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  return {
    tenants: tenantsQuery.data?.tenants.items ?? [],
    capabilities: capsQuery.data?.capabilities.items ?? [],
  };
}
