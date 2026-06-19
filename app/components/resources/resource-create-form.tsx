"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { type Control, type UseFormReturn, useForm } from "react-hook-form";
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
import { JsonEditor } from "@/components/ui/json-editor";
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

const CREATE_RESOURCE_MUTATION = `
  mutation CreateResource($input: CreateResourceInput!) {
    createResource(input: $input) {
      id kind name alias tenantId ownerId attributes createdAt updatedAt
    }
  }
`;

const UPDATE_RESOURCE_MUTATION = `
  mutation UpdateResource($id: ID!, $input: UpdateResourceInput!) {
    updateResource(id: $id, input: $input) {
      id kind name alias tenantId ownerId attributes createdAt updatedAt
    }
  }
`;

const TENANTS_QUERY = `
  query ResourceFormTenants {
    tenants(limit: 100, offset: 0) { items { id name } }
  }
`;

const ENTITIES_QUERY = `
  query ResourceFormEntities {
    entities(limit: 200, offset: 0) { items { id name kind tenantId } }
  }
`;

// ─── Schemas ──────────────────────────────────────────────────────────────────

const attributesSchema = z.string().superRefine((val, ctx) => {
  if (!val.trim()) return;
  try {
    const parsed = JSON.parse(val);
    if (
      typeof parsed !== "object" ||
      Array.isArray(parsed) ||
      parsed === null
    ) {
      ctx.addIssue({
        code: "custom",
        message: "Attributes must be a JSON object.",
      });
    }
  } catch {
    ctx.addIssue({ code: "custom", message: "Attributes must be valid JSON." });
  }
});

const createSchema = z.object({
  kind: z.string().trim().min(1, "Kind is required."),
  name: z.string().trim(),
  alias: z.string().trim(),
  tenantId: z.string(),
  ownerId: z.string(),
  attributes: attributesSchema,
});

const editSchema = z.object({
  name: z.string().trim(),
  alias: z.string().trim(),
  attributes: attributesSchema,
});

type CreateFormValues = z.infer<typeof createSchema>;
type EditFormValues = z.infer<typeof editSchema>;

// ─── Public types ─────────────────────────────────────────────────────────────

export type ResourceFormInitialValues = {
  id: string;
  kind: string;
  name: string;
  alias: string;
  tenantId: string;
  ownerId: string;
  attributes: unknown;
};

// ─── Entry point ─────────────────────────────────────────────────────────────

export function ResourceCreateForm({
  resource,
  onCancel,
  onSaved,
}: {
  resource?: ResourceFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  return resource ? (
    <EditForm resource={resource} onCancel={onCancel} onSaved={onSaved} />
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
  const { tenants, entities } = usePickerData();

  const form = useForm<CreateFormValues>({
    resolver: zodResolver(createSchema),
    defaultValues: {
      kind: "",
      name: "",
      alias: "",
      tenantId: "",
      ownerId: "",
      attributes: "{}",
    },
  });

  const save = useMutation({
    mutationFn: (values: CreateFormValues) =>
      graphqlClient({
        query: CREATE_RESOURCE_MUTATION,
        variables: {
          input: {
            kind: values.kind,
            name: values.name || undefined,
            alias: values.alias || undefined,
            tenantId: values.tenantId || undefined,
            ownerId: values.ownerId || undefined,
            attributes: parseAttributes(values.attributes),
          },
        },
      }),
    onSuccess: () => {
      toast.success("Resource created");
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
        <KindField form={form} />
        <NameField form={form} />
        <AliasField form={form} />
        <TenantSelectField form={form} tenants={tenants} />
        <OwnerSelectField form={form} entities={entities} />
        <AttributesField control={form.control} />
        <FormActions
          isPending={save.isPending}
          mode="create"
          onCancel={onCancel}
        />
      </form>
    </Form>
  );
}

// ─── Edit form ───────────────────────────────────────────────────────────────

function EditForm({
  resource,
  onCancel,
  onSaved,
}: {
  resource: ResourceFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const form = useForm<EditFormValues>({
    resolver: zodResolver(editSchema),
    defaultValues: {
      name: resource.name,
      alias: resource.alias,
      attributes: stringifyAttributes(resource.attributes),
    },
  });

  const save = useMutation({
    mutationFn: (values: EditFormValues) =>
      graphqlClient({
        query: UPDATE_RESOURCE_MUTATION,
        variables: {
          id: resource.id,
          input: {
            name: values.name || undefined,
            alias: values.alias || null,
            attributes: parseAttributes(values.attributes),
          },
        },
      }),
    onSuccess: () => {
      toast.success("Resource updated");
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
        <ReadOnlyField label="Kind" value={resource.kind} />
        <ReadOnlyField label="Tenant" value={resource.tenantId || "—"} />
        <ReadOnlyField label="Owner" value={resource.ownerId || "—"} />
        <EditNameField form={form} />
        <EditAliasField form={form} />
        <EditAttributesField control={form.control} />
        <FormActions
          isPending={save.isPending}
          mode="edit"
          onCancel={onCancel}
        />
      </form>
    </Form>
  );
}

// ─── Field components ────────────────────────────────────────────────────────

function KindField({ form }: { form: UseFormReturn<CreateFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="kind"
      render={({ field }) => (
        <FormItem>
          <RequiredFormLabel required>Kind</RequiredFormLabel>
          <FormControl>
            <Input placeholder="e.g. channel" {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function NameField({ form }: { form: UseFormReturn<CreateFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="name"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Name</FormLabel>
          <FormControl>
            <Input {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function AliasField({ form }: { form: UseFormReturn<CreateFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="alias"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Alias</FormLabel>
          <FormControl>
            <Input {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function EditNameField({ form }: { form: UseFormReturn<EditFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="name"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Name</FormLabel>
          <FormControl>
            <Input {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function EditAliasField({ form }: { form: UseFormReturn<EditFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="alias"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Alias</FormLabel>
          <FormControl>
            <Input {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function TenantSelectField({
  form,
  tenants,
}: {
  form: UseFormReturn<CreateFormValues>;
  tenants: { id: string; name: string }[];
}) {
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;

  React.useEffect(() => {
    if (isTenantScoped) form.setValue("tenantId", selection.id);
  }, [isTenantScoped, selection.id, form]);

  if (isTenantScoped) {
    return (
      <div className="grid gap-2">
        <Label>Tenant</Label>
        <div className="text-sm text-muted-foreground">{selection.name}</div>
      </div>
    );
  }

  const NONE = "__none__";

  return (
    <FormField
      control={form.control}
      name="tenantId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Tenant</FormLabel>
          <Select
            value={field.value || NONE}
            onValueChange={(v) => field.onChange(v === NONE ? "" : v)}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectItem value={NONE}>— none —</SelectItem>
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
  );
}

function OwnerSelectField({
  form,
  entities,
}: {
  form: UseFormReturn<CreateFormValues>;
  entities: {
    id: string;
    name: string;
    kind: string;
    tenantId: string | null;
  }[];
}) {
  const NONE = "__none__";

  return (
    <FormField
      control={form.control}
      name="ownerId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Owner entity</FormLabel>
          <Select
            value={field.value || NONE}
            onValueChange={(v) => field.onChange(v === NONE ? "" : v)}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectItem value={NONE}>— none —</SelectItem>
              {entities.map((e) => (
                <SelectItem key={e.id} value={e.id}>
                  {e.name}
                  {e.tenantId ? ` · ${e.tenantId}` : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function AttributesField({ control }: { control: Control<CreateFormValues> }) {
  return (
    <FormField
      control={control}
      name="attributes"
      render={({ field }) => (
        <FormItem className="min-w-0">
          <FormLabel>Attributes JSON</FormLabel>
          <FormControl>
            <JsonEditor
              className="[&_.cm-editor]:min-h-36"
              onChange={field.onChange}
              value={field.value}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function EditAttributesField({
  control,
}: {
  control: Control<EditFormValues>;
}) {
  return (
    <FormField
      control={control}
      name="attributes"
      render={({ field }) => (
        <FormItem className="min-w-0">
          <FormLabel>Attributes JSON</FormLabel>
          <FormControl>
            <JsonEditor
              className="[&_.cm-editor]:min-h-36"
              onChange={field.onChange}
              value={field.value}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

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

function FormActions({
  isPending,
  mode,
  onCancel,
}: {
  isPending: boolean;
  mode: "create" | "edit";
  onCancel: () => void;
}) {
  return (
    <div className="flex justify-end gap-2">
      <Button onClick={onCancel} type="button" variant="outline">
        Cancel
      </Button>
      <Button disabled={isPending} type="submit">
        {mode === "edit" ? "Save changes" : "Create resource"}
      </Button>
    </div>
  );
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function usePickerData() {
  const tenantsQuery = useQuery({
    queryKey: ["resource-form-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenants: { items: { id: string; name: string }[] } }>({
        query: TENANTS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const entitiesQuery = useQuery({
    queryKey: ["resource-form-entities"],
    queryFn: ({ signal }) =>
      graphqlClient<{
        entities: {
          items: {
            id: string;
            name: string;
            kind: string;
            tenantId: string | null;
          }[];
        };
      }>({ query: ENTITIES_QUERY, signal }),
    staleTime: 60_000,
  });

  return {
    tenants: tenantsQuery.data?.tenants.items ?? [],
    entities: entitiesQuery.data?.entities.items ?? [],
  };
}

function parseAttributes(value: string) {
  if (!value.trim()) return undefined;
  return JSON.parse(value) as Record<string, unknown>;
}

function stringifyAttributes(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "";
  return JSON.stringify(value, null, 2);
}
