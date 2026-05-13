"use client";

import { json, jsonParseLinter } from "@codemirror/lang-json";
import { linter } from "@codemirror/lint";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { EditorView, type ReactCodeMirrorProps } from "@uiw/react-codemirror";
import dynamic from "next/dynamic";
import { type Control, useForm, type UseFormReturn } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
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
import { graphqlClient } from "@/lib/graphql/client";

const CodeMirror = dynamic<ReactCodeMirrorProps>(
  () => import("@uiw/react-codemirror").then((m) => m.default),
  { ssr: false },
);

const JSON_EXTENSIONS = [
  json(),
  linter(jsonParseLinter()),
  EditorView.lineWrapping,
];

const CODEMIRROR_CLASS =
  "max-w-full overflow-hidden rounded-md border bg-background text-xs [&_.cm-content]:max-w-full [&_.cm-editor]:min-h-36 [&_.cm-gutters]:border-r [&_.cm-line]:break-words [&_.cm-scroller]:font-mono";

const CREATE_RESOURCE_MUTATION = `
  mutation CreateResource($input: CreateResourceInput!) {
    createResource(input: $input) {
      id kind name tenantId ownerId attributes createdAt updatedAt
    }
  }
`;

const UPDATE_RESOURCE_MUTATION = `
  mutation UpdateResource($id: ID!, $input: UpdateResourceInput!) {
    updateResource(id: $id, input: $input) {
      id kind name tenantId ownerId attributes createdAt updatedAt
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
  tenantId: z.string(),
  ownerId: z.string(),
  attributes: attributesSchema,
});

const editSchema = z.object({
  name: z.string().trim(),
  attributes: attributesSchema,
});

type CreateFormValues = z.infer<typeof createSchema>;
type EditFormValues = z.infer<typeof editSchema>;

// ─── Public types ─────────────────────────────────────────────────────────────

export type ResourceFormInitialValues = {
  id: string;
  kind: string;
  name: string;
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

function TenantSelectField({
  form,
  tenants,
}: {
  form: UseFormReturn<CreateFormValues>;
  tenants: { id: string; name: string }[];
}) {
  return (
    <FormField
      control={form.control}
      name="tenantId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Tenant</FormLabel>
          <FormControl>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              {...field}
            >
              <option value="">— none —</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name}
                </option>
              ))}
            </select>
          </FormControl>
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
  return (
    <FormField
      control={form.control}
      name="ownerId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Owner entity</FormLabel>
          <FormControl>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
              {...field}
            >
              <option value="">— none —</option>
              {entities.map((e) => (
                <option key={e.id} value={e.id}>
                  {e.name}
                  {e.tenantId ? ` (${e.tenantId})` : ""}
                </option>
              ))}
            </select>
          </FormControl>
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
            <CodeMirror
              basicSetup={{
                foldGutter: true,
                highlightActiveLine: false,
                highlightActiveLineGutter: false,
                lineNumbers: true,
              }}
              className={CODEMIRROR_CLASS}
              extensions={JSON_EXTENSIONS}
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
            <CodeMirror
              basicSetup={{
                foldGutter: true,
                highlightActiveLine: false,
                highlightActiveLineGutter: false,
                lineNumbers: true,
              }}
              className={CODEMIRROR_CLASS}
              extensions={JSON_EXTENSIONS}
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
