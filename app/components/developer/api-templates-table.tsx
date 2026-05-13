"use client";

import { useMutation } from "@tanstack/react-query";
import type { ColumnDef } from "@tanstack/react-table";
import { Plus, X } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import { StatusBadge } from "@/components/crud/status-badge";
import type { ApiTemplateRow } from "@/components/developer/api-templates-workspace";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DataTable } from "@/components/ui/data-table";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";

const CREATE_MUTATION = `
  mutation CreateApiTemplate($input: CreateApiTemplateInput!) {
    createApiTemplate(input: $input) {
      id key name operationKind status createdAt
    }
  }
`;

const UPDATE_MUTATION = `
  mutation UpdateApiTemplate($id: ID!, $input: UpdateApiTemplateInput!) {
    updateApiTemplate(id: $id, input: $input) {
      id key name operationKind status updatedAt
    }
  }
`;

const DISABLE_MUTATION = `
  mutation DisableApiTemplate($id: ID!) {
    disableApiTemplate(id: $id)
  }
`;

type PanelState =
  | { mode: "create" }
  | { mode: "edit"; row: ApiTemplateRow }
  | { mode: "inspect"; row: ApiTemplateRow }
  | null;

export function ApiTemplatesTable({
  rows,
  total,
  page,
  limit,
}: {
  rows: ApiTemplateRow[];
  total: number;
  page: number;
  limit: number;
}) {
  const router = useRouter();
  const [panel, setPanel] = React.useState<PanelState>(null);

  const create = useMutation({
    mutationFn: (input: Record<string, unknown>) =>
      graphqlClient({ query: CREATE_MUTATION, variables: { input } }),
    onSuccess: () => {
      toast.success("Template created");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const update = useMutation({
    mutationFn: ({
      id,
      input,
    }: {
      id: string;
      input: Record<string, unknown>;
    }) => graphqlClient({ query: UPDATE_MUTATION, variables: { id, input } }),
    onSuccess: () => {
      toast.success("Template updated");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const disable = useMutation({
    mutationFn: (id: string) =>
      graphqlClient({ query: DISABLE_MUTATION, variables: { id } }),
    onSuccess: () => {
      toast.success("Template disabled");
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  function submitForm(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const raw = Object.fromEntries(fd.entries());
    const jsonFields = [
      "variablesSchema",
      "defaultVariables",
      "resultSelector",
    ];
    const input: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(raw)) {
      if (key === "tags") continue;
      const str = String(value).trim();
      if (!str) continue;
      if (jsonFields.includes(key)) {
        try {
          input[key] = JSON.parse(str);
        } catch {
          toast.error(`${key} must be valid JSON.`);
          return;
        }
      } else {
        input[key] = str;
      }
    }

    const tagsRaw = String(raw.tags ?? "").trim();
    input.tags = tagsRaw
      ? tagsRaw
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean)
      : [];

    if (panel?.mode === "create") create.mutate(input);
    else if (panel?.mode === "edit") update.mutate({ id: panel.row.id, input });
  }

  const isPending = create.isPending || update.isPending;

  const columns: ColumnDef<ApiTemplateRow>[] = [
    {
      accessorKey: "key",
      header: "Key",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{String(getValue())}</span>
      ),
    },
    { accessorKey: "name", header: "Name" },
    {
      accessorKey: "operationKind",
      header: "Kind",
      cell: ({ getValue }) => (
        <Badge variant="secondary">{String(getValue())}</Badge>
      ),
    },
    {
      accessorKey: "tags",
      header: "Tags",
      cell: ({ getValue }) => (
        <div className="flex flex-wrap gap-1">
          {(getValue() as string[]).map((tag) => (
            <Badge className="text-xs" key={tag} variant="outline">
              {tag}
            </Badge>
          ))}
        </div>
      ),
    },
    {
      accessorKey: "status",
      header: "Status",
      cell: ({ getValue }) => <StatusBadge value={getValue()} />,
    },
    {
      id: "actions",
      header: () => <span className="sr-only">Actions</span>,
      cell: ({ row }) => (
        <div className="flex justify-end gap-2">
          <Button
            onClick={() => setPanel({ mode: "inspect", row: row.original })}
            size="sm"
            variant="outline"
          >
            Inspect
          </Button>
          <Button
            disabled={row.original.status === "disabled"}
            onClick={() => setPanel({ mode: "edit", row: row.original })}
            size="sm"
            variant="outline"
          >
            Edit
          </Button>
          <Button
            disabled={row.original.status === "disabled" || disable.isPending}
            onClick={() => {
              if (
                window.confirm(
                  `Disable "${row.original.name}"? This cannot be undone easily.`,
                )
              ) {
                disable.mutate(row.original.id);
              }
            }}
            size="sm"
            variant="destructive"
          >
            Disable
          </Button>
        </div>
      ),
    },
  ];

  return (
    <>
      <DataTable
        columns={columns}
        data={rows}
        limit={limit}
        noResultsMessage="No templates found."
        page={page}
        paramKey="templates"
        searchPlaceholder="Filter templates…"
        toolbar={
          <Button onClick={() => setPanel({ mode: "create" })}>
            <Plus data-icon="inline-start" />
            Create
          </Button>
        }
        total={total}
      />

      {panel?.mode === "create" || panel?.mode === "edit" ? (
        <SidePanel
          description={
            panel.mode === "create"
              ? "Define a reusable operation blueprint."
              : "Update the template. Endpoints using it will pick up changes immediately."
          }
          onClose={() => setPanel(null)}
          title={
            panel.mode === "create"
              ? "Create template"
              : `Edit "${panel.row.name}"`
          }
        >
          <TemplateForm
            defaultValues={panel.mode === "edit" ? panel.row : undefined}
            isPending={isPending}
            onSubmit={submitForm}
          />
        </SidePanel>
      ) : null}

      {panel?.mode === "inspect" ? (
        <SidePanel
          description="Read-only detail view."
          onClose={() => setPanel(null)}
          title={`Inspect "${panel.row.name}"`}
        >
          <div className="grid gap-3">
            {Object.entries(panel.row).map(([key, value]) => (
              <div
                className="grid gap-1 rounded-lg border bg-background p-3"
                key={key}
              >
                <div className="text-xs font-medium uppercase text-muted-foreground">
                  {key}
                </div>
                <div className="wrap-break-word font-mono text-xs">
                  {typeof value === "object"
                    ? JSON.stringify(value, null, 2)
                    : String(value ?? "-")}
                </div>
              </div>
            ))}
            <Button onClick={() => setPanel(null)} variant="outline">
              Close
            </Button>
          </div>
        </SidePanel>
      ) : null}
    </>
  );
}

function TemplateForm({
  defaultValues,
  isPending,
  onSubmit,
}: {
  defaultValues?: ApiTemplateRow;
  isPending: boolean;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form className="mt-6 grid gap-4" onSubmit={onSubmit}>
      <Field
        defaultValue={defaultValues?.key}
        label="Key"
        name="key"
        placeholder="e.g. create_tenant"
      />
      <Field defaultValue={defaultValues?.name} label="Name" name="name" />
      <Field
        defaultValue={defaultValues?.description ?? ""}
        label="Description"
        name="description"
      />
      <div className="grid gap-2">
        <Label htmlFor="operationKind">Operation kind</Label>
        <select
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          defaultValue={defaultValues?.operationKind ?? "query"}
          id="operationKind"
          name="operationKind"
        >
          <option value="query">Query</option>
          <option value="mutation">Mutation</option>
        </select>
      </div>
      <div className="grid gap-2">
        <Label htmlFor="graphql">Operation</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={defaultValues?.graphql}
          id="graphql"
          name="graphql"
          placeholder="query ExampleQuery { health }"
          rows={6}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="variablesSchema">Variables schema (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues
              ? JSON.stringify(defaultValues.variablesSchema, null, 2)
              : "{}"
          }
          id="variablesSchema"
          name="variablesSchema"
          rows={3}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="defaultVariables">Default variables (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues
              ? JSON.stringify(defaultValues.defaultVariables, null, 2)
              : "{}"
          }
          id="defaultVariables"
          name="defaultVariables"
          rows={3}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="resultSelector">Result selector (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues
              ? JSON.stringify(defaultValues.resultSelector, null, 2)
              : "{}"
          }
          id="resultSelector"
          name="resultSelector"
          placeholder='{"path": ["fieldName"]}'
          rows={3}
        />
      </div>
      <Field
        defaultValue={defaultValues?.tags.join(", ")}
        label="Tags (comma-separated)"
        name="tags"
        placeholder="setup, admin"
      />
      <div className="grid gap-2">
        <Label htmlFor="status">Status</Label>
        <select
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          defaultValue={defaultValues?.status ?? "active"}
          id="status"
          name="status"
        >
          <option value="draft">Draft</option>
          <option value="active">Active</option>
          <option value="deprecated">Deprecated</option>
        </select>
      </div>
      <Button disabled={isPending} type="submit">
        Save
      </Button>
    </form>
  );
}

function Field({
  defaultValue,
  label,
  name,
  placeholder,
}: {
  name: string;
  label: string;
  defaultValue?: string;
  placeholder?: string;
}) {
  return (
    <div className="grid gap-2">
      <Label htmlFor={name}>{label}</Label>
      <Input
        defaultValue={defaultValue}
        id={name}
        name={name}
        placeholder={placeholder}
      />
    </div>
  );
}

function SidePanel({
  children,
  description,
  onClose,
  title,
}: {
  children: React.ReactNode;
  description?: string;
  onClose: () => void;
  title: string;
}) {
  React.useEffect(() => {
    function closeOnEscape(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", closeOnEscape);
    return () => window.removeEventListener("keydown", closeOnEscape);
  }, [onClose]);

  return (
    <div aria-label={title} aria-modal="true" role="dialog">
      <button
        aria-label="Close panel"
        className="fixed inset-0 z-40 bg-black/10"
        onClick={onClose}
        type="button"
      />
      <aside className="fixed inset-y-0 right-0 z-50 flex w-full max-w-xl flex-col gap-4 overflow-y-auto border-l bg-popover p-4 text-sm text-popover-foreground shadow-lg sm:w-3/4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h2 className="font-heading text-base font-medium text-foreground">
              {title}
            </h2>
            {description ? (
              <p className="mt-1 text-sm text-muted-foreground">
                {description}
              </p>
            ) : null}
          </div>
          <Button
            aria-label="Close panel"
            className="-mr-1"
            onClick={onClose}
            size="icon-sm"
            variant="ghost"
          >
            <X />
          </Button>
        </div>
        {children}
      </aside>
    </div>
  );
}
