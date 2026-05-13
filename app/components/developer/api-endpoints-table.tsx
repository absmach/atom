"use client";

import { useMutation } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";
import { Plus, X } from "lucide-react";
import { useRouter } from "next/navigation";
import * as React from "react";
import { toast } from "sonner";
import type {
  ApiEndpointRow,
  TemplateOption,
} from "@/components/developer/api-endpoints-workspace";
import { StatusBadge } from "@/components/crud/status-badge";
import { DataTable } from "@/components/ui/data-table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";

const CREATE_MUTATION = `
  mutation CreateApiEndpoint($input: CreateApiEndpointInput!) {
    createApiEndpoint(input: $input) {
      id key name method path status createdAt
    }
  }
`;

const UPDATE_MUTATION = `
  mutation UpdateApiEndpoint($id: ID!, $input: UpdateApiEndpointInput!) {
    updateApiEndpoint(id: $id, input: $input) {
      id key name method path status updatedAt
    }
  }
`;

const DISABLE_MUTATION = `
  mutation DisableApiEndpoint($id: ID!) {
    disableApiEndpoint(id: $id) { id status }
  }
`;

const ENABLE_MUTATION = `
  mutation EnableApiEndpoint($id: ID!) {
    enableApiEndpoint(id: $id) { id status }
  }
`;

const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"];

type PanelState =
  | { mode: "create" }
  | { mode: "edit"; row: ApiEndpointRow }
  | { mode: "inspect"; row: ApiEndpointRow }
  | null;

export function ApiEndpointsTable({
  rows,
  total,
  page,
  limit,
  templateOptions,
}: {
  rows: ApiEndpointRow[];
  total: number;
  page: number;
  limit: number;
  templateOptions: TemplateOption[];
}) {
  const router = useRouter();
  const [panel, setPanel] = React.useState<PanelState>(null);

  const create = useMutation({
    mutationFn: (input: Record<string, unknown>) =>
      graphqlClient({ query: CREATE_MUTATION, variables: { input } }),
    onSuccess: () => {
      toast.success("Endpoint created");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const update = useMutation({
    mutationFn: ({ id, input }: { id: string; input: Record<string, unknown> }) =>
      graphqlClient({ query: UPDATE_MUTATION, variables: { id, input } }),
    onSuccess: () => {
      toast.success("Endpoint updated");
      setPanel(null);
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  const toggle = useMutation({
    mutationFn: ({ id, enable }: { id: string; enable: boolean }) =>
      graphqlClient({
        query: enable ? ENABLE_MUTATION : DISABLE_MUTATION,
        variables: { id },
      }),
    onSuccess: (_, { enable }) => {
      toast.success(enable ? "Endpoint enabled" : "Endpoint disabled");
      router.refresh();
    },
    onError: (err) => toast.error(err.message),
  });

  function submitForm(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const fd = new FormData(e.currentTarget);
    const raw = Object.fromEntries(fd.entries());
    const jsonFields = ["variablesMapping", "requestSchema", "responseMapping"];
    const input: Record<string, unknown> = {};

    for (const [key, value] of Object.entries(raw)) {
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

    if (panel?.mode === "create") create.mutate(input);
    else if (panel?.mode === "edit") update.mutate({ id: panel.row.id, input });
  }

  const isPending = create.isPending || update.isPending;

  const columns: ColumnDef<ApiEndpointRow>[] = [
    {
      accessorKey: "key",
      header: "Key",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{String(getValue())}</span>
      ),
    },
    { accessorKey: "name", header: "Name" },
    {
      accessorKey: "method",
      header: "Method",
      cell: ({ getValue }) => (
        <Badge variant="secondary">{String(getValue())}</Badge>
      ),
    },
    {
      accessorKey: "path",
      header: "Path",
      cell: ({ getValue }) => (
        <span className="font-mono text-xs">{String(getValue())}</span>
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
          {row.original.status === "disabled" ? (
            <Button
              disabled={toggle.isPending}
              onClick={() => toggle.mutate({ id: row.original.id, enable: true })}
              size="sm"
              variant="outline"
            >
              Enable
            </Button>
          ) : (
            <Button
              disabled={toggle.isPending}
              onClick={() => {
                if (window.confirm(`Disable "${row.original.name}"?`)) {
                  toggle.mutate({ id: row.original.id, enable: false });
                }
              }}
              size="sm"
              variant="destructive"
            >
              Disable
            </Button>
          )}
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
        noResultsMessage="No endpoints found."
        page={page}
        paramKey="endpoints"
        searchPlaceholder="Filter endpoints…"
        toolbar={
          <Button
            disabled={templateOptions.length === 0}
            onClick={() => setPanel({ mode: "create" })}
            title={templateOptions.length === 0 ? "Create a template first" : undefined}
          >
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
              ? "Bind a template to an HTTP path with auth mode and variable mapping."
              : "Update the endpoint configuration."
          }
          onClose={() => setPanel(null)}
          title={panel.mode === "create" ? "Create endpoint" : `Edit "${panel.row.name}"`}
        >
          <EndpointForm
            defaultValues={panel.mode === "edit" ? panel.row : undefined}
            isPending={isPending}
            onSubmit={submitForm}
            templateOptions={templateOptions}
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

function EndpointForm({
  defaultValues,
  isPending,
  onSubmit,
  templateOptions,
}: {
  defaultValues?: ApiEndpointRow;
  isPending: boolean;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
  templateOptions: TemplateOption[];
}) {
  return (
    <form className="mt-6 grid gap-4" onSubmit={onSubmit}>
      <Field
        defaultValue={defaultValues?.key}
        label="Key"
        name="key"
        placeholder="e.g. create_tenant_endpoint"
      />
      <Field defaultValue={defaultValues?.name} label="Name" name="name" />
      <Field
        defaultValue={defaultValues?.description ?? ""}
        label="Description"
        name="description"
      />
      <div className="grid gap-2">
        <Label htmlFor="method">Method</Label>
        <select
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          defaultValue={defaultValues?.method ?? "POST"}
          id="method"
          name="method"
        >
          {HTTP_METHODS.map((m) => (
            <option key={m} value={m}>
              {m}
            </option>
          ))}
        </select>
      </div>
      <Field
        defaultValue={defaultValues?.path}
        label="Path"
        name="path"
        placeholder="/api/v1/tenants"
      />
      <div className="grid gap-2">
        <Label htmlFor="templateId">Template</Label>
        <select
          className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          defaultValue={defaultValues?.templateId ?? ""}
          id="templateId"
          name="templateId"
        >
          <option value="">— select template —</option>
          {templateOptions.map((t) => (
            <option key={t.id} value={t.id}>
              {t.key} — {t.name}
            </option>
          ))}
        </select>
      </div>
      <Field
        defaultValue={defaultValues?.authMode ?? "bearer"}
        label="Auth mode"
        name="authMode"
        placeholder="bearer"
      />
      <div className="grid gap-2">
        <Label htmlFor="variablesMapping">Variables mapping (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues ? JSON.stringify(defaultValues.variablesMapping, null, 2) : "{}"
          }
          id="variablesMapping"
          name="variablesMapping"
          rows={3}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="requestSchema">Request schema (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues ? JSON.stringify(defaultValues.requestSchema, null, 2) : "{}"
          }
          id="requestSchema"
          name="requestSchema"
          rows={3}
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="responseMapping">Response mapping (JSON)</Label>
        <Textarea
          className="font-mono text-xs"
          defaultValue={
            defaultValues ? JSON.stringify(defaultValues.responseMapping, null, 2) : "{}"
          }
          id="responseMapping"
          name="responseMapping"
          rows={3}
        />
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
      <Input defaultValue={defaultValue} id={name} name={name} placeholder={placeholder} />
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
            <h2 className="font-heading text-base font-medium text-foreground">{title}</h2>
            {description ? (
              <p className="mt-1 text-sm text-muted-foreground">{description}</p>
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
