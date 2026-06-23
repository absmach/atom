"use client";

import { useQuery } from "@tanstack/react-query";
import * as React from "react";
import { TENANTS_QUERY } from "@/components/crud/table/constants";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";

type TenantOption = { id: string; name: string };
type TenantsPickerData = { tenants: { items: TenantOption[] } };

export function FallbackCreateForm({
  formAttributes,
  isPending,
  resourceKey,
  onSubmit,
}: {
  formAttributes?: boolean;
  isPending: boolean;
  resourceKey: string;
  onSubmit: (e: React.FormEvent<HTMLFormElement>) => void;
}) {
  return (
    <form className="grid gap-4" onSubmit={onSubmit}>
      {resourceKey !== "tenants" ? (
        <QuickField name="name" label="Name" required />
      ) : null}
      {resourceKey === "groups" || resourceKey === "roles" ? (
        <QuickField name="description" label="Description" />
      ) : null}
      {resourceKey !== "tenants" && resourceKey !== "action-applicability" ? (
        <TenantPickerField />
      ) : null}
      {formAttributes ? (
        <div className="grid gap-2">
          <Label htmlFor="attributes">Attributes JSON</Label>
          <Textarea
            id="attributes"
            name="attributes"
            placeholder='{"env":"prod"}'
          />
        </div>
      ) : null}
      <Button type="submit" disabled={isPending}>
        Save
      </Button>
    </form>
  );
}

function QuickField({
  defaultValue,
  label,
  name,
  required,
}: {
  name: string;
  label: string;
  defaultValue?: string;
  required?: boolean;
}) {
  return (
    <div className="grid gap-2">
      <RequiredLabel htmlFor={name} required={required}>
        {label}
      </RequiredLabel>
      <Input
        defaultValue={defaultValue}
        id={name}
        name={name}
        required={required}
      />
    </div>
  );
}

function RequiredLabel({
  children,
  htmlFor,
  required,
}: {
  children: React.ReactNode;
  htmlFor: string;
  required?: boolean;
}) {
  return (
    <Label htmlFor={htmlFor}>
      {children}
      {required ? <span className="text-destructive"> *</span> : null}
    </Label>
  );
}

function TenantPickerField() {
  const { data } = useQuery({
    queryKey: ["tenant-picker"],
    queryFn: ({ signal }) =>
      graphqlClient<TenantsPickerData>({ query: TENANTS_QUERY, signal }),
    staleTime: 60_000,
  });
  const tenants = data?.tenants.items ?? [];
  const [value, setValue] = React.useState("");

  return (
    <div className="grid gap-2">
      <Label htmlFor="tenantId">Tenant</Label>
      <input name="tenantId" type="hidden" value={value} />
      <select
        className="flex h-9 w-full rounded-md border border-input bg-transparent px-3 py-1 text-sm shadow-xs transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
        id="tenantId"
        onChange={(e) => setValue(e.target.value)}
        value={value}
      >
        <option value="">- select tenant -</option>
        {tenants.map((t) => (
          <option key={t.id} value={t.id}>
            {t.name}
          </option>
        ))}
      </select>
    </div>
  );
}
