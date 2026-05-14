"use client";

import { useQuery } from "@tanstack/react-query";
import { Check, ChevronDown, ChevronRight, Copy } from "lucide-react";
import * as React from "react";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Button } from "@/components/ui/button";
import { JsonEditor } from "@/components/ui/json-editor";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const TENANT_QUERY = `
  query EntityInspectTenant($id: ID!) {
    tenant(id: $id) { id name }
  }
`;

const PROFILE_QUERY = `
  query EntityInspectProfile($id: ID!) {
    profile(id: $id) { id displayName key objectKind kind description }
  }
`;

type Row = Record<string, unknown>;
type TenantData = { tenant: { id: string; name: string } };
type ProfileData = {
  profile: {
    id: string;
    displayName: string;
    key: string;
    objectKind: string;
    kind: string;
    description: string | null;
  };
};

export function EntityInspectDetails({ row }: { row: Row | null }) {
  const [copied, setCopied] = React.useState(false);
  const [profileExpanded, setProfileExpanded] = React.useState(false);

  const id = row?.id ? String(row.id) : "";
  const tenantId = row?.tenantId ? String(row.tenantId) : "";
  const profileId = row?.profileId ? String(row.profileId) : "";

  const tenantQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ["entity-inspect-tenant", tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<TenantData>({
        query: TENANT_QUERY,
        variables: { id: tenantId },
        signal,
      }),
    staleTime: 60_000,
  });

  const profileQuery = useQuery({
    enabled: Boolean(profileId),
    queryKey: ["entity-inspect-profile", profileId],
    queryFn: ({ signal }) =>
      graphqlClient<ProfileData>({
        query: PROFILE_QUERY,
        variables: { id: profileId },
        signal,
      }),
    staleTime: 60_000,
  });

  function copyId() {
    navigator.clipboard.writeText(id).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (!row) return null;

  const tenantName = tenantQuery.data?.tenant.name ?? tenantId;
  const profile = profileQuery.data?.profile;
  const attributes =
    row.attributes &&
    typeof row.attributes === "object" &&
    !Array.isArray(row.attributes)
      ? row.attributes
      : null;
  const attributesCode = attributes
    ? JSON.stringify(attributes, null, 2)
    : null;

  return (
    <div className="grid gap-3">
      <Field label="ID">
        <div className="flex items-center gap-2">
          <span className="break-all font-mono text-xs">{id}</span>
          <Button
            className="h-6 w-6 shrink-0"
            onClick={copyId}
            size="icon"
            variant="ghost"
          >
            {copied ? (
              <Check className="size-3.5" />
            ) : (
              <Copy className="size-3.5" />
            )}
          </Button>
        </div>
      </Field>

      {row.name ? (
        <Field label="Name">
          <span className="text-sm">{String(row.name)}</span>
        </Field>
      ) : null}

      <Field label="Kind">
        <span className="font-mono text-xs">{String(row.kind ?? "—")}</span>
      </Field>

      {row.status ? (
        <Field label="Status">
          <StatusBadge value={row.status} />
        </Field>
      ) : null}

      {tenantId ? (
        <Field label="Tenant">
          <span className="text-sm">{tenantName}</span>
        </Field>
      ) : null}

      {profileId ? (
        <div className="grid gap-1 rounded-lg border bg-background p-3">
          <div className="text-xs font-medium uppercase text-muted-foreground">
            Profile
          </div>
          <button
            className="flex items-center gap-1 text-left text-sm hover:underline focus-visible:outline-none"
            onClick={() => setProfileExpanded((v) => !v)}
            type="button"
          >
            {profileExpanded ? (
              <ChevronDown className="size-3.5 shrink-0" />
            ) : (
              <ChevronRight className="size-3.5 shrink-0" />
            )}
            <span>
              {profile?.displayName ??
                (profileQuery.isFetching ? profileId : profileId)}
            </span>
          </button>
          {profileExpanded ? (
            <div className="mt-2 grid gap-2 pl-5">
              {profileQuery.isFetching && !profile ? (
                <span className="text-xs text-muted-foreground">Loading…</span>
              ) : profile ? (
                <>
                  <ProfileDetailRow label="Key" value={profile.key} />
                  <ProfileDetailRow
                    label="Object kind"
                    value={profile.objectKind}
                  />
                  <ProfileDetailRow label="Kind" value={profile.kind} />
                  {profile.description ? (
                    <ProfileDetailRow
                      label="Description"
                      value={profile.description}
                    />
                  ) : null}
                </>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2">
        {row.createdAt ? (
          <Field label="Created">
            <DisplayTimeCell
              action={Action.Created}
              time={String(row.createdAt)}
            />
          </Field>
        ) : null}
        {row.updatedAt ? (
          <Field label="Updated">
            <DisplayTimeCell
              action={Action.Updated}
              time={String(row.updatedAt)}
            />
          </Field>
        ) : null}
      </div>

      {attributesCode ? (
        <div className="grid gap-1 rounded-lg border bg-background p-3">
          <div className="text-xs font-medium uppercase text-muted-foreground">
            Attributes
          </div>
          <JsonEditor value={attributesCode} />
        </div>
      ) : null}
    </div>
  );
}

function ProfileDetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="grid grid-cols-[7rem_1fr] gap-2 text-xs">
      <span className="font-medium uppercase text-muted-foreground">
        {label}
      </span>
      <span className="font-mono">{value}</span>
    </div>
  );
}

function Field({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div className="grid gap-1 rounded-lg border bg-background p-3">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <div>{children}</div>
    </div>
  );
}
