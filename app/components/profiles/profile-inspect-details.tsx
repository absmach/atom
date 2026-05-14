"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Plus } from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import { Button } from "@/components/ui/button";
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
import type { JsonSchema, UiSchema } from "@/lib/profiles/schema-form";
import { Action } from "@/lib/utils";

const PROFILE_INSPECT_QUERY = `
  query ProfileInspectDetails($id: ID!) {
    profile(id: $id) {
      id tenantId objectKind kind key displayName description status createdAt updatedAt
    }
    profileVersions(profileId: $id) {
      id version status jsonSchema uiSchema createdAt
    }
  }
`;

const TENANT_QUERY = `
  query ProfileInspectTenant($id: ID!) {
    tenant(id: $id) { id name }
  }
`;

const CREATE_VERSION_MUTATION = `
  mutation CreateProfileVersion($profileId: ID!, $input: CreateProfileVersionInput!) {
    createProfileVersion(profileId: $profileId, input: $input) {
      id version status jsonSchema uiSchema createdAt
    }
  }
`;

type ProfileVersion = {
  id: string;
  version: number;
  status: string;
  jsonSchema: JsonSchema;
  uiSchema: UiSchema;
  createdAt: string;
};

type ProfileDetails = {
  id: string;
  tenantId: string | null;
  objectKind: string;
  kind: string;
  key: string;
  displayName: string;
  description: string | null;
  status: string;
  createdAt: string;
  updatedAt: string;
};

type ProfileInspectData = {
  profile: ProfileDetails;
  profileVersions: ProfileVersion[];
};

type Row = Record<string, unknown>;

export function ProfileInspectDetails({ row }: { row: Row | null }) {
  const profileId = row?.id ? String(row.id) : "";
  const [copied, setCopied] = React.useState(false);

  const queryClient = useQueryClient();

  const { data, error, isFetching } = useQuery({
    enabled: Boolean(profileId),
    queryKey: ["profile-inspect", profileId],
    queryFn: ({ signal }) =>
      graphqlClient<ProfileInspectData>({
        query: PROFILE_INSPECT_QUERY,
        variables: { id: profileId },
        signal,
      }),
    staleTime: 30_000,
  });

  const profile = data?.profile;
  const tenantId = profile?.tenantId ?? "";

  const tenantQuery = useQuery({
    enabled: Boolean(tenantId),
    queryKey: ["profile-inspect-tenant", tenantId],
    queryFn: ({ signal }) =>
      graphqlClient<{ tenant: { id: string; name: string } }>({
        query: TENANT_QUERY,
        variables: { id: tenantId },
        signal,
      }),
    staleTime: 60_000,
  });

  const versions = data?.profileVersions ?? [];
  const tenantName = tenantQuery.data?.tenant.name ?? tenantId;
  const nextVersion =
    versions.length > 0 ? Math.max(...versions.map((v) => v.version)) + 1 : 1;

  const createVersion = useMutation({
    mutationFn: (input: {
      version: number;
      jsonSchema: unknown;
      uiSchema: unknown;
      status: string;
    }) =>
      graphqlClient({
        query: CREATE_VERSION_MUTATION,
        variables: {
          profileId,
          input: {
            version: input.version,
            jsonSchema: input.jsonSchema,
            uiSchema: input.uiSchema,
            status: input.status,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Profile version created");
      queryClient.invalidateQueries({
        queryKey: ["profile-inspect", profileId],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  function copyId() {
    navigator.clipboard.writeText(profileId).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
        {error.message}
      </div>
    );
  }

  return (
    <>
      {isFetching && !profile ? (
        <div className="text-sm text-muted-foreground">
          Loading profile details…
        </div>
      ) : null}

      <div className="grid gap-3">
        <Field label="ID">
          <div className="flex items-center gap-2">
            <span className="break-all font-mono text-xs">{profileId}</span>
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

        {profile?.displayName ? (
          <Field label="Display name">
            <span className="text-sm font-medium">{profile.displayName}</span>
          </Field>
        ) : null}

        {tenantId ? (
          <Field label="Tenant">
            <span className="text-sm">{tenantName}</span>
          </Field>
        ) : null}

        <div className="grid grid-cols-3 gap-3">
          <Field label="Key">
            <span className="font-mono text-xs">{profile?.key ?? "—"}</span>
          </Field>
          <Field label="Object kind">
            <span className="font-mono text-xs">
              {profile?.objectKind ?? "—"}
            </span>
          </Field>
          <Field label="Kind">
            <span className="font-mono text-xs">{profile?.kind ?? "—"}</span>
          </Field>
        </div>

        {profile?.description ? (
          <Field label="Description">
            <span className="text-sm">{profile.description}</span>
          </Field>
        ) : null}

        {profile?.status ? (
          <Field label="Status">
            <StatusBadge value={profile.status} />
          </Field>
        ) : null}

        <div className="grid gap-3 sm:grid-cols-2">
          {profile?.createdAt ? (
            <Field label="Created">
              <DisplayTimeCell
                action={Action.Created}
                time={profile.createdAt}
              />
            </Field>
          ) : null}
          {profile?.updatedAt ? (
            <Field label="Updated">
              <DisplayTimeCell
                action={Action.Updated}
                time={profile.updatedAt}
              />
            </Field>
          ) : null}
        </div>
      </div>

      <ProfileVersionsSection
        isPending={createVersion.isPending}
        nextVersion={nextVersion}
        onCreateVersion={(input) => createVersion.mutate(input)}
        versions={versions}
      />
    </>
  );
}

function ProfileVersionsSection({
  versions,
  nextVersion,
  isPending,
  onCreateVersion,
}: {
  versions: ProfileVersion[];
  nextVersion: number;
  isPending: boolean;
  onCreateVersion: (input: {
    version: number;
    jsonSchema: unknown;
    uiSchema: unknown;
    status: string;
  }) => void;
}) {
  const [showForm, setShowForm] = React.useState(false);

  return (
    <div className="grid min-w-0 gap-3">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium">Profile versions</span>
        {!showForm ? (
          <Button onClick={() => setShowForm(true)} size="sm" variant="outline">
            <Plus className="size-3.5" />
            New version
          </Button>
        ) : null}
      </div>

      {showForm ? (
        <NewVersionForm
          isPending={isPending}
          nextVersion={nextVersion}
          onCancel={() => setShowForm(false)}
          onSubmit={(input) => {
            onCreateVersion(input);
            setShowForm(false);
          }}
        />
      ) : null}

      {versions.length === 1 ? (
        <div className="rounded-lg border bg-background p-3">
          <div className="mb-3 flex items-center gap-3">
            <span className="text-sm font-medium">v{versions[0].version}</span>
            <StatusBadge value={versions[0].status} />
            <DisplayTimeCell
              action={Action.Created}
              time={versions[0].createdAt}
            />
          </div>
          <ProfileVersionCard version={versions[0]} />
        </div>
      ) : versions.length > 1 ? (
        <Accordion className="w-full" type="multiple">
          {versions.map((version) => (
            <AccordionItem key={version.id} value={version.id}>
              <AccordionTrigger className="py-3 text-sm">
                <div className="flex items-center gap-3">
                  <span className="font-medium">v{version.version}</span>
                  <StatusBadge value={version.status} />
                </div>
              </AccordionTrigger>
              <AccordionContent className="h-auto">
                <div className="max-h-96 overflow-y-auto">
                  <div className="grid gap-3 pb-4">
                    <ProfileVersionCard version={version} />
                  </div>
                </div>
              </AccordionContent>
            </AccordionItem>
          ))}
        </Accordion>
      ) : (
        !showForm && (
          <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
            No profile versions yet.
          </div>
        )
      )}
    </div>
  );
}

function NewVersionForm({
  nextVersion,
  isPending,
  onCancel,
  onSubmit,
}: {
  nextVersion: number;
  isPending: boolean;
  onCancel: () => void;
  onSubmit: (input: {
    version: number;
    jsonSchema: unknown;
    uiSchema: unknown;
    status: string;
  }) => void;
}) {
  const [versionNum, setVersionNum] = React.useState(String(nextVersion));
  const [jsonCode, setJsonCode] = React.useState("{}");
  const [uiCode, setUiCode] = React.useState("{}");
  const [status, setStatus] = React.useState("active");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const vNum = Number.parseInt(versionNum, 10);
    if (Number.isNaN(vNum) || vNum < 1) {
      toast.error("Version must be a positive integer.");
      return;
    }
    let jsonSchema: unknown;
    let uiSchema: unknown;
    try {
      jsonSchema = JSON.parse(jsonCode);
    } catch {
      toast.error("JSON schema must be valid JSON.");
      return;
    }
    try {
      uiSchema = JSON.parse(uiCode);
    } catch {
      toast.error("UI schema must be valid JSON.");
      return;
    }
    onSubmit({ version: vNum, jsonSchema, uiSchema, status });
  }

  return (
    <form
      className="grid gap-4 rounded-lg border bg-muted/30 p-4"
      onSubmit={handleSubmit}
    >
      <div className="text-sm font-medium">New version</div>

      <div className="grid gap-2 sm:grid-cols-2">
        <div className="grid gap-2">
          <Label htmlFor="version-num">Version</Label>
          <Input
            id="version-num"
            min={1}
            onChange={(e) => setVersionNum(e.target.value)}
            required
            type="number"
            value={versionNum}
          />
        </div>
        <div className="grid gap-2">
          <Label htmlFor="version-status">Status</Label>
          <Select onValueChange={setStatus} value={status}>
            <SelectTrigger className="w-full" id="version-status">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="active">active</SelectItem>
              <SelectItem value="deprecated">deprecated</SelectItem>
              <SelectItem value="disabled">disabled</SelectItem>
            </SelectContent>
          </Select>
        </div>
      </div>

      <div className="grid gap-2">
        <Label>JSON schema</Label>
        <JsonEditor
          className="[&_.cm-editor]:min-h-36"
          onChange={setJsonCode}
          value={jsonCode}
        />
      </div>

      <div className="grid gap-2">
        <Label>UI schema</Label>
        <JsonEditor
          className="[&_.cm-editor]:min-h-36"
          onChange={setUiCode}
          value={uiCode}
        />
      </div>

      <div className="flex justify-end gap-2">
        <Button onClick={onCancel} type="button" variant="outline">
          Cancel
        </Button>
        <Button disabled={isPending} type="submit">
          Create version
        </Button>
      </div>
    </form>
  );
}

function ProfileVersionCard({ version }: { version: ProfileVersion }) {
  const jsonCode = React.useMemo(
    () => JSON.stringify(version.jsonSchema, null, 2),
    [version.jsonSchema],
  );
  const uiCode = React.useMemo(
    () => JSON.stringify(version.uiSchema, null, 2),
    [version.uiSchema],
  );

  return (
    <div className="grid min-w-0 gap-3">
      <div className="grid grid-cols-2 gap-3">
        <Field label="ID">
          <span className="break-all font-mono text-xs">{version.id}</span>
        </Field>
        <Field label="Version">
          <span className="font-mono text-xs">v{version.version}</span>
        </Field>
      </div>
      <div className="grid min-w-0 gap-4 lg:grid-cols-2">
        <SchemaViewer code={jsonCode} label="JSON schema" />
        <SchemaViewer code={uiCode} label="UI schema" />
      </div>
    </div>
  );
}

function SchemaViewer({ label, code }: { label: string; code: string }) {
  return (
    <div className="grid min-w-0 max-w-full gap-2">
      <div className="text-xs font-medium uppercase text-muted-foreground">
        {label}
      </div>
      <JsonEditor value={code} className="[&_.cm-editor]:min-h-48" />
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
