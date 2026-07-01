"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, KeyRound, Loader2, Trash2 } from "lucide-react";
import * as React from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import * as z from "zod";

import { DisplayTimeCell } from "@/components/display-time";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { DateTimePicker } from "@/components/ui/date-time-picker";
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
import { PasswordInput } from "@/components/ui/password-input";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const ENTITY_QUERY = `
  query ProfileEntity($id: ID!) {
    entity(id: $id) {
      id
      name
      attributes
    }
  }
`;

const UPDATE_ENTITY_MUTATION = `
  mutation UpdateProfileEntity($id: ID!, $input: UpdateEntityInput!) {
    updateEntity(id: $id, input: $input) {
      id
      name
      attributes
    }
  }
`;

const CREDENTIALS_QUERY = `
  query ProfileCredentials($entityId: ID!) {
    credentials(entityId: $entityId) {
      items { id kind }
    }
  }
`;

const REVOKE_CREDENTIAL_MUTATION = `
  mutation RevokeProfileCredential($entityId: ID!, $credentialId: ID!) {
    revokeCredential(entityId: $entityId, credentialId: $credentialId)
  }
`;

const CREATE_PASSWORD_MUTATION = `
  mutation CreateProfilePassword($entityId: ID!, $password: String!) {
    createPassword(entityId: $entityId, password: $password)
  }
`;

const ACCESS_TOKENS_QUERY = `
  query ProfileAccessTokens {
    accessTokens {
      items {
        credentialId
        name
        description
        identifier
        status
        scoped
        permissions {
          actions
          scopeMode
          tenantId
          objectKind
          objectType
          objectId
        }
        expiresAt
        createdAt
      }
      total
    }
  }
`;

const CREATE_ACCESS_TOKEN_MUTATION = `
  mutation CreateAccessToken($input: CreateAccessTokenInput!) {
    createAccessToken(input: $input) {
      credentialId
      token
      name
      description
      expiresAt
    }
  }
`;

const REVOKE_ACCESS_TOKEN_MUTATION = `
  mutation RevokeAccessToken($credentialId: ID!) {
    revokeAccessToken(credentialId: $credentialId)
  }
`;

const REPLACE_ACCESS_TOKEN_PERMISSIONS_MUTATION = `
  mutation ReplaceAccessTokenPermissions(
    $credentialId: ID!
    $permissions: [AccessTokenPermissionInput!]!
  ) {
    replaceAccessTokenPermissions(
      credentialId: $credentialId
      permissions: $permissions
    )
  }
`;

type EntityData = {
  entity: { id: string; name: string; attributes: Record<string, unknown> };
};

type CredentialsData = {
  credentials: { items: { id: string; kind: string }[] };
};

type AccessTokenPermission = {
  actions: string[];
  scopeMode: string;
  tenantId: string | null;
  objectKind: string | null;
  objectType: string | null;
  objectId: string | null;
};

type AccessToken = {
  credentialId: string;
  name: string;
  description: string | null;
  identifier: string | null;
  status: string;
  scoped: boolean;
  permissions: AccessTokenPermission[];
  expiresAt: string | null;
  createdAt: string;
};

type AccessTokensData = {
  accessTokens: { items: AccessToken[]; total: number };
};

type CreatedAccessToken = {
  credentialId: string;
  token: string;
  name: string;
  description: string | null;
  expiresAt: string | null;
};

const SCOPE_MODES = [
  "platform",
  "tenant",
  "object_kind",
  "object_type",
  "object",
] as const;
type ScopeMode = (typeof SCOPE_MODES)[number];

// A permission row in the create form, edited as raw strings before being
// translated into a GraphQL AccessTokenPermissionInput on submit.
type PermissionDraft = {
  // Stable client-only key so React can track editable rows across reorders and
  // removals; never sent to the API (see buildPermissionInputs).
  id: string;
  actions: string;
  scopeMode: ScopeMode;
  tenantId: string;
  objectKind: string;
  objectType: string;
  objectId: string;
};

function emptyPermissionDraft(): PermissionDraft {
  return {
    id: crypto.randomUUID(),
    actions: "",
    scopeMode: "object_kind",
    tenantId: "",
    objectKind: "",
    objectType: "",
    objectId: "",
  };
}

function draftsFromPermissions(
  permissions: AccessTokenPermission[],
): PermissionDraft[] {
  if (permissions.length === 0) {
    return [emptyPermissionDraft()];
  }
  return permissions.map((permission) => ({
    id: crypto.randomUUID(),
    actions: permission.actions.join(", "),
    scopeMode: (SCOPE_MODES.includes(permission.scopeMode as ScopeMode)
      ? permission.scopeMode
      : "object_kind") as ScopeMode,
    tenantId: permission.tenantId ?? "",
    objectKind: permission.objectKind ?? "",
    objectType: permission.objectType ?? "",
    objectId: permission.objectId ?? "",
  }));
}

const accountSchema = z.object({
  firstName: z.string().min(1, "First name is required"),
  lastName: z.string().min(1, "Last name is required"),
  username: z
    .string()
    .min(1, "Username is required")
    .regex(/^\S+$/, "Username must not contain spaces"),
  email: z.email("Invalid email address"),
});

const passwordSchema = z
  .object({
    newPassword: z.string().min(1, "New password is required"),
    confirmPassword: z.string(),
  })
  .refine((d) => d.newPassword === d.confirmPassword, {
    message: "Passwords do not match",
    path: ["confirmPassword"],
  });

const accessTokenSchema = z.object({
  name: z.string().trim().min(1, "Name is required"),
  description: z.string(),
  expiresAt: z.string(),
});

type AccountValues = z.infer<typeof accountSchema>;
type PasswordValues = z.infer<typeof passwordSchema>;
type AccessTokenValues = z.infer<typeof accessTokenSchema>;

export function ProfileForm({ entityId }: { entityId: string }) {
  const queryClient = useQueryClient();

  const { data, isLoading, error } = useQuery({
    queryKey: ["profile-entity", entityId],
    queryFn: () =>
      graphqlClient<EntityData>({
        query: ENTITY_QUERY,
        variables: { id: entityId },
      }),
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 p-8 text-muted-foreground">
        <Loader2 className="animate-spin size-4" />
        Loading profile…
      </div>
    );
  }

  if (error || !data) {
    return (
      <Alert variant="destructive" className="m-4">
        <AlertDescription>Failed to load profile.</AlertDescription>
      </Alert>
    );
  }

  const { entity } = data;
  const attrs = (entity.attributes ?? {}) as Record<string, unknown>;

  return (
    <div className="max-w-2xl space-y-6 p-6">
      <div>
        <h1 className="text-2xl font-semibold">Profile</h1>
        <p className="text-sm text-muted-foreground">
          Manage your account details and password.
        </p>
      </div>
      <AccountSection
        entityId={entityId}
        defaultValues={{
          firstName: String(attrs.first_name ?? ""),
          lastName: String(attrs.last_name ?? ""),
          username: entity.name,
          email: String(attrs.email ?? ""),
        }}
        onSaved={() =>
          queryClient.invalidateQueries({
            queryKey: ["profile-entity", entityId],
          })
        }
      />
      <PasswordSection entityId={entityId} />
      <AccessTokenSection />
    </div>
  );
}

function AccountSection({
  entityId,
  defaultValues,
  onSaved,
}: {
  entityId: string;
  defaultValues: AccountValues;
  onSaved: () => void;
}) {
  const form = useForm<AccountValues>({
    resolver: zodResolver(accountSchema),
    defaultValues,
  });

  const update = useMutation({
    mutationFn: (values: AccountValues) =>
      graphqlClient({
        query: UPDATE_ENTITY_MUTATION,
        variables: {
          id: entityId,
          input: {
            name: values.username,
            attributes: {
              first_name: values.firstName,
              last_name: values.lastName,
              email: values.email,
            },
          },
        },
      }),
    onSuccess: () => {
      toast.success("Profile updated");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Account</CardTitle>
        <CardDescription>Update your name, username and email.</CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form
            className="grid gap-4"
            onSubmit={form.handleSubmit((v) => update.mutate(v))}
          >
            {form.formState.errors.root ? (
              <Alert variant="destructive">
                <AlertDescription>
                  {form.formState.errors.root.message}
                </AlertDescription>
              </Alert>
            ) : null}
            <div className="grid grid-cols-2 gap-4">
              <FormField
                control={form.control}
                name="firstName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>First Name</FormLabel>
                    <FormControl>
                      <Input autoComplete="given-name" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="lastName"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Last Name</FormLabel>
                    <FormControl>
                      <Input autoComplete="family-name" {...field} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="username"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Username</FormLabel>
                  <FormControl>
                    <Input autoComplete="username" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="email"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Email</FormLabel>
                  <FormControl>
                    <Input type="email" autoComplete="email" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="flex justify-end">
              <Button type="submit" disabled={update.isPending}>
                {update.isPending ? <Loader2 className="animate-spin" /> : null}
                Save changes
              </Button>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}

function PasswordSection({ entityId }: { entityId: string }) {
  const form = useForm<PasswordValues>({
    resolver: zodResolver(passwordSchema),
    defaultValues: { newPassword: "", confirmPassword: "" },
  });

  const changePassword = useMutation({
    mutationFn: async (values: PasswordValues) => {
      const creds = await graphqlClient<CredentialsData>({
        query: CREDENTIALS_QUERY,
        variables: { entityId },
      });
      const passwordCred = creds.credentials.items.find(
        (c) => c.kind === "password",
      );
      if (passwordCred) {
        await graphqlClient({
          query: REVOKE_CREDENTIAL_MUTATION,
          variables: { entityId, credentialId: passwordCred.id },
        });
      }
      await graphqlClient({
        query: CREATE_PASSWORD_MUTATION,
        variables: { entityId, password: values.newPassword },
      });
    },
    onSuccess: () => {
      toast.success("Password updated");
      form.reset();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Card>
      <CardHeader>
        <CardTitle>Change Password</CardTitle>
        <CardDescription>
          Setting a new password will invalidate your current one.
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Form {...form}>
          <form
            className="grid gap-4"
            onSubmit={form.handleSubmit((v) => changePassword.mutate(v))}
          >
            <FormField
              control={form.control}
              name="newPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>New Password</FormLabel>
                  <FormControl>
                    <PasswordInput autoComplete="new-password" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <FormField
              control={form.control}
              name="confirmPassword"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Confirm Password</FormLabel>
                  <FormControl>
                    <PasswordInput autoComplete="new-password" {...field} />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />
            <div className="flex justify-end">
              <Button type="submit" disabled={changePassword.isPending}>
                {changePassword.isPending ? (
                  <Loader2 className="animate-spin" />
                ) : null}
                Update password
              </Button>
            </div>
          </form>
        </Form>
      </CardContent>
    </Card>
  );
}

function AccessTokenSection() {
  const queryClient = useQueryClient();
  const [createdToken, setCreatedToken] =
    React.useState<CreatedAccessToken | null>(null);
  const [permissions, setPermissions] = React.useState<PermissionDraft[]>([
    emptyPermissionDraft(),
  ]);
  const form = useForm<AccessTokenValues>({
    resolver: zodResolver(accessTokenSchema),
    defaultValues: { name: "", description: "", expiresAt: "" },
  });

  const { data, error, isLoading } = useQuery({
    queryKey: ["profile-access-tokens"],
    queryFn: ({ signal }) =>
      graphqlClient<AccessTokensData>({
        query: ACCESS_TOKENS_QUERY,
        signal,
      }),
    staleTime: 15_000,
  });

  const createToken = useMutation({
    mutationFn: async (values: AccessTokenValues) => {
      const permissionInputs = buildPermissionInputs(permissions);
      if (permissionInputs.length === 0) {
        throw new Error("Add at least one permission with an action");
      }
      const input: {
        name: string;
        description?: string;
        expiresAt?: string;
        permissions: ReturnType<typeof buildPermissionInputs>;
      } = { name: values.name.trim(), permissions: permissionInputs };
      if (values.description.trim()) {
        input.description = values.description.trim();
      }
      if (values.expiresAt.trim()) {
        input.expiresAt = values.expiresAt.trim();
      }
      return graphqlClient<{
        createAccessToken: CreatedAccessToken;
      }>({
        query: CREATE_ACCESS_TOKEN_MUTATION,
        variables: { input },
      });
    },
    onSuccess: (response) => {
      setCreatedToken(response.createAccessToken);
      form.reset({ name: "", description: "", expiresAt: "" });
      setPermissions([emptyPermissionDraft()]);
      toast.success("Access token created");
      void queryClient.invalidateQueries({
        queryKey: ["profile-access-tokens"],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeToken = useMutation({
    mutationFn: async (credentialId: string) =>
      graphqlClient({
        query: REVOKE_ACCESS_TOKEN_MUTATION,
        variables: { credentialId },
      }),
    onSuccess: () => {
      toast.success("Access token revoked");
      void queryClient.invalidateQueries({
        queryKey: ["profile-access-tokens"],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  const replacePermissions = useMutation({
    mutationFn: async (args: {
      credentialId: string;
      drafts: PermissionDraft[];
    }) => {
      const permissions = buildPermissionInputs(args.drafts);
      if (permissions.length === 0) {
        throw new Error("Add at least one permission with an action");
      }
      return graphqlClient({
        query: REPLACE_ACCESS_TOKEN_PERMISSIONS_MUTATION,
        variables: { credentialId: args.credentialId, permissions },
      });
    },
    onSuccess: () => {
      toast.success("Access token permissions updated");
      void queryClient.invalidateQueries({
        queryKey: ["profile-access-tokens"],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  const tokens = data?.accessTokens.items ?? [];

  function updatePermission(index: number, patch: Partial<PermissionDraft>) {
    setPermissions((prev) =>
      prev.map((p, i) => (i === index ? { ...p, ...patch } : p)),
    );
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Access Tokens</CardTitle>
        <CardDescription>
          Create scoped tokens for command-line and API access. A token can
          never exceed your own permissions, and is further limited to the
          permissions you grant it below.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {createdToken ? (
          <AccessTokenReveal
            token={createdToken}
            onDismiss={() => setCreatedToken(null)}
          />
        ) : null}

        <Form {...form}>
          <form
            className="grid gap-4"
            onSubmit={form.handleSubmit((values) => createToken.mutate(values))}
          >
            <div className="grid gap-4 md:grid-cols-[minmax(0,1fr)_minmax(13rem,0.7fr)]">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name</FormLabel>
                    <FormControl>
                      <Input
                        autoComplete="off"
                        placeholder="e.g. laptop CLI"
                        {...field}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name="expiresAt"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Expires at</FormLabel>
                    <FormControl>
                      <DateTimePicker
                        onChange={field.onChange}
                        placeholder="No expiry"
                        value={field.value || undefined}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>
            <FormField
              control={form.control}
              name="description"
              render={({ field }) => (
                <FormItem>
                  <FormLabel>Description</FormLabel>
                  <FormControl>
                    <Textarea
                      className="min-h-20"
                      placeholder="Optional"
                      {...field}
                    />
                  </FormControl>
                  <FormMessage />
                </FormItem>
              )}
            />

            <div className="grid gap-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Permissions</span>
                <Button
                  onClick={() =>
                    setPermissions((prev) => [...prev, emptyPermissionDraft()])
                  }
                  size="sm"
                  type="button"
                  variant="outline"
                >
                  Add permission
                </Button>
              </div>
              {permissions.map((permission, index) => (
                <PermissionDraftRow
                  key={permission.id}
                  permission={permission}
                  canRemove={permissions.length > 1}
                  onChange={(patch) => updatePermission(index, patch)}
                  onRemove={() =>
                    setPermissions((prev) => prev.filter((_, i) => i !== index))
                  }
                />
              ))}
            </div>

            <div className="flex justify-end">
              <Button type="submit" disabled={createToken.isPending}>
                {createToken.isPending ? (
                  <Loader2 className="animate-spin" />
                ) : (
                  <KeyRound data-icon="inline-start" />
                )}
                Create token
              </Button>
            </div>
          </form>
        </Form>

        <div className="rounded-md border">
          {isLoading ? (
            <div className="flex items-center gap-2 p-4 text-sm text-muted-foreground">
              <Loader2 className="size-4 animate-spin" />
              Loading tokens…
            </div>
          ) : error ? (
            <div className="p-4 text-sm text-destructive">
              Failed to load access tokens.
            </div>
          ) : tokens.length === 0 ? (
            <div className="p-4 text-sm text-muted-foreground">
              No access tokens.
            </div>
          ) : (
            <div className="divide-y">
              {tokens.map((token) => (
                <AccessTokenRow
                  key={token.credentialId}
                  token={token}
                  onRevoke={(credentialId) => revokeToken.mutate(credentialId)}
                  revokePending={
                    revokeToken.isPending &&
                    revokeToken.variables === token.credentialId
                  }
                  onReplacePermissions={(drafts) =>
                    replacePermissions.mutateAsync({
                      credentialId: token.credentialId,
                      drafts,
                    })
                  }
                  replacePending={
                    replacePermissions.isPending &&
                    replacePermissions.variables?.credentialId ===
                      token.credentialId
                  }
                />
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

/// Translate the raw permission drafts into GraphQL inputs, dropping rows with no
/// actions and only including the scope fields relevant to each scope mode.
function buildPermissionInputs(drafts: PermissionDraft[]) {
  const inputs: Array<{
    actions: string[];
    scopeMode: string;
    tenantId?: string;
    objectKind?: string;
    objectType?: string;
    objectId?: string;
  }> = [];
  for (const draft of drafts) {
    const actions = draft.actions
      .split(",")
      .map((a) => a.trim())
      .filter(Boolean);
    if (actions.length === 0) {
      continue;
    }
    const input: (typeof inputs)[number] = {
      actions,
      scopeMode: draft.scopeMode,
    };
    if (draft.scopeMode === "tenant" && draft.tenantId.trim()) {
      input.tenantId = draft.tenantId.trim();
    }
    if (
      (draft.scopeMode === "object_kind" ||
        draft.scopeMode === "object_type") &&
      draft.objectKind.trim()
    ) {
      input.objectKind = draft.objectKind.trim();
    }
    if (draft.scopeMode === "object_type" && draft.objectType.trim()) {
      input.objectType = draft.objectType.trim();
    }
    if (draft.scopeMode === "object" && draft.objectId.trim()) {
      input.objectId = draft.objectId.trim();
    }
    inputs.push(input);
  }
  return inputs;
}

function PermissionDraftRow({
  permission,
  canRemove,
  onChange,
  onRemove,
}: {
  permission: PermissionDraft;
  canRemove: boolean;
  onChange: (patch: Partial<PermissionDraft>) => void;
  onRemove: () => void;
}) {
  return (
    <div className="grid gap-2 rounded-md border p-3">
      <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_minmax(9rem,auto)_auto] sm:items-end">
        <div className="grid gap-1">
          <Label>Actions</Label>
          <Input
            aria-label="Actions"
            onChange={(e) => onChange({ actions: e.target.value })}
            placeholder="read, manage"
            value={permission.actions}
          />
        </div>
        <div className="grid gap-1">
          <Label>Scope</Label>
          <select
            aria-label="Scope"
            className="h-9 rounded-md border border-input bg-transparent px-3 text-sm shadow-sm"
            onChange={(e) =>
              onChange({ scopeMode: e.target.value as ScopeMode })
            }
            value={permission.scopeMode}
          >
            {SCOPE_MODES.map((mode) => (
              <option key={mode} value={mode}>
                {mode}
              </option>
            ))}
          </select>
        </div>
        {canRemove ? (
          <Button onClick={onRemove} size="sm" type="button" variant="ghost">
            <Trash2 data-icon="inline-start" />
            Remove
          </Button>
        ) : null}
      </div>
      {permission.scopeMode === "tenant" ? (
        <div className="grid gap-1">
          <Label>Tenant ID</Label>
          <Input
            aria-label="Tenant ID"
            onChange={(e) => onChange({ tenantId: e.target.value })}
            placeholder="tenant uuid"
            value={permission.tenantId}
          />
        </div>
      ) : null}
      {permission.scopeMode === "object_kind" ||
      permission.scopeMode === "object_type" ? (
        <div className="grid gap-2 sm:grid-cols-2">
          <div className="grid gap-1">
            <Label>Object kind</Label>
            <Input
              aria-label="Object kind"
              onChange={(e) => onChange({ objectKind: e.target.value })}
              placeholder="entity"
              value={permission.objectKind}
            />
          </div>
          {permission.scopeMode === "object_type" ? (
            <div className="grid gap-1">
              <Label>Object type</Label>
              <Input
                aria-label="Object type"
                onChange={(e) => onChange({ objectType: e.target.value })}
                placeholder="e.g. entity:device"
                value={permission.objectType}
              />
            </div>
          ) : null}
        </div>
      ) : null}
      {permission.scopeMode === "object" ? (
        <div className="grid gap-1">
          <Label>Object ID</Label>
          <Input
            aria-label="Object ID"
            onChange={(e) => onChange({ objectId: e.target.value })}
            placeholder="object uuid"
            value={permission.objectId}
          />
        </div>
      ) : null}
    </div>
  );
}

function permissionSummary(permission: AccessTokenPermission): string {
  const actions = permission.actions.join(", ") || "—";
  let target = permission.scopeMode;
  if (permission.scopeMode === "tenant" && permission.tenantId) {
    target = `tenant ${permission.tenantId}`;
  } else if (permission.scopeMode === "object_kind" && permission.objectKind) {
    target = `kind ${permission.objectKind}`;
  } else if (permission.scopeMode === "object_type" && permission.objectType) {
    // object_type is already namespaced (e.g. "entity:device").
    target = permission.objectType;
  } else if (permission.scopeMode === "object" && permission.objectId) {
    target = `object ${permission.objectId}`;
  }
  return `${actions} on ${target}`;
}

function AccessTokenRow({
  token,
  onRevoke,
  revokePending,
  onReplacePermissions,
  replacePending,
}: {
  token: AccessToken;
  onRevoke: (credentialId: string) => void;
  revokePending: boolean;
  onReplacePermissions: (drafts: PermissionDraft[]) => Promise<unknown>;
  replacePending: boolean;
}) {
  const active = token.status === "active";
  const [editing, setEditing] = React.useState(false);
  const [drafts, setDrafts] = React.useState<PermissionDraft[]>(() =>
    draftsFromPermissions(token.permissions),
  );

  function startEditing() {
    setDrafts(draftsFromPermissions(token.permissions));
    setEditing(true);
  }

  function updateDraft(index: number, patch: Partial<PermissionDraft>) {
    setDrafts((prev) =>
      prev.map((p, i) => (i === index ? { ...p, ...patch } : p)),
    );
  }

  async function save() {
    await onReplacePermissions(drafts);
    setEditing(false);
  }

  return (
    <div className="grid gap-3 p-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-start">
      <div className="min-w-0 space-y-1">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <KeyRound className="size-4 shrink-0 text-muted-foreground" />
          <span className="truncate text-sm font-medium">{token.name}</span>
          <Badge variant={active ? "secondary" : "outline"}>
            {token.status}
          </Badge>
          {token.scoped ? <Badge variant="outline">scoped</Badge> : null}
        </div>
        {token.description ? (
          <p className="text-sm text-muted-foreground">{token.description}</p>
        ) : null}
        {token.permissions.length > 0 ? (
          <ul className="space-y-0.5 text-xs text-muted-foreground">
            {token.permissions.map((permission, index) => (
              <li
                key={`${permissionSummary(permission)}-${index}`}
                className="font-mono"
              >
                {permissionSummary(permission)}
              </li>
            ))}
          </ul>
        ) : null}
        <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted-foreground">
          {token.identifier ? (
            <span className="font-mono">{token.identifier}</span>
          ) : null}
          <span>
            Created <DisplayTimeCell time={token.createdAt} />
          </span>
          <span>
            {token.expiresAt ? (
              <DisplayTimeCell action={Action.Expired} time={token.expiresAt} />
            ) : (
              "No expiry"
            )}
          </span>
        </div>

        {editing ? (
          <div className="mt-3 grid gap-2">
            {drafts.map((permission, index) => (
              <PermissionDraftRow
                key={permission.id}
                permission={permission}
                canRemove={drafts.length > 1}
                onChange={(patch) => updateDraft(index, patch)}
                onRemove={() =>
                  setDrafts((prev) => prev.filter((_, i) => i !== index))
                }
              />
            ))}
            <div className="flex flex-wrap gap-2">
              <Button
                onClick={() =>
                  setDrafts((prev) => [...prev, emptyPermissionDraft()])
                }
                size="sm"
                type="button"
                variant="outline"
              >
                Add permission
              </Button>
              <Button
                disabled={replacePending}
                onClick={() => void save()}
                size="sm"
                type="button"
              >
                {replacePending ? <Loader2 className="animate-spin" /> : null}
                Save permissions
              </Button>
              <Button
                onClick={() => setEditing(false)}
                size="sm"
                type="button"
                variant="ghost"
              >
                Cancel
              </Button>
            </div>
          </div>
        ) : null}
      </div>
      <div className="flex flex-wrap gap-2 justify-self-start sm:justify-self-end">
        {active && token.scoped && !editing ? (
          <Button
            onClick={startEditing}
            size="sm"
            type="button"
            variant="outline"
          >
            <KeyRound data-icon="inline-start" />
            Edit permissions
          </Button>
        ) : null}
        <Button
          disabled={!active || revokePending}
          onClick={() => onRevoke(token.credentialId)}
          size="sm"
          type="button"
          variant="outline"
        >
          {revokePending ? (
            <Loader2 className="animate-spin" />
          ) : (
            <Trash2 data-icon="inline-start" />
          )}
          Revoke
        </Button>
      </div>
    </div>
  );
}

function AccessTokenReveal({
  token,
  onDismiss,
}: {
  token: CreatedAccessToken;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = React.useState(false);

  async function copy() {
    await navigator.clipboard.writeText(token.token);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1500);
  }

  return (
    <Alert>
      <KeyRound className="size-4" />
      <AlertDescription>
        <div className="grid gap-3">
          <div className="font-medium">Access token created — copy it now</div>
          <code className="block break-all rounded-md bg-muted px-3 py-2 font-mono text-xs">
            {token.token}
          </code>
          <div className="flex flex-wrap gap-2">
            <Button onClick={copy} size="sm" type="button" variant="outline">
              <Copy data-icon="inline-start" />
              {copied ? "Copied!" : "Copy"}
            </Button>
            <Button onClick={onDismiss} size="sm" type="button" variant="ghost">
              Dismiss
            </Button>
          </div>
        </div>
      </AlertDescription>
    </Alert>
  );
}
