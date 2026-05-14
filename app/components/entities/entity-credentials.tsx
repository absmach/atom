"use client";

import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Eye,
  EyeOff,
  KeyRound,
  Lock,
  Plus,
  Shield,
  Trash2,
} from "lucide-react";
import * as React from "react";
import { toast } from "sonner";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DateTimePicker } from "@/components/ui/date-time-picker";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const CREDENTIALS_QUERY = `
  query EntityCredentials($entityId: ID!) {
    credentials(entityId: $entityId) {
      items {
        id
        kind
        status
        identifier
        expiresAt
        createdAt
      }
      total
    }
  }
`;

const CREATE_PASSWORD_MUTATION = `
  mutation CreatePassword($entityId: ID!, $password: String!) {
    createPassword(entityId: $entityId, password: $password)
  }
`;

const CREATE_API_KEY_MUTATION = `
  mutation CreateApiKey($entityId: ID!, $input: CreateApiKeyInput!) {
    createApiKey(entityId: $entityId, input: $input) {
      credentialId
      key
      expiresAt
    }
  }
`;

const REVOKE_CREDENTIAL_MUTATION = `
  mutation RevokeCredential($entityId: ID!, $credentialId: ID!) {
    revokeCredential(entityId: $entityId, credentialId: $credentialId)
  }
`;

type Credential = {
  id: string;
  kind: string;
  status: string;
  identifier: string | null;
  expiresAt: string | null;
  createdAt: string;
};

type CredentialKind = "password" | "api_key";

type AddCredentialState =
  | { kind: "password"; password: string; confirm: string }
  | { kind: "api_key"; description: string; expiresAt: string };

type ApiKeyResult = {
  credentialId: string;
  key: string;
  expiresAt: string | null;
};

export function EntityCredentials({ entityId }: { entityId: string }) {
  const [adding, setAdding] = React.useState(false);
  const [selectedKind, setSelectedKind] =
    React.useState<CredentialKind>("password");
  const [createdApiKey, setCreatedApiKey] = React.useState<ApiKeyResult | null>(
    null,
  );
  const [showPassword, setShowPassword] = React.useState(false);
  const [form, setForm] = React.useState<AddCredentialState>({
    kind: "password",
    password: "",
    confirm: "",
  });

  const { data, error, isFetching, refetch } = useQuery({
    enabled: Boolean(entityId),
    queryKey: ["entity-credentials", entityId],
    queryFn: ({ signal }) =>
      graphqlClient<{ credentials: { items: Credential[]; total: number } }>({
        query: CREDENTIALS_QUERY,
        variables: { entityId },
        signal,
      }),
    staleTime: 15_000,
  });

  const createPassword = useMutation({
    mutationFn: async (password: string) =>
      graphqlClient({
        query: CREATE_PASSWORD_MUTATION,
        variables: { entityId, password },
      }),
    onSuccess: () => {
      toast.success("Password credential created");
      setAdding(false);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const createApiKey = useMutation({
    mutationFn: async (input: { description?: string; expiresAt?: string }) =>
      graphqlClient<{ createApiKey: ApiKeyResult }>({
        query: CREATE_API_KEY_MUTATION,
        variables: { entityId, input },
      }),
    onSuccess: (data) => {
      setCreatedApiKey(data.createApiKey);
      setAdding(false);
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeCredential = useMutation({
    mutationFn: async (credentialId: string) =>
      graphqlClient({
        query: REVOKE_CREDENTIAL_MUTATION,
        variables: { entityId, credentialId },
      }),
    onSuccess: () => {
      toast.success("Credential revoked");
      void refetch();
    },
    onError: (err) => toast.error(err.message),
  });

  const credentials = data?.credentials.items ?? [];

  function handleKindChange(kind: CredentialKind) {
    setSelectedKind(kind);
    setForm(
      kind === "password"
        ? { kind: "password", password: "", confirm: "" }
        : { kind: "api_key", description: "", expiresAt: "" },
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (form.kind === "password") {
      if (!form.password) {
        toast.error("Password is required.");
        return;
      }
      if (form.password !== form.confirm) {
        toast.error("Passwords do not match.");
        return;
      }
      createPassword.mutate(form.password);
    } else {
      const input: { description?: string; expiresAt?: string } = {};
      if (form.description.trim()) input.description = form.description.trim();
      if (form.expiresAt.trim()) input.expiresAt = form.expiresAt.trim();
      createApiKey.mutate(input);
    }
  }

  const isPending = createPassword.isPending || createApiKey.isPending;

  return (
    <div className="grid gap-4">
      <div className="flex items-center justify-between">
        <div className="text-sm font-medium">Credentials</div>
        {!adding ? (
          <Button onClick={() => setAdding(true)} size="sm" variant="outline">
            <Plus data-icon="inline-start" className="size-3.5" />
            Add credential
          </Button>
        ) : null}
      </div>

      {createdApiKey ? (
        <ApiKeyRevealBanner
          apiKey={createdApiKey}
          onDismiss={() => setCreatedApiKey(null)}
        />
      ) : null}

      {adding ? (
        <div className="rounded-lg border bg-background p-4">
          <div className="mb-3 text-sm font-medium">New credential</div>
          <form className="grid gap-3" onSubmit={handleSubmit}>
            <div className="grid gap-2">
              <Label>Type</Label>
              <Select
                onValueChange={(v) => handleKindChange(v as CredentialKind)}
                value={selectedKind}
              >
                <SelectTrigger className="w-full">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value="password">
                      <span className="flex items-center gap-2">
                        <Lock className="size-3.5" />
                        Password
                      </span>
                    </SelectItem>
                    <SelectItem value="api_key">
                      <span className="flex items-center gap-2">
                        <KeyRound className="size-3.5" />
                        API Key
                      </span>
                    </SelectItem>
                  </SelectGroup>
                </SelectContent>
              </Select>
            </div>

            {form.kind === "password" ? (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="cred-password">Password</Label>
                  <div className="relative">
                    <Input
                      autoComplete="new-password"
                      id="cred-password"
                      onChange={(e) =>
                        setForm((prev) =>
                          prev.kind === "password"
                            ? { ...prev, password: e.target.value }
                            : prev,
                        )
                      }
                      required
                      type={showPassword ? "text" : "password"}
                      value={form.password}
                    />
                    <Button
                      className="absolute right-1 top-1/2 -translate-y-1/2"
                      onClick={() => setShowPassword((v) => !v)}
                      size="sm"
                      type="button"
                      variant="ghost"
                    >
                      {showPassword ? (
                        <EyeOff className="size-3.5" />
                      ) : (
                        <Eye className="size-3.5" />
                      )}
                    </Button>
                  </div>
                </div>
                <div className="grid gap-2">
                  <Label htmlFor="cred-confirm">Confirm password</Label>
                  <Input
                    autoComplete="new-password"
                    id="cred-confirm"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "password"
                          ? { ...prev, confirm: e.target.value }
                          : prev,
                      )
                    }
                    required
                    type={showPassword ? "text" : "password"}
                    value={form.confirm}
                  />
                </div>
              </>
            ) : (
              <>
                <div className="grid gap-2">
                  <Label htmlFor="cred-description">Description</Label>
                  <Input
                    id="cred-description"
                    onChange={(e) =>
                      setForm((prev) =>
                        prev.kind === "api_key"
                          ? { ...prev, description: e.target.value }
                          : prev,
                      )
                    }
                    placeholder="e.g. CI/CD pipeline key"
                    value={form.description}
                  />
                </div>
                <div className="grid gap-2">
                  <Label>Expires at (optional)</Label>
                  <DateTimePicker
                    value={form.expiresAt || undefined}
                    onChange={(v) =>
                      setForm((prev) =>
                        prev.kind === "api_key"
                          ? { ...prev, expiresAt: v }
                          : prev,
                      )
                    }
                    placeholder="No expiry"
                  />
                </div>
              </>
            )}

            <div className="flex justify-end gap-2">
              <Button
                onClick={() => setAdding(false)}
                type="button"
                variant="outline"
                size="sm"
              >
                Cancel
              </Button>
              <Button disabled={isPending} size="sm" type="submit">
                Create
              </Button>
            </div>
          </form>
        </div>
      ) : null}

      {isFetching && credentials.length === 0 ? (
        <div className="text-sm text-muted-foreground">
          Loading credentials…
        </div>
      ) : error ? (
        <div className="rounded-lg border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive">
          {error.message}
        </div>
      ) : credentials.length === 0 ? (
        <div className="rounded-lg border bg-background p-3 text-sm text-muted-foreground">
          No credentials found.
        </div>
      ) : (
        <div className="grid gap-2">
          {credentials.map((cred) => (
            <CredentialRow
              cred={cred}
              key={cred.id}
              onRevoke={() => {
                if (
                  window.confirm(
                    "Revoke this credential? This cannot be undone.",
                  )
                ) {
                  revokeCredential.mutate(cred.id);
                }
              }}
              revoking={revokeCredential.isPending}
            />
          ))}
        </div>
      )}
    </div>
  );
}

function CredentialRow({
  cred,
  onRevoke,
  revoking,
}: {
  cred: Credential;
  onRevoke: () => void;
  revoking: boolean;
}) {
  return (
    <div className="flex items-start justify-between gap-3 rounded-lg border bg-background p-3">
      <div className="flex min-w-0 items-start gap-2">
        <CredentialKindIcon kind={cred.kind} />
        <div className="grid min-w-0 gap-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-sm font-medium">
              {credentialKindLabel(cred.kind)}
            </span>
            <StatusBadge value={cred.status} />
          </div>
          {cred.identifier ? (
            <div className="font-mono text-xs text-muted-foreground truncate">
              {cred.identifier}
            </div>
          ) : null}
          <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
            <span>
              Created{" "}
              <DisplayTimeCell action={Action.Created} time={cred.createdAt} />
            </span>
            {cred.expiresAt ? (
              <span>
                Expires{" "}
                <DisplayTimeCell
                  action={Action.Expired}
                  time={cred.expiresAt}
                />
              </span>
            ) : null}
          </div>
        </div>
      </div>
      {cred.status === "active" ? (
        <Button
          disabled={revoking}
          onClick={onRevoke}
          size="sm"
          variant="ghost"
          className="shrink-0 text-destructive hover:text-destructive"
        >
          <Trash2 className="size-3.5" />
          <span className="sr-only">Revoke</span>
        </Button>
      ) : null}
    </div>
  );
}

function CredentialKindIcon({ kind }: { kind: string }) {
  switch (kind) {
    case "password":
      return <Lock className="mt-0.5 size-4 shrink-0 text-muted-foreground" />;
    case "api_key":
      return (
        <KeyRound className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      );
    default:
      return (
        <Shield className="mt-0.5 size-4 shrink-0 text-muted-foreground" />
      );
  }
}

function credentialKindLabel(kind: string) {
  switch (kind) {
    case "password":
      return "Password";
    case "api_key":
      return "API Key";
    case "certificate":
      return "Certificate";
    default:
      return kind;
  }
}

function ApiKeyRevealBanner({
  apiKey,
  onDismiss,
}: {
  apiKey: ApiKeyResult;
  onDismiss: () => void;
}) {
  const [copied, setCopied] = React.useState(false);

  async function copy() {
    await navigator.clipboard.writeText(apiKey.key);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="rounded-lg border border-yellow-200 bg-yellow-50 p-3 dark:border-yellow-800 dark:bg-yellow-950">
      <div className="mb-2 flex items-center justify-between">
        <div className="text-sm font-medium text-yellow-800 dark:text-yellow-200">
          API key created — copy it now
        </div>
        <Badge variant="outline" className="text-xs">
          shown once
        </Badge>
      </div>
      <p className="mb-2 text-xs text-yellow-700 dark:text-yellow-300">
        This key will not be shown again. Store it securely before dismissing.
      </p>
      <div className="mb-3 flex gap-2">
        <code className="min-w-0 flex-1 break-all rounded bg-yellow-100 px-2 py-1 font-mono text-xs text-yellow-900 dark:bg-yellow-900 dark:text-yellow-100">
          {apiKey.key}
        </code>
        <Button onClick={copy} size="sm" variant="outline">
          {copied ? "Copied!" : "Copy"}
        </Button>
      </div>
      <Button onClick={onDismiss} size="sm" variant="outline">
        Dismiss
      </Button>
    </div>
  );
}
