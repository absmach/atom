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

const PERSONAL_ACCESS_TOKENS_QUERY = `
  query ProfilePersonalAccessTokens {
    personalAccessTokens {
      items {
        credentialId
        name
        description
        identifier
        status
        expiresAt
        createdAt
      }
      total
    }
  }
`;

const CREATE_PERSONAL_ACCESS_TOKEN_MUTATION = `
  mutation CreatePersonalAccessToken($input: CreatePersonalAccessTokenInput!) {
    createPersonalAccessToken(input: $input) {
      credentialId
      token
      name
      description
      expiresAt
    }
  }
`;

const REVOKE_PERSONAL_ACCESS_TOKEN_MUTATION = `
  mutation RevokePersonalAccessToken($credentialId: ID!) {
    revokePersonalAccessToken(credentialId: $credentialId)
  }
`;

type EntityData = {
  entity: { id: string; name: string; attributes: Record<string, unknown> };
};

type CredentialsData = {
  credentials: { items: { id: string; kind: string }[] };
};

type PersonalAccessToken = {
  credentialId: string;
  name: string;
  description: string | null;
  identifier: string | null;
  status: string;
  expiresAt: string | null;
  createdAt: string;
};

type PersonalAccessTokensData = {
  personalAccessTokens: { items: PersonalAccessToken[]; total: number };
};

type CreatedPersonalAccessToken = {
  credentialId: string;
  token: string;
  name: string;
  description: string | null;
  expiresAt: string | null;
};

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

const personalAccessTokenSchema = z.object({
  name: z.string().trim().min(1, "Name is required"),
  description: z.string(),
  expiresAt: z.string(),
});

type AccountValues = z.infer<typeof accountSchema>;
type PasswordValues = z.infer<typeof passwordSchema>;
type PersonalAccessTokenValues = z.infer<typeof personalAccessTokenSchema>;

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
      <PersonalAccessTokenSection />
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

function PersonalAccessTokenSection() {
  const queryClient = useQueryClient();
  const [createdToken, setCreatedToken] =
    React.useState<CreatedPersonalAccessToken | null>(null);
  const form = useForm<PersonalAccessTokenValues>({
    resolver: zodResolver(personalAccessTokenSchema),
    defaultValues: { name: "", description: "", expiresAt: "" },
  });

  const { data, error, isLoading } = useQuery({
    queryKey: ["profile-personal-access-tokens"],
    queryFn: ({ signal }) =>
      graphqlClient<PersonalAccessTokensData>({
        query: PERSONAL_ACCESS_TOKENS_QUERY,
        signal,
      }),
    staleTime: 15_000,
  });

  const createToken = useMutation({
    mutationFn: async (values: PersonalAccessTokenValues) => {
      const input: {
        name: string;
        description?: string;
        expiresAt?: string;
      } = { name: values.name.trim() };
      if (values.description.trim()) {
        input.description = values.description.trim();
      }
      if (values.expiresAt.trim()) {
        input.expiresAt = values.expiresAt.trim();
      }
      return graphqlClient<{
        createPersonalAccessToken: CreatedPersonalAccessToken;
      }>({
        query: CREATE_PERSONAL_ACCESS_TOKEN_MUTATION,
        variables: { input },
      });
    },
    onSuccess: (response) => {
      setCreatedToken(response.createPersonalAccessToken);
      form.reset({ name: "", description: "", expiresAt: "" });
      toast.success("Personal access token created");
      void queryClient.invalidateQueries({
        queryKey: ["profile-personal-access-tokens"],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  const revokeToken = useMutation({
    mutationFn: async (credentialId: string) =>
      graphqlClient({
        query: REVOKE_PERSONAL_ACCESS_TOKEN_MUTATION,
        variables: { credentialId },
      }),
    onSuccess: () => {
      toast.success("Personal access token revoked");
      void queryClient.invalidateQueries({
        queryKey: ["profile-personal-access-tokens"],
      });
    },
    onError: (err) => toast.error(err.message),
  });

  const tokens = data?.personalAccessTokens.items ?? [];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Personal Access Tokens</CardTitle>
        <CardDescription>
          Create and revoke tokens for command-line and API access.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {createdToken ? (
          <PersonalAccessTokenReveal
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
              Failed to load personal access tokens.
            </div>
          ) : tokens.length === 0 ? (
            <div className="p-4 text-sm text-muted-foreground">
              No personal access tokens.
            </div>
          ) : (
            <div className="divide-y">
              {tokens.map((token) => (
                <PersonalAccessTokenRow
                  key={token.credentialId}
                  token={token}
                  onRevoke={(credentialId) => revokeToken.mutate(credentialId)}
                  revokePending={
                    revokeToken.isPending &&
                    revokeToken.variables === token.credentialId
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

function PersonalAccessTokenRow({
  token,
  onRevoke,
  revokePending,
}: {
  token: PersonalAccessToken;
  onRevoke: (credentialId: string) => void;
  revokePending: boolean;
}) {
  const active = token.status === "active";

  return (
    <div className="grid gap-3 p-4 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-center">
      <div className="min-w-0 space-y-1">
        <div className="flex min-w-0 flex-wrap items-center gap-2">
          <KeyRound className="size-4 shrink-0 text-muted-foreground" />
          <span className="truncate text-sm font-medium">{token.name}</span>
          <Badge variant={active ? "secondary" : "outline"}>
            {token.status}
          </Badge>
        </div>
        {token.description ? (
          <p className="text-sm text-muted-foreground">{token.description}</p>
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
      </div>
      <Button
        className="justify-self-start sm:justify-self-end"
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
  );
}

function PersonalAccessTokenReveal({
  token,
  onDismiss,
}: {
  token: CreatedPersonalAccessToken;
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
          <div className="font-medium">
            Personal access token created — copy it now
          </div>
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
