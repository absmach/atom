"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import * as z from "zod";

import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
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
import { graphqlClient } from "@/lib/graphql/client";

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

type EntityData = {
  entity: { id: string; name: string; attributes: Record<string, unknown> };
};

type CredentialsData = {
  credentials: { items: { id: string; kind: string }[] };
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

type AccountValues = z.infer<typeof accountSchema>;
type PasswordValues = z.infer<typeof passwordSchema>;

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
