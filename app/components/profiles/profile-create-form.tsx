"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { type UseFormReturn, useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import {
  ProfileVersionForm,
  type ProfileVersionSubmitInput,
} from "@/components/profiles/profile-version-form";
import { Badge } from "@/components/ui/badge";
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
import { GLOBAL_TENANT } from "@/lib/tenant/context";

const TENANTS_QUERY = `
  query ProfileFormTenants {
    tenants(limit: 100, offset: 0) {
      items { id name }
    }
  }
`;

const CREATE_PROFILE_WITH_ID_MUTATION = `
  mutation CreateProfileWithId($input: CreateProfileInput!) {
    createProfile(input: $input) {
      id
      objectKind
      kind
      key
      displayName
      status
      createdAt
      updatedAt
    }
  }
`;

const CREATE_PROFILE_VERSION_MUTATION = `
  mutation CreateProfileVersion($profileId: ID!, $input: CreateProfileVersionInput!) {
    createProfileVersion(profileId: $profileId, input: $input) {
      id
      version
      status
      createdAt
    }
  }
`;

const PROFILE_OBJECT_KINDS = [
  "entity",
  "resource",
  "group",
  "tenant",
  "credential",
] as const;
const ENTITY_KINDS = [
  "human",
  "device",
  "service",
  "workload",
  "application",
] as const;
const GLOBAL_TENANT_VALUE = "__global__";

type TenantOption = { id: string; name: string };
type TenantsPickerData = { tenants: { items: TenantOption[] } };
type ProfileCreateResponse = {
  createProfile: { id: string };
};

const profileFormSchema = z
  .object({
    objectKind: z.enum(PROFILE_OBJECT_KINDS),
    kind: z.string().trim().min(1, "Kind is required."),
    key: z.string().trim().min(1, "Profile key is required."),
    displayName: z.string().trim().min(1, "Display name is required."),
    description: z.string().trim(),
    tenantId: z.string().trim(),
  })
  .superRefine((value, ctx) => {
    if (
      value.objectKind === "entity" &&
      !ENTITY_KINDS.includes(value.kind as never)
    ) {
      ctx.addIssue({
        code: "custom",
        path: ["kind"],
        message: "Entity profiles must use a supported entity kind.",
      });
    }
  });

type ProfileFormValues = z.infer<typeof profileFormSchema>;

const defaultValues: ProfileFormValues = {
  objectKind: "entity",
  kind: "human",
  key: "",
  displayName: "",
  description: "",
  tenantId: "",
};

export function ProfileCreateForm({
  onCancel,
  onCreated,
}: {
  onCancel: () => void;
  onCreated: () => void;
}) {
  const [step, setStep] = React.useState<"basics" | "version">("basics");
  const form = useForm<ProfileFormValues>({
    resolver: zodResolver(profileFormSchema),
    mode: "onSubmit",
    defaultValues,
  });
  const objectKind = form.watch("objectKind");

  React.useEffect(() => {
    if (
      objectKind === "entity" &&
      !ENTITY_KINDS.includes(form.getValues("kind") as never)
    ) {
      form.setValue("kind", "human", { shouldValidate: true });
    }
  }, [form, objectKind]);

  const createProfile = useMutation({
    mutationFn: async ({
      profileValues,
      versionValues,
    }: {
      profileValues: ProfileFormValues;
      versionValues: ProfileVersionSubmitInput;
    }) => {
      const profile = await graphqlClient<ProfileCreateResponse>({
        query: CREATE_PROFILE_WITH_ID_MUTATION,
        variables: {
          input: removeEmptyValues({
            tenantId: profileValues.tenantId,
            objectKind: profileValues.objectKind,
            kind: profileValues.kind,
            key: profileValues.key,
            displayName: profileValues.displayName,
            description: profileValues.description,
            status: "active",
          }),
        },
      });
      await graphqlClient({
        query: CREATE_PROFILE_VERSION_MUTATION,
        variables: {
          profileId: profile.createProfile.id,
          input: {
            version: versionValues.version,
            jsonSchema: versionValues.jsonSchema,
            uiSchema: versionValues.uiSchema,
            status: versionValues.status,
          },
        },
      });
    },
    onSuccess: () => {
      toast.success("Profile and first version created");
      form.reset(defaultValues);
      onCreated();
    },
    onError: (error) => toast.error(error.message),
  });

  async function nextStep() {
    const valid = await form.trigger([
      "objectKind",
      "kind",
      "key",
      "displayName",
      "tenantId",
    ]);
    if (valid) setStep("version");
  }

  function submitVersion(versionValues: ProfileVersionSubmitInput) {
    createProfile.mutate({
      profileValues: form.getValues(),
      versionValues,
    });
  }

  return (
    <div className="mt-6 grid gap-4">
      <div className="flex gap-2">
        <Badge variant={step === "basics" ? "default" : "outline"}>
          Basics
        </Badge>
        <Badge variant={step === "version" ? "default" : "outline"}>
          Version
        </Badge>
      </div>

      {step === "basics" ? (
        <Form {...form}>
          <form
            className="grid gap-4"
            onSubmit={form.handleSubmit(() => setStep("version"))}
          >
            <ProfileBasicsFields form={form} objectKind={objectKind} />
            <div className="flex justify-end gap-2">
              <Button onClick={onCancel} type="button" variant="outline">
                Cancel
              </Button>
              <Button onClick={nextStep} type="button">
                Next
              </Button>
            </div>
          </form>
        </Form>
      ) : (
        <ProfileVersionForm
          isPending={createProfile.isPending}
          nextVersion={1}
          onCancel={() => setStep("basics")}
          onSubmit={submitVersion}
          submitLabel="Save profile"
        />
      )}
    </div>
  );
}

function ProfileBasicsFields({
  form,
  objectKind,
}: {
  form: UseFormReturn<ProfileFormValues>;
  objectKind: ProfileFormValues["objectKind"];
}) {
  return (
    <>
      <NativeSelectField
        form={form}
        label="Object kind"
        name="objectKind"
        options={PROFILE_OBJECT_KINDS}
        required
      />
      {objectKind === "entity" ? (
        <NativeSelectField
          form={form}
          label="Kind"
          name="kind"
          options={ENTITY_KINDS}
          required
        />
      ) : (
        <TextField form={form} label="Kind" name="kind" required />
      )}
      <TextField
        form={form}
        label="Profile key"
        name="key"
        placeholder="gateway"
        required
      />
      <TextField
        form={form}
        label="Display name"
        name="displayName"
        placeholder="Gateway"
        required
      />
      <TextField form={form} label="Description" name="description" />
      <TenantSelectField form={form} />
    </>
  );
}

function TextField({
  form,
  label,
  name,
  placeholder,
  required,
  type = "text",
}: {
  form: UseFormReturn<ProfileFormValues>;
  label: string;
  name: "kind" | "key" | "displayName" | "description";
  placeholder?: string;
  required?: boolean;
  type?: string;
}) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <RequiredFormLabel required={required}>{label}</RequiredFormLabel>
          <FormControl>
            <Input
              {...field}
              onChange={(event) =>
                field.onChange(
                  type === "number"
                    ? Number(event.target.value)
                    : event.target.value,
                )
              }
              placeholder={placeholder}
              type={type}
              value={field.value ?? ""}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function NativeSelectField({
  form,
  label,
  name,
  options,
  required,
}: {
  form: UseFormReturn<ProfileFormValues>;
  label: string;
  name: "objectKind" | "kind";
  options: readonly string[];
  required?: boolean;
}) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <RequiredFormLabel required={required}>{label}</RequiredFormLabel>
          <Select
            onValueChange={field.onChange}
            value={String(field.value ?? "")}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                {options.map((option) => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function TenantSelectField({
  form,
}: {
  form: UseFormReturn<ProfileFormValues>;
}) {
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;

  const { data } = useQuery({
    queryKey: ["profile-form-tenant-picker"],
    queryFn: ({ signal }) =>
      graphqlClient<TenantsPickerData>({ query: TENANTS_QUERY, signal }),
    staleTime: 60_000,
    enabled: !isTenantScoped,
  });
  const tenants = data?.tenants.items ?? [];

  React.useEffect(() => {
    if (isTenantScoped) form.setValue("tenantId", selection.id);
  }, [isTenantScoped, selection.id, form]);

  if (isTenantScoped) {
    return (
      <div className="grid gap-2">
        <Label>Tenant</Label>
        <div className="text-sm text-muted-foreground">{selection.name}</div>
      </div>
    );
  }

  return (
    <FormField
      control={form.control}
      name="tenantId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Tenant</FormLabel>
          <Select
            onValueChange={(value) =>
              field.onChange(value === GLOBAL_TENANT_VALUE ? "" : value)
            }
            value={field.value || GLOBAL_TENANT_VALUE}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                <SelectItem value={GLOBAL_TENANT_VALUE}>Global</SelectItem>
                {tenants.map((tenant) => (
                  <SelectItem key={tenant.id} value={tenant.id}>
                    {tenant.name}
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function removeEmptyValues(values: Record<string, unknown>) {
  return Object.fromEntries(
    Object.entries(values).filter(([, value]) => {
      if (value === undefined || value === null || value === "") return false;
      if (Array.isArray(value) && value.length === 0) return false;
      return true;
    }),
  );
}
