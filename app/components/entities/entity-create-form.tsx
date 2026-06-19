"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { type UseFormReturn, useForm, useWatch } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Form,
  FormControl,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { JsonEditor } from "@/components/ui/json-editor";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { graphqlClient } from "@/lib/graphql/client";
import {
  fieldsFromSchema,
  type JsonSchema,
  type SchemaField,
  type UiSchema,
} from "@/lib/profiles/schema-form";
import { GLOBAL_TENANT } from "@/lib/tenant/context";

const TENANTS_QUERY = `
  query EntityFormTenants {
    tenants(limit: 100, offset: 0) {
      items { id name }
    }
  }
`;

const ENTITY_PROFILES_QUERY = `
  query EntityFormProfiles {
    profiles(objectKind: "entity", status: "active", limit: 100, offset: 0) {
      items { id displayName kind key tenantId }
    }
  }
`;

const PROFILE_VERSIONS_QUERY = `
  query EntityFormProfileVersions($profileId: ID!) {
    profileVersions(profileId: $profileId) {
      id
      version
      status
      jsonSchema
      uiSchema
    }
  }
`;

const CREATE_ENTITY_MUTATION = `
  mutation CreateEntity($input: CreateEntityInput!) {
    createEntity(input: $input) {
      id
      kind
      profileId
      profileVersionId
      name
      alias
      tenantId
      status
      createdAt
      updatedAt
    }
  }
`;

const UPDATE_ENTITY_MUTATION = `
  mutation UpdateEntity($id: ID!, $input: UpdateEntityInput!) {
    updateEntity(id: $id, input: $input) {
      id
      kind
      profileId
      profileVersionId
      name
      alias
      tenantId
      status
      updatedAt
    }
  }
`;

const ENTITY_KINDS = [
  "human",
  "device",
  "service",
  "workload",
  "application",
] as const;
const EMPTY_SELECT_VALUE = "__empty__";
const GLOBAL_TENANT_VALUE = "__global__";

type TenantOption = { id: string; name: string };
type TenantsData = { tenants: { items: TenantOption[] } };
type EntityProfileOption = {
  id: string;
  displayName: string;
  kind: (typeof ENTITY_KINDS)[number];
  key: string;
  tenantId: string | null;
};
type EntityProfilesData = {
  profiles: { items: EntityProfileOption[] };
};
type ProfileVersionOption = {
  id: string;
  version: number;
  status: string;
  jsonSchema: JsonSchema;
  uiSchema: UiSchema;
};
type ProfileVersionsData = {
  profileVersions: ProfileVersionOption[];
};

const entityFormSchema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  alias: z.string().trim(),
  kind: z.enum(ENTITY_KINDS),
  tenantId: z.string().trim(),
  profileId: z.string().trim(),
  profileVersionId: z.string().trim(),
  attributes: z.string().trim(),
  schemaAttributes: z.record(z.string(), z.unknown()),
});

function buildEntityFormSchema(
  fields: SchemaField[],
  selectedVersion: ProfileVersionOption | undefined,
) {
  return entityFormSchema.superRefine((values, ctx) => {
    let attributes: Record<string, unknown>;
    try {
      attributes = buildEntityAttributes(values, fields);
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        path: ["attributes"],
        message:
          error instanceof Error
            ? error.message
            : "Attributes must be valid JSON.",
      });
      return;
    }

    for (const field of fields) {
      const value = values.schemaAttributes[field.name];
      if (field.required && isEmptyAttributeValue(value)) {
        ctx.addIssue({
          code: "custom",
          path: ["schemaAttributes", field.name],
          message: `${field.label} is required.`,
        });
        continue;
      }
      const fieldError = validateSchemaFieldValue(field, value);
      if (fieldError) {
        ctx.addIssue({
          code: "custom",
          path: ["schemaAttributes", field.name],
          message: fieldError,
        });
      }
    }

    if (selectedVersion) {
      const schemaError = validateJsonSchema(
        selectedVersion.jsonSchema,
        attributes,
      );
      if (schemaError) {
        ctx.addIssue({
          code: "custom",
          path: ["attributes"],
          message: schemaError,
        });
      }
    }
  });
}

type EntityFormValues = z.infer<typeof entityFormSchema>;

export type EntityFormInitialValues = {
  id: string;
  name: string;
  alias: string;
  kind: (typeof ENTITY_KINDS)[number];
  tenantId: string;
  profileId: string;
  profileVersionId: string;
  attributes: Record<string, unknown>;
};

const defaultValues: EntityFormValues = {
  name: "",
  alias: "",
  kind: "human",
  tenantId: "",
  profileId: "",
  profileVersionId: "",
  attributes: "{}",
  schemaAttributes: {},
};

export function EntityCreateForm({
  entity,
  onCancel,
  onCreated,
}: {
  entity?: EntityFormInitialValues;
  onCancel: () => void;
  onCreated: () => void;
}) {
  const schemaFieldsRef = React.useRef<SchemaField[]>([]);
  const selectedVersionRef = React.useRef<ProfileVersionOption | undefined>(
    undefined,
  );
  const form = useForm<EntityFormValues>({
    resolver: (values, context, options) =>
      zodResolver(
        buildEntityFormSchema(
          schemaFieldsRef.current,
          selectedVersionRef.current,
        ),
      )(values, context, options),
    defaultValues: entity
      ? {
          name: entity.name,
          alias: entity.alias,
          kind: entity.kind,
          tenantId: entity.tenantId,
          profileId: entity.profileId,
          profileVersionId: entity.profileVersionId,
          attributes: Object.keys(entity.attributes).length
            ? JSON.stringify(entity.attributes, null, 2)
            : "{}",
          schemaAttributes: {},
        }
      : defaultValues,
  });
  const profileId = useWatch({ control: form.control, name: "profileId" });
  const profileVersionId = useWatch({
    control: form.control,
    name: "profileVersionId",
  });

  const { data: profilesData } = useQuery({
    queryKey: ["entity-create-profiles"],
    queryFn: ({ signal }) =>
      graphqlClient<EntityProfilesData>({
        query: ENTITY_PROFILES_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });
  const { data: versionsData, isFetching: versionsFetching } = useQuery({
    enabled: Boolean(profileId),
    queryKey: ["entity-create-profile-versions", profileId],
    queryFn: ({ signal }) =>
      graphqlClient<ProfileVersionsData>({
        query: PROFILE_VERSIONS_QUERY,
        variables: { profileId },
        signal,
      }),
    staleTime: 60_000,
  });

  const profiles = profilesData?.profiles.items ?? [];
  const versions = React.useMemo(
    () => versionsData?.profileVersions ?? [],
    [versionsData],
  );
  const selectedProfile = profiles.find((profile) => profile.id === profileId);
  const selectedVersion = versions.find(
    (version) => version.id === profileVersionId,
  );
  const schemaFields = React.useMemo(
    () =>
      selectedVersion
        ? fieldsFromSchema(selectedVersion.jsonSchema, selectedVersion.uiSchema)
        : [],
    [selectedVersion],
  );

  React.useEffect(() => {
    schemaFieldsRef.current = schemaFields;
    selectedVersionRef.current = selectedVersion;
  }, [schemaFields, selectedVersion]);

  React.useEffect(() => {
    if (!selectedProfile) return;
    form.setValue("kind", selectedProfile.kind, { shouldValidate: true });
  }, [form, selectedProfile]);

  React.useEffect(() => {
    if (!profileId || versions.length === 0) {
      form.setValue("profileVersionId", "");
      return;
    }
    if (versions.some((version) => version.id === profileVersionId)) {
      return;
    }
    const activeVersion = versions.find(
      (version) => version.status === "active",
    );
    form.setValue("profileVersionId", (activeVersion ?? versions[0]).id);
  }, [form, profileId, profileVersionId, versions]);

  React.useEffect(() => {
    form.setValue(
      "schemaAttributes",
      entity
        ? seedAttributeValues(schemaFields, entity.attributes)
        : defaultAttributeValues(schemaFields),
      { shouldValidate: true },
    );
  }, [form, schemaFields, entity]);

  const saveEntity = useMutation({
    mutationFn: async (values: EntityFormValues) => {
      const attributes = buildEntityAttributes(values, schemaFields);
      if (entity) {
        await graphqlClient({
          query: UPDATE_ENTITY_MUTATION,
          variables: {
            id: entity.id,
            input: {
              ...removeEmptyValues({
                name: values.name,
                kind: values.kind,
                tenantId: values.tenantId,
                profileId: values.profileId,
                profileVersionId: values.profileVersionId,
                attributes,
              }),
              alias: values.alias || null,
            },
          },
        });
      } else {
        await graphqlClient({
          query: CREATE_ENTITY_MUTATION,
          variables: {
            input: removeEmptyValues({
              name: values.name,
              alias: values.alias,
              kind: values.kind,
              tenantId: values.tenantId,
              profileId: values.profileId,
              profileVersionId: values.profileVersionId,
              attributes,
            }),
          },
        });
      }
    },
    onSuccess: () => {
      toast.success(entity ? "Entity updated" : "Entity created");
      if (!entity) form.reset(defaultValues);
      onCreated();
    },
    onError: (error) => toast.error(error.message),
  });

  function submit(values: EntityFormValues) {
    saveEntity.mutate(values);
  }

  return (
    <Form {...form}>
      <form className="grid gap-4" onSubmit={form.handleSubmit(submit)}>
        <TextField form={form} label="Name" name="name" required />
        <TextField form={form} label="Alias" name="alias" />
        <KindSelectField form={form} disabled={Boolean(profileId)} />
        <TenantSelectField form={form} />
        <ProfileSelectField form={form} profiles={profiles} />
        <ProfileVersionSelectField
          form={form}
          profileId={profileId}
          versions={versions}
          versionsFetching={versionsFetching}
        />
        {schemaFields.length ? (
          <div className="grid gap-4 rounded-lg border p-3">
            {schemaFields.map((field) => (
              <SchemaAttributeField
                field={field}
                form={form}
                key={field.name}
              />
            ))}
          </div>
        ) : null}
        <JsonAttributesField form={form} />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button type="submit" disabled={saveEntity.isPending}>
            {entity ? "Save changes" : "Save entity"}
          </Button>
        </div>
      </form>
    </Form>
  );
}

function TextField({
  form,
  label,
  name,
  required,
}: {
  form: UseFormReturn<EntityFormValues>;
  label: string;
  name: "name" | "alias";
  required?: boolean;
}) {
  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field }) => (
        <FormItem>
          <RequiredFormLabel required={required}>{label}</RequiredFormLabel>
          <FormControl>
            <Input {...field} />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function KindSelectField({
  disabled,
  form,
}: {
  disabled?: boolean;
  form: UseFormReturn<EntityFormValues>;
}) {
  return (
    <FormField
      control={form.control}
      name="kind"
      render={({ field }) => (
        <FormItem>
          <RequiredFormLabel required>Kind</RequiredFormLabel>
          <Select
            disabled={disabled}
            onValueChange={field.onChange}
            value={field.value}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                {ENTITY_KINDS.map((kind) => (
                  <SelectItem key={kind} value={kind}>
                    {kind}
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
  form: UseFormReturn<EntityFormValues>;
}) {
  const { selection } = useTenant();
  const isTenantScoped = selection.id !== "" && selection.id !== GLOBAL_TENANT;

  const { data } = useQuery({
    queryKey: ["entity-create-tenants"],
    queryFn: ({ signal }) =>
      graphqlClient<TenantsData>({ query: TENANTS_QUERY, signal }),
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

function ProfileSelectField({
  form,
  profiles,
}: {
  form: UseFormReturn<EntityFormValues>;
  profiles: EntityProfileOption[];
}) {
  return (
    <FormField
      control={form.control}
      name="profileId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Profile</FormLabel>
          <Select
            onValueChange={(value) => {
              field.onChange(value === EMPTY_SELECT_VALUE ? "" : value);
              form.setValue("profileVersionId", "");
              form.setValue("schemaAttributes", {});
            }}
            value={field.value || EMPTY_SELECT_VALUE}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue placeholder="Select profile" />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                <SelectItem value={EMPTY_SELECT_VALUE}>No profile</SelectItem>
                {profiles.map((profile) => (
                  <SelectItem key={profile.id} value={profile.id}>
                    {profile.displayName} ({profile.kind})
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

function ProfileVersionSelectField({
  form,
  profileId,
  versions,
  versionsFetching,
}: {
  form: UseFormReturn<EntityFormValues>;
  profileId: string;
  versions: ProfileVersionOption[];
  versionsFetching: boolean;
}) {
  return (
    <FormField
      control={form.control}
      name="profileVersionId"
      render={({ field }) => (
        <FormItem>
          <FormLabel>Profile version</FormLabel>
          <Select
            disabled={!profileId || versionsFetching || versions.length === 0}
            onValueChange={(value) =>
              field.onChange(value === EMPTY_SELECT_VALUE ? "" : value)
            }
            value={field.value || EMPTY_SELECT_VALUE}
          >
            <FormControl>
              <SelectTrigger className="w-full">
                <SelectValue
                  placeholder={
                    profileId ? "Use active version" : "Select a profile first"
                  }
                />
              </SelectTrigger>
            </FormControl>
            <SelectContent>
              <SelectGroup>
                {versions.map((version) => (
                  <SelectItem key={version.id} value={version.id}>
                    v{version.version} ({version.status})
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

function JsonAttributesField({
  form,
}: {
  form: UseFormReturn<EntityFormValues>;
}) {
  return (
    <FormField
      control={form.control}
      name="attributes"
      render={({ field }) => (
        <FormItem className="min-w-0">
          <FormLabel>Attributes JSON</FormLabel>
          <FormControl>
            <JsonEditor
              value={field.value}
              onChange={field.onChange}
              className="[&_.cm-editor]:min-h-48"
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function SchemaAttributeField({
  field,
  form,
}: {
  field: SchemaField;
  form: UseFormReturn<EntityFormValues>;
}) {
  const name = `schemaAttributes.${field.name}` as never;
  const id = `schema-attribute-${field.name}`;

  return (
    <FormField
      control={form.control}
      name={name}
      render={({ field: formField }) => {
        const value = formField.value;
        const stringValue =
          value === undefined || value === null ? "" : String(value);

        return (
          <FormItem>
            <RequiredFormLabel required={field.required}>
              {field.label}
            </RequiredFormLabel>
            {field.type === "text" ? (
              <FormControl>
                <Input
                  id={id}
                  onChange={formField.onChange}
                  placeholder={field.placeholder ?? field.description}
                  value={stringValue}
                />
              </FormControl>
            ) : null}
            {field.type === "number" ? (
              <FormControl>
                <Input
                  id={id}
                  onChange={(event) => formField.onChange(event.target.value)}
                  placeholder={field.placeholder ?? field.description}
                  type="number"
                  value={stringValue}
                />
              </FormControl>
            ) : null}
            {field.type === "checkbox" ? (
              <FormLabel className="flex min-h-9 items-center gap-2 text-sm">
                <FormControl>
                  <Checkbox
                    checked={Boolean(value)}
                    id={id}
                    onCheckedChange={(checked) =>
                      formField.onChange(checked === true)
                    }
                  />
                </FormControl>
                {field.description ?? "Boolean flag"}
              </FormLabel>
            ) : null}
            {field.type === "select" ? (
              <Select
                onValueChange={(next) =>
                  formField.onChange(next === EMPTY_SELECT_VALUE ? "" : next)
                }
                value={stringValue || EMPTY_SELECT_VALUE}
              >
                <FormControl>
                  <SelectTrigger className="w-full" id={id}>
                    <SelectValue placeholder={field.placeholder ?? "Choose"} />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectGroup>
                    <SelectItem value={EMPTY_SELECT_VALUE}>No value</SelectItem>
                    {field.options?.map((option) => (
                      <SelectItem key={option} value={option}>
                        {option}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
            ) : null}
            {field.type === "textarea" || field.type === "json" ? (
              <FormControl>
                <Textarea
                  className="font-mono text-xs"
                  id={id}
                  onChange={formField.onChange}
                  placeholder={field.placeholder ?? field.description}
                  value={stringValue}
                />
              </FormControl>
            ) : null}
            {field.description && field.type !== "checkbox" ? (
              <p className="text-xs text-muted-foreground">
                {field.description}
              </p>
            ) : null}
            <FormMessage />
          </FormItem>
        );
      }}
    />
  );
}

function defaultAttributeValues(fields: SchemaField[]) {
  return Object.fromEntries(
    fields.map((field) => [
      field.name,
      field.defaultValue ?? (field.type === "checkbox" ? false : ""),
    ]),
  );
}

function seedAttributeValues(
  fields: SchemaField[],
  existing: Record<string, unknown>,
) {
  return Object.fromEntries(
    fields.map((field) => {
      const stored = existing[field.name];
      if (stored === undefined || stored === null) {
        return [
          field.name,
          field.defaultValue ?? (field.type === "checkbox" ? false : ""),
        ];
      }
      if (field.type === "json" && typeof stored === "object") {
        return [field.name, JSON.stringify(stored, null, 2)];
      }
      return [field.name, stored];
    }),
  );
}

function collectSchemaAttributes(
  fields: SchemaField[],
  values: Record<string, unknown>,
) {
  return Object.fromEntries(
    fields
      .map(
        (field) =>
          [
            field.name,
            normalizeAttributeValue(field, values[field.name]),
          ] as const,
      )
      .filter(([, value]) => value !== undefined),
  );
}

function buildEntityAttributes(
  values: EntityFormValues,
  fields: SchemaField[],
) {
  return {
    ...parseAttributesJson(values.attributes),
    ...collectSchemaAttributes(fields, values.schemaAttributes),
  };
}

function normalizeAttributeValue(field: SchemaField, value: unknown) {
  if (field.type === "checkbox") return Boolean(value);
  if (value === undefined || value === null || value === "") return undefined;
  if (field.type === "number") {
    const parsed = Number(value);
    return Number.isNaN(parsed) ? undefined : parsed;
  }
  if (field.type === "json" && typeof value === "string") {
    try {
      return JSON.parse(value);
    } catch {
      return value;
    }
  }
  return value;
}

function isEmptyAttributeValue(value: unknown) {
  if (typeof value === "boolean") return false;
  return value === undefined || value === null || value === "";
}

function validateSchemaFieldValue(field: SchemaField, value: unknown) {
  if (isEmptyAttributeValue(value)) return null;
  switch (field.type) {
    case "number":
      return Number.isNaN(Number(value))
        ? `${field.label} must be a number.`
        : null;
    case "json":
      if (typeof value !== "string") return null;
      try {
        JSON.parse(value);
        return null;
      } catch {
        return `${field.label} must be valid JSON.`;
      }
    case "select":
      return field.options?.length && !field.options.includes(String(value))
        ? `${field.label} must be one of: ${field.options.join(", ")}.`
        : null;
    case "checkbox":
      return typeof value === "boolean"
        ? null
        : `${field.label} must be true or false.`;
    case "text":
    case "textarea":
      return null;
  }
}

function parseAttributesJson(value: string) {
  if (!value.trim()) return {};
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Attributes JSON must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
}

function validateJsonSchema(
  schema: JsonSchema,
  value: unknown,
  path = "attributes",
): string | null {
  const typeError = validateJsonSchemaType(schema, value, path);
  if (typeError) return typeError;

  if (schema.enum && !schema.enum.some((option) => Object.is(option, value))) {
    return `${path} must be one of: ${schema.enum.join(", ")}.`;
  }

  if (
    schema.properties &&
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    const objectValue = value as Record<string, unknown>;
    const missingRequired = (schema.required ?? []).find((name) =>
      isEmptyAttributeValue(objectValue[name]),
    );
    if (missingRequired) {
      return `${path}.${missingRequired} is required.`;
    }

    for (const [name, propertySchema] of Object.entries(schema.properties)) {
      if (objectValue[name] === undefined || objectValue[name] === null) {
        continue;
      }
      const propertyError = validateJsonSchema(
        propertySchema,
        objectValue[name],
        `${path}.${name}`,
      );
      if (propertyError) return propertyError;
    }
  }

  return null;
}

function validateJsonSchemaType(
  schema: JsonSchema,
  value: unknown,
  path: string,
) {
  switch (schema.type) {
    case undefined:
      return null;
    case "object":
      return value && typeof value === "object" && !Array.isArray(value)
        ? null
        : `${path} must be a JSON object.`;
    case "string":
      return typeof value === "string" ? null : `${path} must be a string.`;
    case "number":
      return typeof value === "number" && !Number.isNaN(value)
        ? null
        : `${path} must be a number.`;
    case "integer":
      return typeof value === "number" && Number.isInteger(value)
        ? null
        : `${path} must be an integer.`;
    case "boolean":
      return typeof value === "boolean" ? null : `${path} must be a boolean.`;
    case "array":
      return Array.isArray(value) ? null : `${path} must be an array.`;
    default:
      return null;
  }
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
