"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import * as React from "react";
import {
  type UseFormReturn,
  useFieldArray,
  useForm,
  useWatch,
} from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { useTenant } from "@/components/app-shell/tenant-provider";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { Badge } from "@/components/ui/badge";
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
const SCHEMA_FIELD_TYPES = [
  "string",
  "number",
  "integer",
  "boolean",
  "json",
] as const;
const ATTRIBUTE_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;
const GLOBAL_TENANT_VALUE = "__global__";

type TenantOption = { id: string; name: string };
type TenantsPickerData = { tenants: { items: TenantOption[] } };
type ProfileCreateResponse = {
  createProfile: { id: string };
};

const schemaFieldSchema = z.object({
  name: z
    .string()
    .trim()
    .min(1, "Attribute name is required.")
    .regex(
      ATTRIBUTE_NAME_PATTERN,
      "Use letters, numbers, and underscores only. The first character cannot be a number.",
    ),
  label: z.string().trim(),
  type: z.enum(SCHEMA_FIELD_TYPES),
  required: z.boolean(),
  options: z.string().trim(),
  description: z.string().trim(),
  placeholder: z.string().trim(),
});

const profileFormSchema = z
  .object({
    objectKind: z.enum(PROFILE_OBJECT_KINDS),
    kind: z.string().trim().min(1, "Kind is required."),
    key: z.string().trim().min(1, "Profile key is required."),
    displayName: z.string().trim().min(1, "Display name is required."),
    description: z.string().trim(),
    tenantId: z.string().trim(),
    version: z.number().int().min(1, "Version must be at least 1."),
    schemaFields: z.array(schemaFieldSchema),
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

    const names = value.schemaFields.map((field) => field.name);
    if (new Set(names).size !== names.length) {
      ctx.addIssue({
        code: "custom",
        path: ["schemaFields"],
        message: "Attribute names must be unique.",
      });
    }
  });

type ProfileFormValues = z.infer<typeof profileFormSchema>;
type SchemaBuilderField = ProfileFormValues["schemaFields"][number];

const defaultValues: ProfileFormValues = {
  objectKind: "entity",
  kind: "human",
  key: "",
  displayName: "",
  description: "",
  tenantId: "",
  version: 1,
  schemaFields: [],
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
  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: "schemaFields",
  });
  const objectKind = form.watch("objectKind");
  const schemaFields =
    useWatch({
      control: form.control,
      name: "schemaFields",
    }) ?? [];
  const generated = React.useMemo(
    () => buildProfileSchemas(schemaFields),
    [schemaFields],
  );

  React.useEffect(() => {
    if (
      objectKind === "entity" &&
      !ENTITY_KINDS.includes(form.getValues("kind") as never)
    ) {
      form.setValue("kind", "human", { shouldValidate: true });
    }
  }, [form, objectKind]);

  const createProfile = useMutation({
    mutationFn: async (values: ProfileFormValues) => {
      const schemas = buildProfileSchemas(values.schemaFields);
      const profile = await graphqlClient<ProfileCreateResponse>({
        query: CREATE_PROFILE_WITH_ID_MUTATION,
        variables: {
          input: removeEmptyValues({
            tenantId: values.tenantId,
            objectKind: values.objectKind,
            kind: values.kind,
            key: values.key,
            displayName: values.displayName,
            description: values.description,
            status: "active",
          }),
        },
      });
      await graphqlClient({
        query: CREATE_PROFILE_VERSION_MUTATION,
        variables: {
          profileId: profile.createProfile.id,
          input: {
            version: values.version,
            jsonSchema: schemas.jsonSchema,
            uiSchema: schemas.uiSchema,
            status: "active",
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

  function submit(values: ProfileFormValues) {
    createProfile.mutate(values);
  }

  return (
    <Form {...form}>
      <form className="mt-6 grid gap-4" onSubmit={form.handleSubmit(submit)}>
        <div className="flex gap-2">
          <Badge variant={step === "basics" ? "default" : "outline"}>
            Basics
          </Badge>
          <Badge variant={step === "version" ? "default" : "outline"}>
            Version
          </Badge>
        </div>

        {step === "basics" ? (
          <>
            <ProfileBasicsFields form={form} objectKind={objectKind} />
            <div className="flex justify-end gap-2">
              <Button onClick={onCancel} type="button" variant="outline">
                Cancel
              </Button>
              <Button onClick={nextStep} type="button">
                Next
              </Button>
            </div>
          </>
        ) : (
          <>
            <ProfileVersionFields form={form} />
            <div className="grid gap-3 rounded-lg border p-3">
              <div className="grid gap-1">
                <h3 className="text-sm font-medium">Schema fields</h3>
                <p className="text-xs text-muted-foreground">
                  Schema fields are optional. Add fields only when they should
                  become generated entity attribute inputs.
                </p>
              </div>
              {fields.map((field, index) => (
                <SchemaBuilderRow
                  form={form}
                  index={index}
                  key={field.id}
                  onRemove={() => remove(index)}
                  position={index + 1}
                />
              ))}
              <Button
                onClick={() => append(emptySchemaBuilderField())}
                type="button"
                variant="outline"
              >
                <Plus data-icon="inline-start" />
                Add field
              </Button>
            </div>

            <div className="grid min-w-0 gap-4 lg:grid-cols-2">
              <GeneratedSchemaPreview
                label="JSON schema"
                value={generated.jsonSchema}
              />
              <GeneratedSchemaPreview
                label="UI schema"
                value={generated.uiSchema}
              />
            </div>

            <div className="flex justify-between gap-2">
              <Button
                onClick={() => setStep("basics")}
                type="button"
                variant="outline"
              >
                Back
              </Button>
              <Button type="submit" disabled={createProfile.isPending}>
                Save profile
              </Button>
            </div>
          </>
        )}
      </form>
    </Form>
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

function ProfileVersionFields({
  form,
}: {
  form: UseFormReturn<ProfileFormValues>;
}) {
  return (
    <TextField
      form={form}
      label="Version"
      name="version"
      required
      type="number"
    />
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
  name:
    | "kind"
    | "key"
    | "displayName"
    | "description"
    | "version"
    | `schemaFields.${number}.name`
    | `schemaFields.${number}.label`
    | `schemaFields.${number}.options`
    | `schemaFields.${number}.description`
    | `schemaFields.${number}.placeholder`;
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
  name: "objectKind" | "kind" | `schemaFields.${number}.type`;
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

function SchemaBuilderRow({
  form,
  index,
  onRemove,
  position,
}: {
  form: UseFormReturn<ProfileFormValues>;
  index: number;
  onRemove: () => void;
  position: number;
}) {
  const type = form.watch(`schemaFields.${index}.type`);

  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="flex items-center justify-between gap-2">
        <Badge variant="outline">Field {position}</Badge>
        <Button onClick={onRemove} size="sm" type="button" variant="ghost">
          Remove
        </Button>
      </div>
      <div className="grid gap-3 sm:grid-cols-2">
        <TextField
          form={form}
          label="Attribute name"
          name={`schemaFields.${index}.name`}
          placeholder="serial_no"
          required
        />
        <TextField
          form={form}
          label="Label"
          name={`schemaFields.${index}.label`}
          placeholder="Serial number"
        />
        <NativeSelectField
          form={form}
          label="Type"
          name={`schemaFields.${index}.type`}
          options={SCHEMA_FIELD_TYPES}
          required
        />
        <TextField
          form={form}
          label="Placeholder"
          name={`schemaFields.${index}.placeholder`}
        />
      </div>
      <TextField
        form={form}
        label="Help text"
        name={`schemaFields.${index}.description`}
      />
      {type === "string" ? (
        <TextField
          form={form}
          label="Options"
          name={`schemaFields.${index}.options`}
          placeholder="prod, stage, dev"
        />
      ) : null}
      <FormField
        control={form.control}
        name={`schemaFields.${index}.required`}
        render={({ field }) => (
          <FormItem>
            <FormLabel className="flex min-h-9 items-center gap-2 text-sm">
              <FormControl>
                <Checkbox
                  checked={Boolean(field.value)}
                  onCheckedChange={(checked) =>
                    field.onChange(checked === true)
                  }
                />
              </FormControl>
              Required field
            </FormLabel>
            <FormMessage />
          </FormItem>
        )}
      />
    </div>
  );
}

function GeneratedSchemaPreview({
  label,
  value,
}: {
  label: string;
  value: unknown;
}) {
  const code = React.useMemo(() => JSON.stringify(value, null, 2), [value]);

  return (
    <div className="grid min-w-0 max-w-full gap-2">
      <div className="text-sm font-medium">{label}</div>
      <JsonEditor value={code} className="[&_.cm-editor]:min-h-48" />
    </div>
  );
}

function emptySchemaBuilderField(): SchemaBuilderField {
  return {
    name: "",
    label: "",
    type: "string",
    required: false,
    options: "",
    description: "",
    placeholder: "",
  };
}

function buildProfileSchemas(fields: SchemaBuilderField[]) {
  if (fields.length === 0) {
    return { jsonSchema: {}, uiSchema: {} };
  }

  const properties = Object.fromEntries(
    fields.map((field) => [
      field.name.trim(),
      removeEmptyValues({
        type: schemaPropertyType(field.type),
        title: field.label.trim() || titleizeLocal(field.name),
        description: field.description,
        enum:
          field.type === "string"
            ? field.options
                .split(",")
                .map((option) => option.trim())
                .filter(Boolean)
            : undefined,
      }),
    ]),
  );
  const required = fields
    .filter((field) => field.required)
    .map((field) => field.name.trim());
  const jsonSchema = removeEmptyValues({
    type: "object",
    required: required.length ? required : undefined,
    properties,
  });
  const uiSchema = removeEmptyValues({
    "ui:order": fields.map((field) => field.name.trim()),
    ...Object.fromEntries(
      fields.map((field) => [
        field.name.trim(),
        removeEmptyValues({
          "ui:title": field.label,
          "ui:description": field.description,
          "ui:placeholder": field.placeholder,
          "ui:widget": field.type === "json" ? "textarea" : undefined,
        }),
      ]),
    ),
  });

  return { jsonSchema, uiSchema };
}

function schemaPropertyType(type: SchemaBuilderField["type"]) {
  switch (type) {
    case "string":
      return "string";
    case "number":
      return "number";
    case "integer":
      return "integer";
    case "boolean":
      return "boolean";
    case "json":
      return "object";
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

function titleizeLocal(value: string) {
  return value
    .replaceAll("_", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
