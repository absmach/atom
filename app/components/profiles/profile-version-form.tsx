"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { Plus } from "lucide-react";
import * as React from "react";
import { useFieldArray, useForm } from "react-hook-form";
import { z } from "zod";
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
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

export const PROFILE_VERSION_STATUSES = [
  "active",
  "deprecated",
  "disabled",
] as const;

const SCHEMA_FIELD_TYPES = [
  "string",
  "number",
  "integer",
  "boolean",
  "json",
] as const;
const ATTRIBUTE_NAME_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*$/;

export const schemaFieldSchema = z.object({
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

export const profileVersionFormSchema = z
  .object({
    version: z.number().int().min(1, "Version must be at least 1."),
    status: z.enum(PROFILE_VERSION_STATUSES),
    schemaFields: z.array(schemaFieldSchema),
  })
  .superRefine((value, ctx) => {
    const names = value.schemaFields.map((field) => field.name);
    if (new Set(names).size !== names.length) {
      ctx.addIssue({
        code: "custom",
        path: ["schemaFields"],
        message: "Attribute names must be unique.",
      });
    }
  });

export type ProfileVersionFormValues = z.infer<typeof profileVersionFormSchema>;
export type SchemaBuilderField =
  ProfileVersionFormValues["schemaFields"][number];

export type ProfileVersionSubmitInput = {
  version: number;
  status: string;
  jsonSchema: unknown;
  uiSchema: unknown;
};

export function ProfileVersionForm({
  nextVersion,
  isPending,
  submitLabel,
  onCancel,
  onSubmit,
}: {
  nextVersion: number;
  isPending: boolean;
  submitLabel: string;
  onCancel: () => void;
  onSubmit: (input: ProfileVersionSubmitInput) => void;
}) {
  const form = useForm<ProfileVersionFormValues>({
    resolver: zodResolver(profileVersionFormSchema),
    defaultValues: profileVersionFormDefaultValues(nextVersion),
  });
  const { fields, append, remove } = useFieldArray({
    control: form.control,
    name: "schemaFields",
  });
  const schemaFields = form.watch("schemaFields");
  const generated = React.useMemo(
    () => buildProfileSchemas(schemaFields),
    [schemaFields],
  );

  React.useEffect(() => {
    form.reset(profileVersionFormDefaultValues(nextVersion));
  }, [form, nextVersion]);

  function submit(values: ProfileVersionFormValues) {
    const schemas = buildProfileSchemas(values.schemaFields);
    onSubmit({
      version: values.version,
      status: values.status,
      jsonSchema: schemas.jsonSchema,
      uiSchema: schemas.uiSchema,
    });
  }

  return (
    <Form {...form}>
      <form
        className="grid gap-4 rounded-lg border bg-muted/30 p-4"
        onSubmit={form.handleSubmit(submit)}
      >
        <div className="text-sm font-medium">New version</div>

        <div className="grid gap-3 sm:grid-cols-2">
          <TextField
            form={form}
            label="Version"
            name="version"
            required
            type="number"
          />
          <NativeSelectField
            form={form}
            label="Status"
            name="status"
            options={PROFILE_VERSION_STATUSES}
            required
          />
        </div>

        <div className="grid gap-3 rounded-lg border bg-background p-3">
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

        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={isPending} type="submit">
            {submitLabel}
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
  placeholder,
  required,
  type = "text",
}: {
  form: ReturnType<typeof useForm<ProfileVersionFormValues>>;
  label: string;
  name:
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
  form: ReturnType<typeof useForm<ProfileVersionFormValues>>;
  label: string;
  name: "status" | `schemaFields.${number}.type`;
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

function SchemaBuilderRow({
  form,
  index,
  onRemove,
  position,
}: {
  form: ReturnType<typeof useForm<ProfileVersionFormValues>>;
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

function profileVersionFormDefaultValues(
  nextVersion: number,
): ProfileVersionFormValues {
  return {
    version: nextVersion,
    status: "active",
    schemaFields: [],
  };
}

export function emptySchemaBuilderField(): SchemaBuilderField {
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

export function buildProfileSchemas(fields: SchemaBuilderField[]) {
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
