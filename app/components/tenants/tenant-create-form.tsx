"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import type { Tag } from "emblor";
import { type SetStateAction, useEffect, useState } from "react";
import { type UseFormReturn, useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
import { TagsFormInput } from "@/components/tags-form-input";
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
import { JsonEditor } from "@/components/ui/json-editor";
import { graphqlClient } from "@/lib/graphql/client";

const CREATE_TENANT_MUTATION = `
  mutation CreateTenant($input: CreateTenantInput!) {
    createTenant(input: $input) {
      id
      name
      route
      status
      tags
      attributes
      createdAt
      updatedAt
    }
  }
`;

const UPDATE_TENANT_MUTATION = `
  mutation UpdateTenant($id: ID!, $input: UpdateTenantInput!) {
    updateTenant(id: $id, input: $input) {
      id
      name
      route
      status
      tags
      attributes
      createdAt
      updatedAt
    }
  }
`;

const tenantFormSchema = z
  .object({
    name: z.string().trim().min(1, "Name is required."),
    route: z.string().trim(),
    tags: z.array(z.string().trim().min(1)).superRefine((tags, ctx) => {
      if (new Set(tags).size !== tags.length) {
        ctx.addIssue({
          code: "custom",
          message: "Tags must be unique.",
        });
      }
    }),
    attributes: z.string().trim(),
  })
  .superRefine((values, ctx) => {
    try {
      parseAttributesJson(values.attributes);
    } catch (error) {
      ctx.addIssue({
        code: "custom",
        path: ["attributes"],
        message:
          error instanceof Error
            ? error.message
            : "Attributes must be valid JSON.",
      });
    }
  });

type TenantFormValues = z.infer<typeof tenantFormSchema>;
export type TenantFormInitialValues = {
  id: string;
  name?: string | null;
  route?: string | null;
  tags?: string[] | null;
  attributes?: unknown;
};

const defaultValues: TenantFormValues = {
  name: "",
  route: "",
  tags: [],
  attributes: "{}",
};

export function TenantCreateForm({
  tenant,
  onCancel,
  onCreated,
}: {
  tenant?: TenantFormInitialValues;
  onCancel: () => void;
  onCreated: () => void;
}) {
  const mode = tenant ? "edit" : "create";
  const initialValues = tenantFormValuesFromTenant(tenant);
  const [tagItems, setTagItems] = useState<Tag[]>(() =>
    tagsFromStrings(initialValues.tags),
  );
  const form = useForm<TenantFormValues>({
    resolver: zodResolver(tenantFormSchema),
    defaultValues: initialValues,
  });

  useEffect(() => {
    form.setValue(
      "tags",
      tagItems.map((tag) => tag.text),
      { shouldValidate: true },
    );
  }, [form, tagItems]);

  const createTenant = useMutation({
    mutationFn: async (values: TenantFormValues) =>
      graphqlClient({
        query: CREATE_TENANT_MUTATION,
        variables: {
          input: removeEmptyValues({
            name: values.name,
            route: values.route,
            tags: values.tags,
            attributes: parseAttributesJson(values.attributes),
          }),
        },
      }),
    onSuccess: () => {
      toast.success("Tenant created");
      form.reset(defaultValues);
      setTagItems([]);
      onCreated();
    },
    onError: (error) => toast.error(error.message),
  });
  const updateTenant = useMutation({
    mutationFn: async (values: TenantFormValues) => {
      if (!tenant) throw new Error("Tenant is required for update.");
      return graphqlClient({
        query: UPDATE_TENANT_MUTATION,
        variables: {
          id: tenant.id,
          input: {
            name: values.name,
            route: values.route || null,
            tags: values.tags,
            attributes: parseAttributesJson(values.attributes),
          },
        },
      });
    },
    onSuccess: () => {
      toast.success("Tenant updated");
      onCreated();
    },
    onError: (error) => toast.error(error.message),
  });

  function submit(values: TenantFormValues) {
    if (mode === "edit") {
      updateTenant.mutate(values);
      return;
    }
    createTenant.mutate(values);
  }

  return (
    <Form {...form}>
      <form className="grid gap-4" onSubmit={form.handleSubmit(submit)}>
        <TextField form={form} label="Name" name="name" required />
        <TextField form={form} label="Route" name="route" />
        <TagsField
          form={form}
          setTagItems={setTenantTags}
          tagItems={tagItems}
        />
        <AttributesField form={form} />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={createTenant.isPending || updateTenant.isPending}
          >
            {mode === "edit" ? "Update tenant" : "Save tenant"}
          </Button>
        </div>
      </form>
    </Form>
  );

  function setTenantTags(action: SetStateAction<Tag[]>) {
    setTagItems(action);
  }
}

function tenantFormValuesFromTenant(
  tenant: TenantFormInitialValues | undefined,
): TenantFormValues {
  if (!tenant) return defaultValues;
  return {
    name: tenant.name ?? "",
    route: tenant.route ?? "",
    tags: tenant.tags ?? [],
    attributes: stringifyAttributes(tenant.attributes),
  };
}

function tagsFromStrings(tags: string[]) {
  return tags.map((tag) => ({ id: tag, text: tag }));
}

function stringifyAttributes(value: unknown) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "{}";
  return JSON.stringify(value, null, 2);
}

function TextField({
  form,
  label,
  name,
  required,
}: {
  form: UseFormReturn<TenantFormValues>;
  label: string;
  name: "name" | "route";
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

function TagsField({
  form,
  setTagItems,
  tagItems,
}: {
  form: UseFormReturn<TenantFormValues>;
  setTagItems: (action: SetStateAction<Tag[]>) => void;
  tagItems: Tag[];
}) {
  return (
    <FormField
      control={form.control}
      name="tags"
      render={({ field }) => (
        <TagsFormInput
          field={field}
          label="Tags"
          newTags={tagItems}
          placeholder="Type a tag and press Enter"
          setTags={setTagItems}
        />
      )}
    />
  );
}

function AttributesField({ form }: { form: UseFormReturn<TenantFormValues> }) {
  return (
    <FormField
      control={form.control}
      name="attributes"
      render={({ field }) => (
        <FormItem className="min-w-0">
          <FormLabel>Attributes JSON</FormLabel>
          <FormControl>
            <JsonEditor
              className="[&_.cm-editor]:min-h-48"
              onChange={field.onChange}
              value={field.value}
            />
          </FormControl>
          <FormMessage />
        </FormItem>
      )}
    />
  );
}

function parseAttributesJson(value: string) {
  if (!value.trim()) return {};
  const parsed = JSON.parse(value);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error("Attributes JSON must be a JSON object.");
  }
  return parsed as Record<string, unknown>;
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
