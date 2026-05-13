"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { RequiredFormLabel } from "@/components/forms/required-form-label";
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
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { graphqlClient } from "@/lib/graphql/client";

// ─── GraphQL ─────────────────────────────────────────────────────────────────

const CREATE_CAPABILITY_MUTATION = `
  mutation CreateCapability($input: CreateCapabilityInput!) {
    createCapability(input: $input) { id name resourceKind description createdAt updatedAt }
  }
`;

const UPDATE_CAPABILITY_MUTATION = `
  mutation UpdateCapability($id: ID!, $input: UpdateCapabilityInput!) {
    updateCapability(id: $id, input: $input) { id name resourceKind description createdAt updatedAt }
  }
`;

const RESOURCE_KINDS_QUERY = `
  query CapabilityFormResourceKinds {
    resources(limit: 200, offset: 0) { items { kind } }
  }
`;

const KIND_NONE = "__none__";

// ─── Types ────────────────────────────────────────────────────────────────────

export type CapabilityFormInitialValues = {
  id: string;
  name: string;
  resourceKind: string;
  description: string;
};

// ─── Schema ──────────────────────────────────────────────────────────────────

const schema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  resourceKind: z.string().trim(),
  description: z.string().trim(),
});

type FormValues = z.infer<typeof schema>;

// ─── Entry point ─────────────────────────────────────────────────────────────

export function CapabilityCreateForm({
  capability,
  onCancel,
  onSaved,
}: {
  capability?: CapabilityFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const isEdit = Boolean(capability);

  const resourceKindsQuery = useQuery({
    queryKey: ["capability-form-resource-kinds"],
    queryFn: ({ signal }) =>
      graphqlClient<{ resources: { items: { kind: string }[] } }>({
        query: RESOURCE_KINDS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const fetchedKinds = [
    ...new Set(
      (resourceKindsQuery.data?.resources.items ?? [])
        .map((r) => r.kind)
        .filter(Boolean),
    ),
  ].sort();

  // In edit mode, ensure the saved value appears even if no matching resource exists.
  const currentKind = capability?.resourceKind ?? "";
  const knownKinds =
    currentKind && !fetchedKinds.includes(currentKind)
      ? [...fetchedKinds, currentKind].sort()
      : fetchedKinds;

  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: capability?.name ?? "",
      resourceKind: capability?.resourceKind ?? "",
      description: capability?.description ?? "",
    },
  });

  const save = useMutation({
    mutationFn: (values: FormValues) =>
      isEdit
        ? graphqlClient({
            query: UPDATE_CAPABILITY_MUTATION,
            variables: {
              id: capability!.id,
              input: {
                name: values.name,
                resourceKind: values.resourceKind || undefined,
                description: values.description || undefined,
              },
            },
          })
        : graphqlClient({
            query: CREATE_CAPABILITY_MUTATION,
            variables: {
              input: {
                name: values.name,
                resourceKind: values.resourceKind || undefined,
                description: values.description || undefined,
              },
            },
          }),
    onSuccess: () => {
      toast.success(isEdit ? "Capability updated" : "Capability created");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((v) => save.mutate(v))}
      >
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>Name</RequiredFormLabel>
              <FormControl>
                <Input placeholder="e.g. publish" {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="resourceKind"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Resource kind</FormLabel>
              <Select
                value={field.value || KIND_NONE}
                onValueChange={(v) =>
                  field.onChange(v === KIND_NONE ? "" : v)
                }
              >
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="— applies to all resources —" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value={KIND_NONE}>
                    — applies to all resources —
                  </SelectItem>
                  {knownKinds.map((kind) => (
                    <SelectItem key={kind} value={kind}>
                      {kind}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Description</FormLabel>
              <FormControl>
                <Input
                  placeholder="e.g. Publish messages to a channel"
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={save.isPending} type="submit">
            {isEdit ? "Save changes" : "Create capability"}
          </Button>
        </div>
      </form>
    </Form>
  );
}
