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
  FormDescription,
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

const ACTIONS_QUERY = `
  query ActionApplicabilityFormActions {
    actions(limit: 500, offset: 0) { items { id name description } }
  }
`;

const CREATE_ACTION_MUTATION = `
  mutation CreateAction($input: CreateActionInput!) {
    createAction(input: $input) {
      id
      name
      description
      createdAt
      updatedAt
    }
  }
`;

const ADD_ACTION_APPLICABILITY_MUTATION = `
  mutation AddActionApplicability($input: AddActionApplicabilityInput!) {
    addActionApplicability(input: $input) {
      id
      actionId
      actionName
      objectKind
      objectType
      createdAt
    }
  }
`;

const OBJECT_KINDS = [
  "entity",
  "resource",
  "group",
  "tenant",
  "role",
  "policy",
  "credential",
  "audit_log",
] as const;

export type ActionApplicabilityFormInitialValues = {
  id: string;
  actionId: string;
  actionName: string;
  objectKind: string;
  objectType: string;
};

const actionSchema = z.object({
  name: z.string().trim().min(1, "name is required."),
  description: z.string().trim(),
});

const applicabilitySchema = z.object({
  actionId: z.string().min(1, "action_id is required."),
  objectKind: z.string().min(1, "object_kind is required."),
  objectType: z.string().trim(),
});

type ActionValues = z.infer<typeof actionSchema>;
type ActionApplicabilityValues = z.infer<typeof applicabilitySchema>;

type ActionOption = {
  id: string;
  name: string;
  description?: string | null;
};

export function ActionCreateForm({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => void;
}) {
  const form = useForm<ActionValues>({
    resolver: zodResolver(actionSchema),
    defaultValues: {
      name: "",
      description: "",
    },
  });

  const save = useMutation({
    mutationFn: (values: ActionValues) =>
      graphqlClient({
        query: CREATE_ACTION_MUTATION,
        variables: {
          input: {
            name: values.name,
            description: values.description || null,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Action created");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((values) => save.mutate(values))}
      >
        <FormField
          control={form.control}
          name="name"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>name</RequiredFormLabel>
              <FormControl>
                <Input placeholder="e.g. publish" {...field} />
              </FormControl>
              <FormDescription>
                One unique action name stored in `actions.name`.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="description"
          render={({ field }) => (
            <FormItem>
              <FormLabel>description</FormLabel>
              <FormControl>
                <Input
                  placeholder="e.g. Publish messages to channels"
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
            Create action
          </Button>
        </div>
      </form>
    </Form>
  );
}

export function ActionApplicabilityCreateForm({
  applicability,
  onCancel,
  onSaved,
}: {
  applicability?: ActionApplicabilityFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const actionsQuery = useQuery({
    queryKey: ["action-applicability-form-actions"],
    queryFn: ({ signal }) =>
      graphqlClient<{ actions: { items: ActionOption[] } }>({
        query: ACTIONS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const form = useForm<ActionApplicabilityValues>({
    resolver: zodResolver(applicabilitySchema),
    defaultValues: {
      actionId: applicability?.actionId ?? "",
      objectKind: applicability?.objectKind ?? "",
      objectType: applicability?.objectType ?? "",
    },
  });

  const save = useMutation({
    mutationFn: (values: ActionApplicabilityValues) =>
      graphqlClient({
        query: ADD_ACTION_APPLICABILITY_MUTATION,
        variables: {
          input: {
            actionId: values.actionId,
            objectKind: values.objectKind,
            objectType: values.objectType || null,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Action applicability row saved");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  const actions = actionsQuery.data?.actions.items ?? [];

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((values) => save.mutate(values))}
      >
        <FormField
          control={form.control}
          name="actionId"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>action_id</RequiredFormLabel>
              <Select
                disabled={actionsQuery.isFetching}
                onValueChange={field.onChange}
                value={field.value || undefined}
              >
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select action" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {actions.map((item) => (
                    <SelectItem key={item.id} value={item.id}>
                      {item.name} ({item.id})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <FormDescription>
                References `actions.id`. Create the action first if it does not
                exist yet.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="objectKind"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>object_kind</RequiredFormLabel>
              <Select
                onValueChange={field.onChange}
                value={field.value || undefined}
              >
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select object_kind" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {OBJECT_KINDS.map((kind) => (
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
          name="objectType"
          render={({ field }) => (
            <FormItem>
              <FormLabel>object_type</FormLabel>
              <FormControl>
                <Input placeholder="NULL or e.g. resource:channel" {...field} />
              </FormControl>
              <FormDescription>
                Leave empty to store `NULL`. Use namespaced values such as
                `entity:device` or `resource:channel`.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={save.isPending} type="submit">
            Create row
          </Button>
        </div>
      </form>
    </Form>
  );
}
