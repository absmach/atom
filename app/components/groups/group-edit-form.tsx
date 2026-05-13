"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
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
import { graphqlClient } from "@/lib/graphql/client";

const UPDATE_GROUP_MUTATION = `
  mutation UpdateGroup($id: ID!, $input: UpdateGroupInput!) {
    updateGroup(id: $id, input: $input) {
      id
      name
      description
      updatedAt
    }
  }
`;

const schema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  description: z.string().trim(),
});

type FormValues = z.infer<typeof schema>;

export type GroupFormInitialValues = {
  id: string;
  name: string;
  description: string;
};

export function GroupEditForm({
  group,
  onCancel,
  onSaved,
}: {
  group: GroupFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      name: group.name,
      description: group.description,
    },
  });

  const save = useMutation({
    mutationFn: (values: FormValues) =>
      graphqlClient({
        query: UPDATE_GROUP_MUTATION,
        variables: {
          id: group.id,
          input: {
            name: values.name,
            description: values.description || undefined,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Group updated");
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
                <Input {...field} />
              </FormControl>
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
                <Input {...field} />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button type="submit" disabled={save.isPending}>
            Save changes
          </Button>
        </div>
      </form>
    </Form>
  );
}
