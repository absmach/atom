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

const SET_GROUP_PARENT_MUTATION = `
  mutation SetGroupParent($id: ID!, $parentId: ID!) {
    setGroupParent(id: $id, parentId: $parentId) { id parentId updatedAt }
  }
`;

const REMOVE_GROUP_PARENT_MUTATION = `
  mutation RemoveGroupParent($id: ID!) {
    removeGroupParent(id: $id)
  }
`;

const OBJECT_GROUPS_QUERY = `
  query GroupEditObjectGroups($tenantId: ID) {
    groups: objectGroups(tenantId: $tenantId, limit: 200, offset: 0) {
      items { id name tenantId parentId groupType }
    }
  }
`;

const PRINCIPAL_GROUPS_QUERY = `
  query GroupEditPrincipalGroups($tenantId: ID) {
    groups: principalGroups(tenantId: $tenantId, limit: 200, offset: 0) {
      items { id name tenantId parentId groupType }
    }
  }
`;

const PARENT_NONE = "__none__";

const schema = z.object({
  name: z.string().trim().min(1, "Name is required."),
  description: z.string().trim(),
  parentId: z.string(),
});

type FormValues = z.infer<typeof schema>;

export type GroupFormInitialValues = {
  id: string;
  name: string;
  tenantId: string;
  groupType: string;
  parentId: string;
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
      parentId: group.parentId,
    },
  });

  const groupsQuery = useQuery({
    queryKey: [
      "group-edit-parent-options",
      group.tenantId,
      group.groupType,
      group.id,
    ],
    queryFn: ({ signal }) =>
      graphqlClient<{
        groups: {
          items: {
            id: string;
            name: string;
            tenantId: string | null;
            groupType: string;
          }[];
        };
      }>({
        query:
          group.groupType === "principal"
            ? PRINCIPAL_GROUPS_QUERY
            : OBJECT_GROUPS_QUERY,
        variables: {
          tenantId: group.tenantId || undefined,
        },
        signal,
      }),
    staleTime: 30_000,
  });
  const parentOptions = (groupsQuery.data?.groups.items ?? []).filter(
    (item) => item.id !== group.id,
  );

  const save = useMutation({
    mutationFn: async (values: FormValues) => {
      await graphqlClient({
        query: UPDATE_GROUP_MUTATION,
        variables: {
          id: group.id,
          input: {
            name: values.name,
            description: values.description || undefined,
          },
        },
      });
      if (values.parentId !== group.parentId) {
        if (values.parentId) {
          await graphqlClient({
            query: SET_GROUP_PARENT_MUTATION,
            variables: { id: group.id, parentId: values.parentId },
          });
        } else {
          await graphqlClient({
            query: REMOVE_GROUP_PARENT_MUTATION,
            variables: { id: group.id },
          });
        }
      }
    },
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
        <div className="grid gap-1 rounded-lg border bg-muted/30 px-3 py-2">
          <span className="text-xs font-medium uppercase text-muted-foreground">
            Group type
          </span>
          <span className="text-sm">{groupTypeLabel(group.groupType)}</span>
        </div>
        <FormField
          control={form.control}
          name="parentId"
          render={({ field }) => (
            <FormItem>
              <FormLabel>Parent group</FormLabel>
              <Select
                value={field.value || PARENT_NONE}
                onValueChange={(value) =>
                  field.onChange(value === PARENT_NONE ? "" : value)
                }
              >
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="- no parent -" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectItem value={PARENT_NONE}>- no parent -</SelectItem>
                  {parentOptions.map((option) => (
                    <SelectItem key={option.id} value={option.id}>
                      {option.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {group.groupType === "principal"
                  ? "Parent Principal Groups extend inherited role assignments for identities."
                  : "Parent Object Groups extend where role permissions apply. They do not grant access by themselves."}
              </p>
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

function groupTypeLabel(groupType: string) {
  if (groupType === "principal") return "Principal group";
  return "Object group";
}
