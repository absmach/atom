"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation, useQuery } from "@tanstack/react-query";
import * as React from "react";
import { useForm } from "react-hook-form";
import { toast } from "sonner";
import { z } from "zod";
import { useTenant } from "@/components/app-shell/tenant-provider";
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
import { Switch } from "@/components/ui/switch";
import { graphqlClient } from "@/lib/graphql/client";
import { tenantQueryValue } from "@/lib/tenant/context";

const ACTIONS_QUERY = `
  query ActionAssignmentRuleFormActions {
    actions(limit: 500, offset: 0) { items { id name description } }
  }
`;

const CREATE_RULE_MUTATION = `
  mutation CreateActionAssignmentRule($input: CreateActionAssignmentRuleInput!) {
    createActionAssignmentRule(input: $input) {
      id
      tenantId
      entityKind
      actionName
      objectKind
      objectType
      decision
      isAbsolute
      createdAt
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

const OBJECT_KINDS = [
  "entity",
  "resource",
  "group",
  "tenant",
  "role",
  "policy",
  "credential",
  "audit_log",
  "signing_key",
] as const;

const schema = z.object({
  entityKind: z.enum(ENTITY_KINDS),
  actionName: z.string().min(1, "action_name is required."),
  objectKind: z.enum(OBJECT_KINDS),
  objectType: z.string().trim(),
  decision: z.enum(["allow", "deny"]),
  isAbsolute: z.boolean(),
});

type Values = z.infer<typeof schema>;
type ActionOption = { id: string; name: string; description?: string | null };

export function ActionAssignmentRuleCreateForm({
  onCancel,
  onSaved,
}: {
  onCancel: () => void;
  onSaved: () => void;
}) {
  const { selection } = useTenant();
  const tenantId = tenantQueryValue(selection);
  const actionsQuery = useQuery({
    queryKey: ["action-assignment-rule-form-actions"],
    queryFn: ({ signal }) =>
      graphqlClient<{ actions: { items: ActionOption[] } }>({
        query: ACTIONS_QUERY,
        signal,
      }),
    staleTime: 60_000,
  });

  const form = useForm<Values>({
    resolver: zodResolver(schema),
    defaultValues: {
      entityKind: "device",
      actionName: "",
      objectKind: "resource",
      objectType: "",
      decision: tenantId ? "deny" : "allow",
      isAbsolute: false,
    },
  });

  const save = useMutation({
    mutationFn: (values: Values) =>
      graphqlClient({
        query: CREATE_RULE_MUTATION,
        variables: {
          input: {
            tenantId,
            entityKind: values.entityKind,
            actionName: values.actionName,
            objectKind: values.objectKind,
            objectType: values.objectType || null,
            decision: tenantId ? "deny" : values.decision,
            isAbsolute: tenantId ? false : values.isAbsolute,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Assignment guardrail created");
      onSaved();
    },
    onError: (err) => toast.error(err.message),
  });

  const actions = actionsQuery.data?.actions.items ?? [];

  React.useEffect(() => {
    if (!tenantId) return;
    form.setValue("decision", "deny");
    form.setValue("isAbsolute", false);
  }, [form, tenantId]);

  return (
    <Form {...form}>
      <form
        className="grid gap-4"
        onSubmit={form.handleSubmit((values) => save.mutate(values))}
      >
        <FormField
          control={form.control}
          name="entityKind"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>entity_kind</RequiredFormLabel>
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select entity kind" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {ENTITY_KINDS.map((kind) => (
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
          name="actionName"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>action_name</RequiredFormLabel>
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
                  {actions.map((action) => (
                    <SelectItem key={action.id} value={action.name}>
                      {action.name}
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
          name="objectKind"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>object_kind</RequiredFormLabel>
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select object kind" />
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
                Leave empty to match every sub-kind for the selected object
                kind.
              </FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />

        <FormField
          control={form.control}
          name="decision"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>decision</RequiredFormLabel>
              <Select
                onValueChange={field.onChange}
                value={tenantId ? "deny" : field.value}
              >
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue placeholder="Select decision" />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  {!tenantId ? (
                    <SelectItem value="allow">allow</SelectItem>
                  ) : null}
                  <SelectItem value="deny">deny</SelectItem>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />

        {!tenantId ? (
          <FormField
            control={form.control}
            name="isAbsolute"
            render={({ field }) => (
              <FormItem className="flex items-center justify-between gap-4 rounded-lg border p-3">
                <div>
                  <FormLabel>is_absolute</FormLabel>
                  <FormDescription>
                    Absolute global rules cannot be overridden by tenants.
                  </FormDescription>
                </div>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </FormItem>
            )}
          />
        ) : null}

        <div className="flex justify-end gap-2">
          <Button onClick={onCancel} type="button" variant="outline">
            Cancel
          </Button>
          <Button disabled={save.isPending} type="submit">
            Create guardrail
          </Button>
        </div>
      </form>
    </Form>
  );
}
