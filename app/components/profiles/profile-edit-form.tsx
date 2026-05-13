"use client";

import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
import * as React from "react";
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
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { graphqlClient } from "@/lib/graphql/client";

const UPDATE_PROFILE_MUTATION = `
  mutation UpdateProfile($id: ID!, $input: UpdateProfileInput!) {
    updateProfile(id: $id, input: $input) {
      id
      displayName
      description
      status
      updatedAt
    }
  }
`;

const PROFILE_STATUSES = ["active", "deprecated", "disabled"] as const;

const schema = z.object({
  displayName: z.string().trim().min(1, "Display name is required."),
  description: z.string().trim(),
  status: z.enum(PROFILE_STATUSES),
});

type FormValues = z.infer<typeof schema>;

export type ProfileFormInitialValues = {
  id: string;
  displayName: string;
  description: string;
  status: (typeof PROFILE_STATUSES)[number];
};

export function ProfileEditForm({
  profile,
  onCancel,
  onSaved,
}: {
  profile: ProfileFormInitialValues;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const form = useForm<FormValues>({
    resolver: zodResolver(schema),
    defaultValues: {
      displayName: profile.displayName,
      description: profile.description,
      status: profile.status,
    },
  });

  const save = useMutation({
    mutationFn: (values: FormValues) =>
      graphqlClient({
        query: UPDATE_PROFILE_MUTATION,
        variables: {
          id: profile.id,
          input: {
            displayName: values.displayName,
            description: values.description || undefined,
            status: values.status,
          },
        },
      }),
    onSuccess: () => {
      toast.success("Profile updated");
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
          name="displayName"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>Display name</RequiredFormLabel>
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
        <FormField
          control={form.control}
          name="status"
          render={({ field }) => (
            <FormItem>
              <RequiredFormLabel required>Status</RequiredFormLabel>
              <Select onValueChange={field.onChange} value={field.value}>
                <FormControl>
                  <SelectTrigger className="w-full">
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent>
                  <SelectGroup>
                    {PROFILE_STATUSES.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
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
