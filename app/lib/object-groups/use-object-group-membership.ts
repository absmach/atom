"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { graphqlClient } from "@/lib/graphql/client";
import {
  candidatesQuery,
  type MembershipOperation,
  membershipMutation,
  membershipQuery,
  membershipVariables,
  membersQuery,
  OBJECT_GROUPS_QUERY,
  excludeJoinedGroups,
  excludeJoinedMembers,
  type ObjectGroupMember,
  type ObjectGroupMemberPage,
  type ObjectGroupMembership,
  type ObjectGroupOption,
  type ObjectMemberKind,
} from "@/lib/object-groups/membership";

export const OBJECT_GROUP_MEMBERS_KEY = "object-group-members";
export const OBJECT_GROUP_MEMBERSHIP_KEY = "object-group-membership";
export const OBJECT_GROUP_CANDIDATES_KEY = "object-group-member-candidates";

export function membersQueryKey(
  kind: ObjectMemberKind,
  groupId: string,
  page: number,
) {
  return [OBJECT_GROUP_MEMBERS_KEY, kind, groupId, page];
}

export function membershipQueryKey(
  kind: ObjectMemberKind,
  memberId: string,
): [string, ObjectMemberKind, string] {
  return [OBJECT_GROUP_MEMBERSHIP_KEY, kind, memberId];
}

/** Members of one object group, one kind at a time. */
export function useObjectGroupMembers({
  groupId,
  kind,
  page,
  pageSize,
}: {
  groupId: string;
  kind: ObjectMemberKind;
  page: number;
  pageSize: number;
}) {
  return useQuery({
    enabled: Boolean(groupId),
    queryKey: membersQueryKey(kind, groupId, page),
    queryFn: async ({ signal }) => {
      const data = await graphqlClient<{ list: ObjectGroupMemberPage }>({
        query: membersQuery(kind),
        variables: {
          groupId,
          limit: pageSize,
          offset: (page - 1) * pageSize,
        },
        signal,
      });
      return data.list;
    },
    staleTime: 30_000,
    placeholderData: (previous) => previous,
  });
}

/** Search-to-add candidates for a group panel, scoped to the group's tenant. */
export function useObjectGroupMemberCandidates({
  kind,
  tenantId,
  search,
  groupId,
  limit = 20,
}: {
  kind: ObjectMemberKind;
  tenantId?: string | null;
  search: string;
  groupId: string;
  limit?: number;
}) {
  const q = search.trim();
  return useQuery({
    enabled: Boolean(tenantId),
    queryKey: [
      OBJECT_GROUP_CANDIDATES_KEY,
      kind,
      tenantId ?? null,
      groupId,
      q,
    ],
    queryFn: async ({ signal }) => {
      const items: ObjectGroupMember[] = [];
      let total = 0;
      let offset = 0;

      // Membership is returned on each row, so refill the picker from later
      // pages when an earlier page consists entirely of joined members.
      while (offset < total || offset === 0) {
        const data = await graphqlClient<{
          list: { total: number; items: ObjectGroupMember[] };
        }>({
          query: candidatesQuery(kind),
          variables: {
            tenantId: tenantId || null,
            q: q || null,
            limit,
            offset,
          },
          signal,
        });
        total = data.list.total;
        items.push(...excludeJoinedMembers(data.list.items, groupId));

        if (
          items.length >= limit ||
          data.list.items.length === 0 ||
          offset + data.list.items.length >= total
        ) break;
        offset += limit;
      }

      return { items: items.slice(0, limit), total };
    },
    staleTime: 30_000,
    placeholderData: (previous) => previous,
  });
}

/** Object groups an entity/resource can be added to, never principal groups. */
export function useObjectGroupOptions({
  tenantId,
  search,
  excludedGroupIds = [],
  limit = 20,
}: {
  tenantId?: string | null;
  search: string;
  excludedGroupIds?: readonly string[];
  limit?: number;
}) {
  const q = search.trim();
  const excludedKey = excludedGroupIds.join(",");
  return useQuery({
    queryKey: ["object-group-options", tenantId ?? null, q, excludedKey],
    queryFn: async ({ signal }) => {
      const items: ObjectGroupOption[] = [];
      let total = 0;
      let offset = 0;

      // Refill from later pages when the first page contains only joined groups.
      while (offset < total || offset === 0) {
        const data = await graphqlClient<{
          objectGroups: { total: number; items: ObjectGroupOption[] };
        }>({
          query: OBJECT_GROUPS_QUERY,
          variables: {
            tenantId: tenantId || null,
            q: q || null,
            limit,
            offset,
          },
          signal,
        });
        total = data.objectGroups.total;
        items.push(
          ...excludeJoinedGroups(data.objectGroups.items, excludedGroupIds),
        );

        if (
          items.length >= limit ||
          data.objectGroups.items.length === 0 ||
          offset + data.objectGroups.items.length >= total
        ) break;
        offset += limit;
      }

      return { items: items.slice(0, limit), total };
    },
    staleTime: 30_000,
    placeholderData: (previous) => previous,
  });
}

/**
 * Every object group one entity/resource belongs to. Seeded from the row the
 * inspect sheet already has, then kept honest by the mutation responses.
 */
export function useObjectGroupIds({
  kind,
  memberId,
  initialObjectGroupIds,
}: {
  kind: ObjectMemberKind;
  memberId: string;
  initialObjectGroupIds: string[];
}) {
  return useQuery({
    enabled: Boolean(memberId),
    queryKey: membershipQueryKey(kind, memberId),
    queryFn: async ({ signal }) => {
      const data = await graphqlClient<{ member: ObjectGroupMembership }>({
        query: membershipQuery(kind),
        variables: { id: memberId },
        signal,
      });
      return data.member.objectGroupIds;
    },
    initialData: initialObjectGroupIds,
    staleTime: 30_000,
  });
}

export type MembershipActionVariables = {
  memberId: string;
  objectGroupId?: string;
  /**
   * Overrides the success toast. The two directions phrase it differently: the
   * group panel names the member, the entity/resource field names the group.
   */
  message?: string;
};

/**
 * The six membership mutations, usable from either direction. Adds and removes
 * are idempotent server-side (`ON CONFLICT DO NOTHING` / zero-row delete), so
 * these need no "already a member" guard; the pickers keep a redundant add out
 * of reach instead, by hiding candidates that are already joined.
 */
export function useObjectGroupMembershipActions(kind: ObjectMemberKind) {
  const queryClient = useQueryClient();

  function mutationFn(operation: MembershipOperation) {
    return async ({ memberId, objectGroupId }: MembershipActionVariables) => {
      const data = await graphqlClient<{ result: ObjectGroupMembership }>({
        query: membershipMutation(kind, operation),
        variables: membershipVariables(kind, memberId, objectGroupId),
      });
      return data.result;
    };
  }

  function settle(result: ObjectGroupMembership, message: string) {
    queryClient.setQueryData(
      membershipQueryKey(kind, result.id),
      result.objectGroupIds,
    );
    queryClient.invalidateQueries({ queryKey: [OBJECT_GROUP_MEMBERS_KEY] });
    // Candidate rows carry the membership the picker filters on, so they go
    // stale the moment a member is added or removed.
    queryClient.invalidateQueries({ queryKey: [OBJECT_GROUP_CANDIDATES_KEY] });
    toast.success(message);
  }

  function fail(error: Error) {
    toast.error(error.message);
  }

  const addToGroup = useMutation({
    mutationFn: mutationFn("add"),
    onSuccess: (result, variables) =>
      settle(result, variables.message ?? "Added to object group"),
    onError: fail,
  });

  const removeFromGroup = useMutation({
    mutationFn: mutationFn("remove"),
    onSuccess: (result, variables) =>
      settle(result, variables.message ?? "Removed from object group"),
    onError: fail,
  });

  const clearGroups = useMutation({
    mutationFn: mutationFn("clear"),
    onSuccess: (result) => settle(result, "Removed from all object groups"),
    onError: fail,
  });

  return { addToGroup, removeFromGroup, clearGroups };
}
