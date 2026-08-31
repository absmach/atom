import { useQuery } from "@tanstack/react-query";
import { graphqlClient } from "@/lib/graphql/client";

const TENANT_Q = `query ResolveTenant($id: ID!) { tenant(id: $id) { name } }`;
const ENTITY_Q = `query ResolveEntity($id: ID!) { entity(id: $id) { name } }`;
const PROFILE_Q = `query ResolveProfile($id: ID!) { profile(id: $id) { displayName } }`;
const GROUP_Q = `query ResolveGroup($id: ID!) { group(id: $id) { name } }`;
const ROLE_Q = `query ResolveRole($id: ID!) { role(id: $id) { name } }`;
const ACTION_Q = `query ResolveAction($id: ID!) { action(id: $id) { name } }`;

export type NameSpec = {
  tenantIds?: string[];
  entityIds?: string[];
  profileIds?: string[];
  groupIds?: string[];
  roleIds?: string[];
  actionIds?: string[];
};

function uniq(ids?: string[]): string[] {
  return [...new Set((ids ?? []).filter(Boolean))];
}

async function fetchNames(spec: NameSpec): Promise<Map<string, string>> {
  const map = new Map<string, string>();
  const tasks: Promise<void>[] = [];

  function add<T>(
    ids: string[],
    query: string,
    pick: (d: T) => string | null | undefined,
  ) {
    for (const id of ids) {
      tasks.push(
        graphqlClient<T>({ query, variables: { id } })
          .then((d) => {
            const n = pick(d);
            if (n) map.set(id, n);
          })
          .catch(() => {}),
      );
    }
  }

  add<{ tenant: { name: string } | null }>(
    uniq(spec.tenantIds),
    TENANT_Q,
    (d) => d.tenant?.name,
  );
  add<{ entity: { name: string } | null }>(
    uniq(spec.entityIds),
    ENTITY_Q,
    (d) => d.entity?.name,
  );
  add<{ profile: { displayName: string } | null }>(
    uniq(spec.profileIds),
    PROFILE_Q,
    (d) => d.profile?.displayName,
  );
  add<{ group: { name: string } | null }>(
    uniq(spec.groupIds),
    GROUP_Q,
    (d) => d.group?.name,
  );
  add<{ role: { name: string } | null }>(
    uniq(spec.roleIds),
    ROLE_Q,
    (d) => d.role?.name,
  );
  add<{ action: { name: string } | null }>(
    uniq(spec.actionIds),
    ACTION_Q,
    (d) => d.action?.name,
  );

  await Promise.all(tasks);
  return map;
}

const EMPTY_MAP = new Map<string, string>();

export function useNameMap(spec: NameSpec): Map<string, string> {
  const tenantIds = uniq(spec.tenantIds);
  const entityIds = uniq(spec.entityIds);
  const profileIds = uniq(spec.profileIds);
  const groupIds = uniq(spec.groupIds);
  const roleIds = uniq(spec.roleIds);
  const actionIds = uniq(spec.actionIds);

  const total =
    tenantIds.length +
    entityIds.length +
    profileIds.length +
    groupIds.length +
    roleIds.length +
    actionIds.length;

  const { data } = useQuery({
    queryKey: [
      "name-map",
      tenantIds.slice().sort(),
      entityIds.slice().sort(),
      profileIds.slice().sort(),
      groupIds.slice().sort(),
      roleIds.slice().sort(),
      actionIds.slice().sort(),
    ],
    queryFn: () => fetchNames(spec),
    enabled: total > 0,
    staleTime: 60_000,
    placeholderData: (prev) => prev,
  });

  return data ?? EMPTY_MAP;
}

export function extractIds(
  resourceKey: string,
  rows: Record<string, unknown>[],
): NameSpec {
  const tenantIds: string[] = [];
  const entityIds: string[] = [];
  const profileIds: string[] = [];
  const groupIds: string[] = [];
  const roleIds: string[] = [];
  const actionIds: string[] = [];

  for (const row of rows) {
    const str = (v: unknown) => (v && typeof v === "string" ? v : undefined);

    if (str(row.tenantId)) tenantIds.push(row.tenantId as string);

    if (resourceKey === "entities") {
      if (str(row.profileId)) profileIds.push(row.profileId as string);
    }

    if (resourceKey === "resources") {
      if (str(row.ownerId)) entityIds.push(row.ownerId as string);
    }

    if (resourceKey === "policies") {
      const subjectId = str(row.subjectId);

      if (subjectId) {
        if (row.subjectKind === "entity") entityIds.push(subjectId);
        else if (row.subjectKind === "group") groupIds.push(subjectId);
      }
    }
  }

  return { tenantIds, entityIds, profileIds, groupIds, roleIds, actionIds };
}
