"use client";

import { useQuery } from "@tanstack/react-query";
import { UserRound, UsersRound } from "lucide-react";
import { StatusBadge } from "@/components/crud/status-badge";
import { DisplayTimeCell } from "@/components/display-time";
import { Badge } from "@/components/ui/badge";
import { graphqlClient } from "@/lib/graphql/client";
import { Action } from "@/lib/utils";

const ROLE_ASSIGNMENTS_QUERY = `
  query RolePrincipalsPanel(
    $roleId: ID!
    $tenantId: ID
    $limit: Int = 100
    $offset: Int = 0
  ) {
    roleAssignments(
      roleId: $roleId
      tenantId: $tenantId
      limit: $limit
      offset: $offset
    ) {
      total
      items {
        id
        tenantId
        subjectKind
        subjectId
        createdAt
      }
    }
  }
`;

const ENTITY_SUBJECT_QUERY = `
  query RolePrincipalEntity($id: ID!) {
    entity(id: $id) {
      id
      name
      kind
      status
      tenantId
    }
  }
`;

const GROUP_SUBJECT_QUERY = `
  query RolePrincipalGroup($id: ID!) {
    group(id: $id) {
      id
      name
      groupType
      status
      tenantId
    }
  }
`;

type RoleAssignment = {
  id: string;
  tenantId?: string | null;
  subjectKind: string;
  subjectId: string;
  createdAt: string;
};

type EntitySubject = {
  id: string;
  name: string;
  kind: string;
  status: string;
  tenantId?: string | null;
};

type GroupSubject = {
  id: string;
  name: string;
  groupType: string;
  status: string;
  tenantId?: string | null;
};

type SubjectLookup =
  | { state: "loaded"; entity: EntitySubject; group?: never }
  | { state: "loaded"; entity?: never; group: GroupSubject }
  | { state: "error"; message: string };

export function RolePrincipalsPanel({
  roleId,
  tenantId,
}: {
  roleId: string;
  tenantId?: string | null;
}) {
  const assignmentsQuery = useQuery({
    queryKey: ["role-principals-panel", roleId, tenantId ?? null],
    queryFn: ({ signal }) =>
      graphqlClient<{
        roleAssignments: { items: RoleAssignment[]; total: number };
      }>({
        query: ROLE_ASSIGNMENTS_QUERY,
        variables: {
          roleId,
          tenantId: tenantId || null,
          limit: 100,
          offset: 0,
        },
        signal,
      }),
    staleTime: 30_000,
  });

  const assignments = assignmentsQuery.data?.roleAssignments.items ?? [];

  const subjectsQuery = useQuery({
    enabled: assignments.length > 0,
    queryKey: [
      "role-principals-subjects",
      assignments
        .map(
          (assignment) =>
            `${assignment.id}:${assignment.subjectKind}:${assignment.subjectId}`,
        )
        .join("|"),
    ],
    queryFn: ({ signal }) => loadSubjects(assignments, signal),
    staleTime: 30_000,
  });

  const total = assignmentsQuery.data?.roleAssignments.total ?? 0;
  const subjects = subjectsQuery.data ?? {};

  return (
    <div className="grid gap-3 rounded-lg border bg-background p-3">
      <div className="flex items-center justify-between gap-3">
        <div className="text-sm font-medium">Principals</div>
        <Badge variant="outline">{total} assigned</Badge>
      </div>

      {assignmentsQuery.isFetching && assignments.length === 0 ? (
        <p className="text-sm text-muted-foreground">Loading...</p>
      ) : assignmentsQuery.error ? (
        <p className="text-sm text-destructive">
          {assignmentsQuery.error.message}
        </p>
      ) : assignments.length === 0 ? (
        <p className="text-sm text-muted-foreground">
          No principals are assigned to this role.
        </p>
      ) : (
        <div className="grid gap-2">
          {assignments.map((assignment) => (
            <PrincipalRow
              assignment={assignment}
              key={assignment.id}
              subject={subjects[assignment.id]}
            />
          ))}
        </div>
      )}

      {subjectsQuery.isFetching && assignments.length > 0 ? (
        <p className="text-xs text-muted-foreground">
          Loading principal details...
        </p>
      ) : null}

      {total > assignments.length ? (
        <p className="text-xs text-muted-foreground">
          Showing first {assignments.length} of {total} assignments.
        </p>
      ) : null}
    </div>
  );
}

async function loadSubjects(
  assignments: RoleAssignment[],
  signal?: AbortSignal,
): Promise<Record<string, SubjectLookup>> {
  const entries = await Promise.all(
    assignments.map(async (assignment) => {
      try {
        if (isGroupAssignment(assignment.subjectKind)) {
          const data = await graphqlClient<{ group: GroupSubject }>({
            query: GROUP_SUBJECT_QUERY,
            variables: { id: assignment.subjectId },
            signal,
          });
          return [
            assignment.id,
            { state: "loaded", group: data.group },
          ] as const;
        }

        const data = await graphqlClient<{ entity: EntitySubject }>({
          query: ENTITY_SUBJECT_QUERY,
          variables: { id: assignment.subjectId },
          signal,
        });
        return [
          assignment.id,
          { state: "loaded", entity: data.entity },
        ] as const;
      } catch (error) {
        return [
          assignment.id,
          {
            state: "error",
            message:
              error instanceof Error
                ? error.message
                : "Unable to load principal details",
          },
        ] as const;
      }
    }),
  );

  return Object.fromEntries(entries);
}

function PrincipalRow({
  assignment,
  subject,
}: {
  assignment: RoleAssignment;
  subject?: SubjectLookup;
}) {
  const isGroup = isGroupAssignment(assignment.subjectKind);
  const Icon = isGroup ? UsersRound : UserRound;
  const loaded = subject?.state === "loaded" ? subject : undefined;
  const name =
    loaded?.entity?.name ?? loaded?.group?.name ?? assignment.subjectId;
  const detail = loaded?.entity?.kind ?? loaded?.group?.groupType;
  const status = loaded?.entity?.status ?? loaded?.group?.status;
  const subjectTenantId = loaded?.entity?.tenantId ?? loaded?.group?.tenantId;

  return (
    <div className="grid gap-2 rounded-md border p-2">
      <div className="flex min-w-0 items-start gap-2">
        <span className="mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted text-muted-foreground">
          <Icon className="size-4" />
        </span>
        <div className="grid min-w-0 flex-1 gap-1">
          <div className="flex min-w-0 flex-wrap items-center gap-2">
            <span className="min-w-0 truncate text-sm font-medium">{name}</span>
            <Badge variant="secondary">
              {isGroup ? "Principal group" : "Entity"}
            </Badge>
            {status ? <StatusBadge value={status} /> : null}
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
            {detail ? <span>{detail}</span> : null}
            {subjectTenantId ? <span>Tenant {subjectTenantId}</span> : null}
            <span>
              Assigned{" "}
              <DisplayTimeCell
                action={Action.Assigned}
                time={assignment.createdAt}
              />
            </span>
          </div>
        </div>
      </div>

      {subject?.state === "error" ? (
        <p className="text-xs text-muted-foreground">{subject.message}</p>
      ) : null}

      <div className="break-all font-mono text-xs text-muted-foreground">
        {assignment.subjectId}
      </div>
    </div>
  );
}

function isGroupAssignment(subjectKind: string) {
  return subjectKind.toLowerCase() === "group";
}
