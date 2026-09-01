import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { RolePrincipalsPanel } from "@/components/roles/role-principals-panel";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderPanel() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <RolePrincipalsPanel roleId="role-1" tenantId="tenant-1" />
    </QueryClientProvider>,
  );
}

describe("RolePrincipalsPanel", () => {
  afterEach(cleanup);

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
  });

  it("lists entity and principal group role assignments", async () => {
    mocks.graphqlClient.mockImplementation(
      ({
        query,
        variables,
      }: {
        query: string;
        variables?: Record<string, unknown>;
      }) => {
        if (query.includes("RolePrincipalsPanel")) {
          expect(variables).toMatchObject({
            roleId: "role-1",
            tenantId: "tenant-1",
          });
          return Promise.resolve({
            roleAssignments: {
              total: 2,
              items: [
                {
                  id: "assignment-1",
                  tenantId: "tenant-1",
                  subjectKind: "entity",
                  subjectId: "entity-1",
                  createdAt: "2026-01-01T00:00:00Z",
                },
                {
                  id: "assignment-2",
                  tenantId: "tenant-1",
                  subjectKind: "group",
                  subjectId: "group-1",
                  createdAt: "2026-01-02T00:00:00Z",
                },
              ],
            },
          });
        }

        if (query.includes("RolePrincipalEntity")) {
          return Promise.resolve({
            entity: {
              id: "entity-1",
              name: "alice",
              kind: "human",
              status: "active",
              tenantId: "tenant-1",
            },
          });
        }

        if (query.includes("RolePrincipalGroup")) {
          return Promise.resolve({
            group: {
              id: "group-1",
              name: "Operators",
              groupType: "principal",
              status: "active",
              tenantId: "tenant-1",
            },
          });
        }

        throw new Error(`Unexpected query: ${query}`);
      },
    );

    renderPanel();

    expect(await screen.findByText("Principals")).toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("alice")).toBeInTheDocument();
      expect(screen.getByText("Operators")).toBeInTheDocument();
    });
    expect(screen.getByText("Entity")).toBeInTheDocument();
    expect(screen.getByText("Principal group")).toBeInTheDocument();
    expect(screen.getByText("2 assigned")).toBeInTheDocument();
  });
});
