import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthzDebugger } from "@/components/authz-debugger";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderDebugger() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <AuthzDebugger
        initialValues={{
          subjectId: "entity-1",
          targetKind: "resource",
          targetId: "resource-1",
        }}
      />
    </QueryClientProvider>,
  );
}

describe("AuthzDebugger", () => {
  afterEach(() => {
    cleanup();
    mocks.graphqlClient.mockReset();
  });

  it("shows prefilled subject and resource selections", async () => {
    mocks.graphqlClient.mockImplementation(({ query }: { query: string }) => {
      if (query.includes("AuthzEntities")) {
        return Promise.resolve({
          entities: {
            items: [{ id: "entity-1", name: "admin", kind: "human" }],
          },
        });
      }
      if (query.includes("AuthzResources")) {
        return Promise.resolve({
          resources: {
            items: [{ id: "resource-1", name: "telemetry", kind: "channel" }],
          },
        });
      }
      if (query.includes("AuthzTenants")) {
        return Promise.resolve({ tenants: { items: [] } });
      }
      if (query.includes("AuthzActions")) {
        return Promise.resolve({ actions: { items: [] } });
      }
      if (query.includes("AuthzObjectGroups")) {
        return Promise.resolve({ objectGroups: { items: [] } });
      }
      // Prefilled values are resolved via single-item lookups (lazy lists).
      if (query.includes("AuthzEntity")) {
        return Promise.resolve({
          entity: { id: "entity-1", name: "admin", kind: "human" },
        });
      }
      if (query.includes("AuthzResource")) {
        return Promise.resolve({
          resource: { id: "resource-1", name: "telemetry", kind: "channel" },
        });
      }
      throw new Error(`Unexpected query: ${query}`);
    });

    renderDebugger();

    const selects = await screen.findAllByRole("combobox");
    await waitFor(() => {
      expect(selects[0]).toHaveTextContent("admin");
      expect(selects[2]).toHaveTextContent("Resource");
      expect(selects[3]).toHaveTextContent("telemetry");
    });
  });
});
