import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TenantMembersPanel } from "@/components/tenants/tenant-members-panel";

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
      <TenantMembersPanel tenantId="tenant-1" />
    </QueryClientProvider>,
  );
}

describe("TenantMembersPanel", () => {
  afterEach(cleanup);

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
  });

  it("lists active tenant members", async () => {
    mocks.graphqlClient.mockResolvedValue({
      tenantMembers: {
        total: 2,
        items: [
          {
            id: "entity-1",
            name: "alice@example.test",
            kind: "human",
            tenantId: null,
            status: "active",
          },
          {
            id: "entity-2",
            name: "bob@example.test",
            kind: "human",
            tenantId: "tenant-1",
            status: "active",
          },
        ],
      },
    });

    renderPanel();

    expect(await screen.findByText("Tenant members")).toBeInTheDocument();
    expect(await screen.findByText("alice@example.test")).toBeInTheDocument();
    expect(screen.getByText("bob@example.test")).toBeInTheDocument();
    expect(screen.getByText("2 active")).toBeInTheDocument();
    expect(screen.getByText("Global entity")).toBeInTheDocument();
    expect(screen.getByText("Home tenant tenant-1")).toBeInTheDocument();

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: {
            tenantId: "tenant-1",
            q: null,
            limit: 100,
            offset: 0,
          },
        }),
      );
    });
  });

  it("shows an empty state", async () => {
    mocks.graphqlClient.mockResolvedValue({
      tenantMembers: {
        total: 0,
        items: [],
      },
    });

    renderPanel();

    expect(await screen.findByText("No active members.")).toBeInTheDocument();
  });
});
