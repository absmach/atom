import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ObjectGroupMembersPanel } from "@/components/groups/object-group-members-panel";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
  toastError: vi.fn(),
  toastSuccess: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

vi.mock("sonner", () => ({
  toast: {
    error: mocks.toastError,
    success: mocks.toastSuccess,
  },
}));

// jsdom has no ResizeObserver, which the scroll area measures itself with.
vi.stubGlobal(
  "ResizeObserver",
  class {
    observe() {}
    unobserve() {}
    disconnect() {}
  },
);

function renderPanel(tenantId: string | null = "tenant-1") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <ObjectGroupMembersPanel groupId="group-1" tenantId={tenantId} />
    </QueryClientProvider>,
  );
}

type GraphqlCall = { query: string; variables?: Record<string, unknown> };

function respond({ query, variables }: GraphqlCall) {
  if (query.includes("ObjectGroupEntityMembers")) {
    expect(variables).toMatchObject({ groupId: "group-1" });
    return Promise.resolve({
      list: {
        total: 1,
        items: [
          {
            id: "entity-1",
            name: "sensor-01",
            kind: "device",
            status: "active",
          },
        ],
      },
    });
  }

  if (query.includes("ObjectGroupEntityCandidates")) {
    expect(variables).toMatchObject({ tenantId: "tenant-1" });
    return Promise.resolve({
      list: {
        total: 1,
        items: [
          {
            id: "entity-2",
            name: "gateway-02",
            kind: "device",
            status: "active",
          },
        ],
      },
    });
  }

  if (query.includes("AddEntityToObjectGroup")) {
    return Promise.resolve({
      result: { id: "entity-2", objectGroupIds: ["group-1"] },
    });
  }

  if (query.includes("RemoveEntityFromObjectGroup")) {
    return Promise.resolve({
      result: { id: "entity-1", objectGroupIds: [] },
    });
  }

  throw new Error(`Unexpected query: ${query}`);
}

describe("ObjectGroupMembersPanel", () => {
  afterEach(cleanup);

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.toastSuccess.mockReset();
    mocks.graphqlClient.mockImplementation(respond);
  });

  it("lists the entities in the object group", async () => {
    renderPanel();

    expect(await screen.findByText("sensor-01")).toBeInTheDocument();
    expect(screen.getByText("1 entity")).toBeInTheDocument();
    expect(screen.getByText("active")).toBeInTheDocument();
  });

  it("adds a searched entity to the group", async () => {
    const user = userEvent.setup();
    renderPanel();

    await screen.findByText("gateway-02");
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { entityId: "entity-2", objectGroupId: "group-1" },
        }),
      );
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "gateway-02 added to this group",
    );
  });

  it("removes a member from the group", async () => {
    const user = userEvent.setup();
    renderPanel();

    await screen.findByText("sensor-01");
    await user.click(screen.getByRole("button", { name: "Remove from group" }));

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { entityId: "entity-1", objectGroupId: "group-1" },
        }),
      );
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "sensor-01 removed from this group",
    );
  });

  it("does not query or render add controls for a platform-scoped group", async () => {
    renderPanel(null);

    await screen.findByText("sensor-01");

    expect(screen.queryByText("Add entity")).not.toBeInTheDocument();
    expect(
      screen.queryByPlaceholderText("Search entities…"),
    ).not.toBeInTheDocument();
    expect(
      mocks.graphqlClient.mock.calls.some(([call]) =>
        call.query.includes("ObjectGroupEntityCandidates"),
      ),
    ).toBe(false);
  });
});
