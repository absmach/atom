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
        total: 2,
        items: [
          {
            id: "entity-1",
            name: "sensor-01",
            kind: "device",
            status: "active",
            objectGroupIds: ["group-1"],
          },
          {
            id: "entity-2",
            name: "gateway-02",
            kind: "device",
            status: "active",
            objectGroupIds: [],
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

  it("keeps entities already in the group out of the add picker", async () => {
    renderPanel();

    await screen.findByText("gateway-02");

    const addButtons = screen.getAllByRole("button", { name: "Add" });
    expect(addButtons).toHaveLength(1);
    expect(addButtons[0].parentElement).toHaveTextContent("gateway-02");
    // Only the member row, never a second row in the picker below it.
    expect(screen.getAllByText("sensor-01")).toHaveLength(1);
  });

  it("refills from later candidate pages after joined rows", async () => {
    mocks.graphqlClient.mockImplementation((call: GraphqlCall) => {
      if (call.query.includes("ObjectGroupEntityCandidates")) {
        const offset = call.variables?.offset ?? 0;
        return Promise.resolve({
          list: {
            total: 21,
            items: offset === 0
              ? [{
                  id: "entity-1",
                  name: "sensor-01",
                  kind: "device",
                  status: "active",
                  objectGroupIds: ["group-1"],
                }]
              : [{
                  id: "entity-2",
                  name: "gateway-02",
                  kind: "device",
                  status: "active",
                  objectGroupIds: [],
                }],
          },
        });
      }
      return respond(call);
    });

    renderPanel();

    expect(await screen.findByText("gateway-02")).toBeInTheDocument();
    expect(mocks.graphqlClient).toHaveBeenCalledWith(
      expect.objectContaining({
        variables: expect.objectContaining({ offset: 20 }),
      }),
    );
  });

  it("says so when every match is already a member", async () => {
    mocks.graphqlClient.mockImplementation((call: GraphqlCall) => {
      if (call.query.includes("ObjectGroupEntityCandidates")) {
        return Promise.resolve({
          list: {
            total: 1,
            items: [
              {
                id: "entity-1",
                name: "sensor-01",
                kind: "device",
                status: "active",
                objectGroupIds: ["group-1"],
              },
            ],
          },
        });
      }
      return respond(call);
    });

    renderPanel();

    expect(
      await screen.findByText(
        "Every matching entity is already in this group.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add" }),
    ).not.toBeInTheDocument();
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
