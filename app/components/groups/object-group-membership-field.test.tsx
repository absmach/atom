import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ObjectGroupMembershipField } from "@/components/groups/object-group-membership-field";

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

function renderField(tenantId: string | null = "tenant-1") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <ObjectGroupMembershipField
        initialObjectGroupIds={["group-1"]}
        kind="entity"
        memberId="entity-1"
        tenantId={tenantId}
      />
    </QueryClientProvider>,
  );
}

type GraphqlCall = { query: string; variables?: Record<string, unknown> };

function respond({ query }: GraphqlCall) {
  if (query.includes("ResolveGroup")) {
    return Promise.resolve({ group: { name: "Floor sensors" } });
  }

  if (query.includes("ObjectGroupPicker")) {
    return Promise.resolve({
      objectGroups: {
        total: 2,
        items: [
          { id: "group-1", name: "Floor sensors" },
          { id: "group-2", name: "Gateways" },
        ],
      },
    });
  }

  if (query.includes("RemoveEntityFromObjectGroup")) {
    return Promise.resolve({ result: { id: "entity-1", objectGroupIds: [] } });
  }

  if (query.includes("AddEntityToObjectGroup")) {
    return Promise.resolve({
      result: { id: "entity-1", objectGroupIds: ["group-1", "group-2"] },
    });
  }

  if (query.includes("ClearEntityObjectGroups")) {
    return Promise.resolve({ result: { id: "entity-1", objectGroupIds: [] } });
  }

  throw new Error(`Unexpected query: ${query}`);
}

describe("ObjectGroupMembershipField", () => {
  afterEach(cleanup);

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.toastSuccess.mockReset();
    mocks.graphqlClient.mockImplementation(respond);
  });

  it("shows the groups the row already carries, resolved to names", async () => {
    renderField();

    expect(await screen.findByText("Floor sensors")).toBeInTheDocument();
    expect(screen.getByText("1 joined")).toBeInTheDocument();
    expect(mocks.graphqlClient).not.toHaveBeenCalledWith(
      expect.objectContaining({
        query: expect.stringContaining("EntityObjectGroups"),
      }),
    );
  });

  it("adds the entity to a picked object group", async () => {
    const user = userEvent.setup();
    renderField();

    await screen.findByText("Gateways");
    await user.click(screen.getByRole("button", { name: "Add" }));

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { entityId: "entity-1", objectGroupId: "group-2" },
        }),
      );
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith("Added to Gateways");
  });

  it("keeps groups the entity already belongs to out of the picker", async () => {
    renderField();

    await screen.findByText("Gateways");

    const addButtons = screen.getAllByRole("button", { name: "Add" });
    expect(addButtons).toHaveLength(1);
    expect(addButtons[0].parentElement).toHaveTextContent("Gateways");
    // Only the joined chip, never a second row in the picker below it.
    expect(screen.getAllByText("Floor sensors")).toHaveLength(1);
  });

  it("refills from later group pages after joined rows", async () => {
    mocks.graphqlClient.mockImplementation((call: GraphqlCall) => {
      if (call.query.includes("ObjectGroupPicker")) {
        const offset = call.variables?.offset ?? 0;
        return Promise.resolve({
          objectGroups: {
            total: 21,
            items: offset === 0
              ? [{ id: "group-1", name: "Floor sensors" }]
              : [{ id: "group-2", name: "Gateways" }],
          },
        });
      }
      return respond(call);
    });

    renderField();

    expect(await screen.findByText("Gateways")).toBeInTheDocument();
    expect(mocks.graphqlClient).toHaveBeenCalledWith(
      expect.objectContaining({
        variables: expect.objectContaining({ offset: 20 }),
      }),
    );
  });

  it("says so when every match is already joined", async () => {
    mocks.graphqlClient.mockImplementation((call: GraphqlCall) => {
      if (call.query.includes("ObjectGroupPicker")) {
        return Promise.resolve({
          objectGroups: {
            total: 1,
            items: [{ id: "group-1", name: "Floor sensors" }],
          },
        });
      }
      return respond(call);
    });

    renderField();

    expect(
      await screen.findByText(
        "Already a member of every matching object group.",
      ),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add" }),
    ).not.toBeInTheDocument();
  });

  it("removes the entity from one group", async () => {
    const user = userEvent.setup();
    renderField();

    await screen.findByText("Floor sensors");
    await user.click(
      screen.getByRole("button", { name: "Remove from Floor sensors" }),
    );

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: { entityId: "entity-1", objectGroupId: "group-1" },
        }),
      );
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "Removed from Floor sensors",
    );
  });

  it("clears every membership behind a confirmation", async () => {
    const user = userEvent.setup();
    renderField();

    await screen.findByText("Floor sensors");
    await user.click(
      screen.getByRole("button", { name: "Remove from all object groups" }),
    );
    await user.click(screen.getByRole("button", { name: "Remove from all" }));

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({ variables: { entityId: "entity-1" } }),
      );
    });
    expect(mocks.toastSuccess).toHaveBeenCalledWith(
      "Removed from all object groups",
    );
  });

  it("explains why a platform-scoped entity cannot join a group", async () => {
    renderField(null);

    expect(
      await screen.findByText(/Platform-scoped entities cannot join/),
    ).toBeInTheDocument();
    expect(
      screen.queryByPlaceholderText("Search object groups…"),
    ).not.toBeInTheDocument();
  });
});
