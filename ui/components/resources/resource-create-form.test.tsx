import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceCreateForm } from "@/components/resources/resource-create-form";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderForm() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  render(
    <QueryClientProvider client={queryClient}>
      <ResourceCreateForm
        resource={{
          id: "resource-1",
          kind: "resource:channel",
          name: "Telemetry",
          alias: "telemetry",
          tenantId: "tenant-1",
          ownerId: "",
          attributes: {},
        }}
        onCancel={vi.fn()}
        onSaved={vi.fn()}
      />
    </QueryClientProvider>,
  );
}

describe("ResourceCreateForm aliases", () => {
  afterEach(cleanup);

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockResolvedValue({});
  });

  it("sends explicit null when an existing alias is cleared", async () => {
    const user = userEvent.setup();
    renderForm();

    const alias = screen.getByLabelText("Alias");
    await user.clear(alias);
    await user.click(screen.getByRole("button", { name: "Save changes" }));

    await waitFor(() => {
      expect(mocks.graphqlClient).toHaveBeenCalledWith(
        expect.objectContaining({
          variables: {
            id: "resource-1",
            input: expect.objectContaining({ alias: null }),
          },
        }),
      );
    });
  });
});
