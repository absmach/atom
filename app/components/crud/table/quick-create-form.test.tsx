import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { FallbackCreateForm } from "@/components/crud/table/quick-create-form";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderForm(resourceKey: string) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  const onSubmit = vi.fn((event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
  });

  render(
    <QueryClientProvider client={queryClient}>
      <FallbackCreateForm
        isPending={false}
        resourceKey={resourceKey}
        onSubmit={onSubmit}
      />
    </QueryClientProvider>,
  );

  return { onSubmit };
}

describe("FallbackCreateForm", () => {
  afterEach(() => {
    cleanup();
    mocks.graphqlClient.mockReset();
  });

  it("requires an explicit group type when creating groups", () => {
    mocks.graphqlClient.mockResolvedValue({ tenants: { items: [] } });
    renderForm("groups");

    const groupType = screen.getByLabelText("Group type");

    expect(groupType).toBeRequired();
    expect(groupType).toHaveValue("object");
    expect(screen.getByRole("option", { name: "Object group" })).toHaveValue(
      "object",
    );
    expect(screen.getByRole("option", { name: "Principal group" })).toHaveValue(
      "principal",
    );
  });

  it("does not show group type for other fallback resources", () => {
    mocks.graphqlClient.mockResolvedValue({ tenants: { items: [] } });
    renderForm("actions");

    expect(screen.queryByLabelText("Group type")).not.toBeInTheDocument();
  });
});
