import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EntityCredentials } from "@/components/entities/entity-credentials";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderEntityCredentials() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <EntityCredentials entityId="entity-1" />
    </QueryClientProvider>,
  );
}

describe("EntityCredentials", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockResolvedValue({
      credentials: {
        items: [
          {
            id: "password-1",
            kind: "password",
            status: "active",
            identifier: null,
            expiresAt: null,
            createdAt: "2026-06-05T00:00:00Z",
          },
          {
            id: "certificate-1",
            kind: "certificate",
            status: "active",
            identifier: "0abc1234",
            expiresAt: "2026-06-06T00:00:00Z",
            createdAt: "2026-06-05T00:00:00Z",
          },
        ],
        total: 2,
      },
    });
  });

  it("shows existing password and certificate credentials together", async () => {
    renderEntityCredentials();

    expect(await screen.findByText("Password")).toBeInTheDocument();
    expect(screen.getByText("Certificate")).toBeInTheDocument();
    expect(screen.getByText("0abc1234")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add password" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add API key" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Issue certificate" }),
    ).toBeInTheDocument();
  });

  it("opens one explicit add form at a time", async () => {
    const user = userEvent.setup();
    renderEntityCredentials();

    await user.click(
      await screen.findByRole("button", { name: "Add password" }),
    );
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.getByLabelText("Confirm password")).toBeInTheDocument();
    expect(screen.queryByLabelText("Common name")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Issue certificate" }));
    expect(screen.getByLabelText("Common name")).toBeInTheDocument();
    expect(screen.getByLabelText("CSR PEM")).toBeInTheDocument();
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    await user.click(screen.getByRole("button", { name: "Add API key" }));
    expect(screen.getByLabelText("Description")).toBeInTheDocument();
    expect(screen.getByText("Expires at (optional)")).toBeInTheDocument();
    expect(screen.queryByLabelText("Common name")).not.toBeInTheDocument();
  });
});
