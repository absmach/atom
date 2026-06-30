import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { EntityCredentials } from "@/components/entities/entity-credentials";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderEntityCredentials(entityKind = "device") {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <EntityCredentials entityId="entity-1" entityKind={entityKind} />
    </QueryClientProvider>,
  );
}

const credentialsResponse = {
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
        id: "shared-key-1",
        kind: "shared_key",
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
    total: 3,
  },
};

describe("EntityCredentials", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockResolvedValue(credentialsResponse);
  });

  it("shows existing password, shared key, and certificate credentials together", async () => {
    renderEntityCredentials();

    expect(await screen.findByText("Password")).toBeInTheDocument();
    expect(screen.getByText("Shared key")).toBeInTheDocument();
    expect(screen.getByText("Certificate")).toBeInTheDocument();
    expect(screen.getByText("0abc1234")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add password" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add API key" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add shared key" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Issue certificate" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Reveal shared key" }),
    ).toBeInTheDocument();
  });

  it("hides the shared key action for human entities", async () => {
    renderEntityCredentials("human");

    expect(await screen.findByText("Password")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add password" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Add shared key" }),
    ).not.toBeInTheDocument();
  });

  it("offers shared keys alongside passwords for non-device machine entities", async () => {
    renderEntityCredentials("service");

    expect(await screen.findByText("Password")).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add password" }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: "Add shared key" }),
    ).toBeInTheDocument();
  });

  it("opens one explicit add form at a time", async () => {
    const user = userEvent.setup();
    renderEntityCredentials("human");

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

  it("creates and reveals shared keys", async () => {
    const user = userEvent.setup();
    mocks.graphqlClient.mockImplementation(async ({ query }) => {
      if (query.includes("CreateSharedKey")) {
        return {
          createSharedKey: {
            credentialId: "shared-key-created",
            key: "atom_shared_created",
            expiresAt: null,
          },
        };
      }
      if (query.includes("RevealSharedKey")) {
        return {
          revealSharedKey: {
            credentialId: "shared-key-1",
            key: "atom_shared_revealed",
            expiresAt: null,
          },
        };
      }
      return credentialsResponse;
    });
    renderEntityCredentials();

    await user.click(
      await screen.findByRole("button", { name: "Add shared key" }),
    );
    await user.type(screen.getByLabelText("Description"), "Provisioning");
    await user.type(screen.getByLabelText("Shared key"), "manual-device-key");
    await user.click(screen.getByRole("button", { name: "Create" }));

    expect(await screen.findByText("atom_shared_created")).toBeInTheDocument();
    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(
          ([request]) =>
            request.query.includes("CreateSharedKey") &&
            request.variables.input.description === "Provisioning" &&
            request.variables.input.key === "manual-device-key",
        ),
      ).toBe(true);
    });

    await user.click(screen.getByRole("button", { name: "Dismiss" }));
    await user.click(screen.getByRole("button", { name: "Reveal shared key" }));

    expect(await screen.findByText("atom_shared_revealed")).toBeInTheDocument();
  });
});
