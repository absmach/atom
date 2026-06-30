import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ProfileForm } from "@/components/profile/profile-form";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderProfileForm() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <ProfileForm entityId="entity-1" />
    </QueryClientProvider>,
  );
}

const profileResponse = {
  entity: {
    id: "entity-1",
    name: "alice",
    attributes: {
      first_name: "Alice",
      last_name: "Example",
      email: "alice@example.test",
    },
  },
};

const tokensResponse = {
  personalAccessTokens: {
    items: [
      {
        credentialId: "pat-1",
        name: "Laptop CLI",
        description: "Local scripts",
        identifier: "atom_abcdef12",
        status: "active",
        expiresAt: null,
        createdAt: "2026-06-05T00:00:00Z",
      },
    ],
    total: 1,
  },
};

describe("ProfileForm personal access tokens", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockImplementation(async ({ query }) => {
      if (query.includes("ProfileEntity")) return profileResponse;
      if (query.includes("ProfilePersonalAccessTokens")) return tokensResponse;
      if (query.includes("CreatePersonalAccessToken")) {
        return {
          createPersonalAccessToken: {
            credentialId: "pat-created",
            token: "atom_created_personal_access_token",
            name: "CI runner",
            description: "Build scripts",
            expiresAt: null,
          },
        };
      }
      if (query.includes("RevokePersonalAccessToken")) {
        return { revokePersonalAccessToken: true };
      }
      return {};
    });
  });

  it("lists personal access tokens in the profile page", async () => {
    renderProfileForm();

    expect(
      await screen.findByText("Personal Access Tokens"),
    ).toBeInTheDocument();
    expect(await screen.findByText("Laptop CLI")).toBeInTheDocument();
    expect(screen.getByText("Local scripts")).toBeInTheDocument();
    expect(screen.getByText("atom_abcdef12")).toBeInTheDocument();
  });

  it("creates and reveals a token without sending an entity id", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await screen.findByText("Personal Access Tokens");
    await user.type(screen.getByLabelText("Name"), "CI runner");
    await user.type(screen.getByLabelText("Description"), "Build scripts");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    expect(
      await screen.findByText("atom_created_personal_access_token"),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(
          ([request]) =>
            request.query.includes("CreatePersonalAccessToken") &&
            request.variables.input.name === "CI runner" &&
            request.variables.input.description === "Build scripts" &&
            request.variables.entityId === undefined,
        ),
      ).toBe(true);
    });
  });

  it("revokes a personal access token by credential id", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await user.click(await screen.findByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(
          ([request]) =>
            request.query.includes("RevokePersonalAccessToken") &&
            request.variables.credentialId === "pat-1",
        ),
      ).toBe(true);
    });
  });
});
