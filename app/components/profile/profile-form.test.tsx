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
  accessTokens: {
    items: [
      {
        credentialId: "tok-1",
        name: "Laptop CLI",
        description: "Local scripts",
        identifier: "atom_abcdef12",
        status: "active",
        scoped: true,
        permissions: [
          {
            actions: ["read"],
            scopeMode: "object_kind",
            tenantId: null,
            objectKind: "entity",
            objectType: null,
            objectId: null,
          },
        ],
        expiresAt: null,
        createdAt: "2026-06-05T00:00:00Z",
      },
    ],
    total: 1,
  },
};

describe("ProfileForm access tokens", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    // Radix Select relies on pointer-capture and layout APIs jsdom omits.
    vi.stubGlobal(
      "ResizeObserver",
      class {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
    Element.prototype.hasPointerCapture ??= () => false;
    Element.prototype.setPointerCapture ??= () => {};
    Element.prototype.releasePointerCapture ??= () => {};
    Element.prototype.scrollIntoView ??= () => {};

    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockImplementation(async ({ query }) => {
      if (query.includes("ProfileEntity")) return profileResponse;
      if (query.includes("ProfileAccessTokens")) return tokensResponse;
      if (query.includes("CreateAccessToken")) {
        return {
          createAccessToken: {
            credentialId: "tok-created",
            token: "atom_created_access_token",
            name: "CI runner",
            description: "Build scripts",
            expiresAt: null,
          },
        };
      }
      if (query.includes("RevokeAccessToken")) {
        return { revokeAccessToken: true };
      }
      if (query.includes("ReplaceAccessTokenPermissions")) {
        return { replaceAccessTokenPermissions: true };
      }
      return {};
    });
  });

  it("lists access tokens with their permission summary", async () => {
    renderProfileForm();

    expect(await screen.findByText("Access Tokens")).toBeInTheDocument();
    expect(await screen.findByText("Laptop CLI")).toBeInTheDocument();
    expect(screen.getByText("Local scripts")).toBeInTheDocument();
    expect(screen.getByText("atom_abcdef12")).toBeInTheDocument();
    expect(screen.getByText("read on kind entity")).toBeInTheDocument();
  });

  it("creates a token with permissions and without an entity id", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await screen.findByText("Access Tokens");
    await user.type(screen.getByLabelText("Name"), "CI runner");
    await user.type(screen.getByLabelText("Description"), "Build scripts");
    await user.type(screen.getByLabelText("Actions"), "read");
    await user.click(screen.getByLabelText("Object kind"));
    await user.click(screen.getByRole("option", { name: "entity" }));
    await user.click(screen.getByRole("button", { name: "Create token" }));

    expect(
      await screen.findByText("atom_created_access_token"),
    ).toBeInTheDocument();
    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(([request]) => {
          if (!request.query.includes("CreateAccessToken")) return false;
          const input = request.variables.input;
          return (
            input.name === "CI runner" &&
            request.variables.entityId === undefined &&
            Array.isArray(input.permissions) &&
            input.permissions[0].actions[0] === "read" &&
            input.permissions[0].scopeMode === "object_kind" &&
            input.permissions[0].objectKind === "entity"
          );
        }),
      ).toBe(true);
    });
  });

  it("blocks creation when no permission action is given", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await screen.findByText("Access Tokens");
    await user.type(screen.getByLabelText("Name"), "no-perms");
    await user.click(screen.getByRole("button", { name: "Create token" }));

    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(([request]) =>
          request.query.includes("CreateAccessToken"),
        ),
      ).toBe(false);
    });
  });

  it("replaces an existing token's permissions in place", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await user.click(
      await screen.findByRole("button", { name: "Edit permissions" }),
    );

    // The create form also has an Actions field; the editor's is the last one.
    const actionsFields = screen.getAllByLabelText("Actions");
    const actions = actionsFields[actionsFields.length - 1];
    if (!actions) {
      throw new Error("expected an Actions field in the permission editor");
    }
    await user.clear(actions);
    await user.type(actions, "manage");
    await user.click(screen.getByRole("button", { name: "Save permissions" }));

    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(([request]) => {
          if (!request.query.includes("ReplaceAccessTokenPermissions")) {
            return false;
          }
          return (
            request.variables.credentialId === "tok-1" &&
            request.variables.permissions[0].actions[0] === "manage"
          );
        }),
      ).toBe(true);
    });
  });

  it("revokes an access token by credential id", async () => {
    const user = userEvent.setup();
    renderProfileForm();

    await user.click(await screen.findByRole("button", { name: "Revoke" }));

    await waitFor(() => {
      expect(
        mocks.graphqlClient.mock.calls.some(
          ([request]) =>
            request.query.includes("RevokeAccessToken") &&
            request.variables.credentialId === "tok-1",
        ),
      ).toBe(true);
    });
  });
});
