import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { TenantContext } from "@/components/app-shell/tenant-provider";
import { ActionAssignmentRuleCreateForm } from "@/components/guardrails/action-assignment-rule-create-form";
import { GLOBAL_TENANT, type TenantSelection } from "@/lib/tenant/context";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderForm(selection: TenantSelection) {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <TenantContext.Provider value={{ selection, setTenant: vi.fn() }}>
      <QueryClientProvider client={queryClient}>
        <ActionAssignmentRuleCreateForm onCancel={vi.fn()} onSaved={vi.fn()} />
      </QueryClientProvider>
    </TenantContext.Provider>,
  );
}

async function selectOption(label: RegExp, option: string) {
  const user = userEvent.setup();
  await user.click(screen.getByLabelText(label));
  await user.click(await screen.findByRole("option", { name: option }));
}

function createMutationVariables() {
  const call = mocks.graphqlClient.mock.calls.find(([arg]) =>
    String(arg.query).includes("mutation CreateActionAssignmentRule"),
  );
  return call?.[0].variables;
}

function actionsQueryVariables() {
  const call = mocks.graphqlClient.mock.calls.find(([arg]) =>
    String(arg.query).includes("query ActionAssignmentRuleFormActions"),
  );
  return call?.[0].variables;
}

describe("ActionAssignmentRuleCreateForm", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    vi.stubGlobal(
      "ResizeObserver",
      class ResizeObserver {
        observe() {}
        unobserve() {}
        disconnect() {}
      },
    );
    if (!Element.prototype.hasPointerCapture) {
      Element.prototype.hasPointerCapture = () => false;
    }
    if (!Element.prototype.setPointerCapture) {
      Element.prototype.setPointerCapture = () => {};
    }
    if (!Element.prototype.releasePointerCapture) {
      Element.prototype.releasePointerCapture = () => {};
    }
    if (!Element.prototype.scrollIntoView) {
      Element.prototype.scrollIntoView = () => {};
    }
    mocks.graphqlClient.mockImplementation(({ query }) => {
      if (String(query).includes("ActionAssignmentRuleFormActions")) {
        return Promise.resolve({
          actions: {
            items: [{ id: "action-manage", name: "manage", description: null }],
          },
        });
      }
      if (String(query).includes("CreateActionAssignmentRule")) {
        return Promise.resolve({
          createActionAssignmentRule: {
            id: "rule-1",
            tenantId: null,
            entityKind: "device",
            actionName: "manage",
            objectKind: "resource",
            objectType: null,
            decision: "allow",
            isAbsolute: false,
            createdAt: "2026-01-01T00:00:00Z",
          },
        });
      }
      return Promise.resolve({});
    });
  });

  it("does not expose require_override in the create decision selector", async () => {
    renderForm({ id: GLOBAL_TENANT, name: "Global" });

    const user = userEvent.setup();
    await user.click(screen.getByLabelText(/decision/i));

    expect(screen.getByRole("option", { name: "allow" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "deny" })).toBeInTheDocument();
    expect(screen.queryByText("require_override")).not.toBeInTheDocument();
  });

  it("submits global guardrails with a null tenantId", async () => {
    renderForm({ id: GLOBAL_TENANT, name: "Global" });

    const user = userEvent.setup();
    await selectOption(/action_name/i, "manage");
    await user.click(screen.getByRole("button", { name: "Create guardrail" }));

    await waitFor(() => {
      expect(createMutationVariables()).toMatchObject({
        input: {
          tenantId: null,
          entityKind: "device",
          actionName: "manage",
          objectKind: "resource",
          decision: "allow",
          isAbsolute: false,
        },
      });
    });
  });

  it("shows global scope and loads global actions in global context", async () => {
    renderForm({ id: GLOBAL_TENANT, name: "Global" });

    expect(screen.getByText("Scope")).toBeInTheDocument();
    expect(screen.getByText("Platform")).toBeInTheDocument();
    expect(screen.getByText("Global")).toBeInTheDocument();
    await waitFor(() => {
      expect(actionsQueryVariables()).toEqual({ tenantId: null });
    });
  });

  it("shows tenant scope and loads tenant actions in tenant context", async () => {
    renderForm({ id: "tenant-1", name: "Tenant 1" });

    expect(screen.getByText("Scope")).toBeInTheDocument();
    expect(screen.getByText("Tenant")).toBeInTheDocument();
    expect(screen.getByText("Tenant 1")).toBeInTheDocument();
    await waitFor(() => {
      expect(actionsQueryVariables()).toEqual({ tenantId: "tenant-1" });
    });
  });

  it("submits tenant guardrails with the selected tenantId and deny decision", async () => {
    renderForm({ id: "tenant-1", name: "Tenant 1" });

    const user = userEvent.setup();
    await selectOption(/action_name/i, "manage");
    await user.click(screen.getByRole("button", { name: "Create guardrail" }));

    await waitFor(() => {
      expect(createMutationVariables()).toMatchObject({
        input: {
          tenantId: "tenant-1",
          actionName: "manage",
          decision: "deny",
          isAbsolute: false,
        },
      });
    });
  });
});
