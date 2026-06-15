import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SystemHealthPage } from "@/components/operations/system-health-page";

const mocks = vi.hoisted(() => ({
  graphqlClient: vi.fn(),
}));

vi.mock("@/lib/graphql/client", () => ({
  graphqlClient: mocks.graphqlClient,
}));

function renderSystemHealthPage() {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: { retry: false },
      mutations: { retry: false },
    },
  });

  return render(
    <QueryClientProvider client={queryClient}>
      <SystemHealthPage />
    </QueryClientProvider>,
  );
}

describe("SystemHealthPage", () => {
  afterEach(() => {
    cleanup();
  });

  beforeEach(() => {
    mocks.graphqlClient.mockReset();
    mocks.graphqlClient.mockResolvedValue({
      systemStatus: {
        status: "error",
        httpReady: { status: "error", message: "not ready" },
        grpcReady: {
          status: "error",
          message: "gRPC server exited on 127.0.0.1:8081: bind failed",
        },
        database: { status: "ok", message: "database reachable" },
        migrations: { status: "ok", message: "2 migrations applied" },
        signingKeys: { status: "ok", message: "signing keys loaded" },
        certificateIssuer: {
          status: "disabled",
          message: "certificate issuer disabled",
        },
        dbPool: {
          maxConnections: 20,
          minConnections: 0,
          acquireTimeoutSecs: 30,
          connectTimeoutSecs: 10,
          idleTimeoutSecs: 600,
          maxLifetimeSecs: 1800,
          size: 2,
          idle: 1,
        },
        signingKeyState: {
          configuredKeyId: "local:v1",
          encryptedCount: 2,
          plaintextCount: 0,
          totalCount: 2,
          plaintextAllowed: false,
        },
        auditRetention: {
          enabled: true,
          days: 365,
          cleanupIntervalSecs: 86_400,
          cleanupBatchSize: 5000,
          lastCleanup: null,
        },
        rateLimits: {
          enabled: true,
          trustedProxyCidrs: ["10.0.0.0/8"],
          policies: [
            {
              category: "graphql",
              maxRequests: 120,
              windowSecs: 60,
            },
          ],
        },
      },
    });
  });

  it("renders gRPC runtime errors from system status", async () => {
    renderSystemHealthPage();

    expect(await screen.findByText("gRPC")).toBeInTheDocument();
    expect(
      screen.getByText("gRPC server exited on 127.0.0.1:8081: bind failed"),
    ).toBeInTheDocument();
  });

  it("renders trusted proxy CIDRs from system status", async () => {
    renderSystemHealthPage();

    expect(await screen.findByText("Trusted proxies")).toBeInTheDocument();
    expect(screen.getByText("10.0.0.0/8")).toBeInTheDocument();
  });
});
