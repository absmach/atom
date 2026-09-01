import { cleanup, render } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SessionRefresh } from "@/components/app-shell/session-refresh";

const mocks = vi.hoisted(() => ({
  refresh: vi.fn(),
  replace: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  useRouter: () => ({
    refresh: mocks.refresh,
    replace: mocks.replace,
  }),
}));

describe("SessionRefresh", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-06-29T00:00:00Z"));
    mocks.refresh.mockReset();
    mocks.replace.mockReset();
  });

  afterEach(() => {
    cleanup();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("refreshes the session before it expires", async () => {
    const fetch = vi.fn(async () =>
      Response.json({ expiresAt: "2026-06-29T01:00:00Z" }),
    );
    vi.stubGlobal("fetch", fetch);

    render(<SessionRefresh expiresAt="2026-06-29T00:10:00Z" />);

    await vi.advanceTimersByTimeAsync(5 * 60 * 1000 - 1);
    expect(fetch).not.toHaveBeenCalled();

    await vi.advanceTimersByTimeAsync(1);
    expect(fetch).toHaveBeenCalledWith("/api/auth/refresh", {
      credentials: "same-origin",
      method: "POST",
    });
    expect(mocks.replace).not.toHaveBeenCalled();
  });

  it("redirects to reauth when refresh reports an auth failure", async () => {
    const fetch = vi.fn(async () =>
      Response.json({ message: "session expired" }, { status: 401 }),
    );
    vi.stubGlobal("fetch", fetch);

    render(<SessionRefresh expiresAt="2026-06-29T00:10:00Z" />);

    await vi.advanceTimersByTimeAsync(5 * 60 * 1000);

    expect(mocks.replace).toHaveBeenCalledWith("/login?reauth=1");
    expect(mocks.refresh).toHaveBeenCalled();
  });
});
