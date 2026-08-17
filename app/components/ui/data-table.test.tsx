import type { ColumnDef } from "@tanstack/react-table";
import { cleanup, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DataTable } from "@/components/ui/data-table";

const mocks = vi.hoisted(() => ({
  replace: vi.fn(),
  searchParams: new URLSearchParams(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/roles",
  useRouter: () => ({ replace: mocks.replace }),
  useSearchParams: () => mocks.searchParams,
}));

type Row = {
  name: string;
  status?: string;
};

const columns: ColumnDef<Row>[] = [
  {
    accessorKey: "name",
    header: "Name",
  },
];

function rows(...names: string[]): Row[] {
  return names.map((name) => ({ name }));
}

/** The footer splits its counts across text nodes, so read the whole subtree. */
function footerText(container: HTMLElement) {
  return (container.textContent ?? "").replace(/\s+/g, " ");
}

describe("DataTable", () => {
  beforeEach(() => {
    mocks.replace.mockReset();
    mocks.searchParams = new URLSearchParams();
  });

  // vitest runs without `globals`, so testing-library never registers its own
  // auto-cleanup and roots would stay mounted past environment teardown.
  afterEach(cleanup);

  it("renders without looping when no filters are provided", () => {
    render(
      <DataTable
        columns={columns}
        data={[{ name: "atom-admin" }]}
        limit={10}
        page={1}
        paramKey="roles"
        total={1}
      />,
    );

    expect(screen.getByText("atom-admin")).toBeInTheDocument();
    expect(mocks.replace).not.toHaveBeenCalled();
  });

  it("renders visible labels for dropdown filters", () => {
    render(
      <DataTable
        columns={columns}
        data={[{ name: "sensor-gateway-01" }]}
        filters={[
          {
            key: "kind",
            label: "Kind",
            type: "select",
            options: [{ label: "Device", value: "device" }],
          },
          {
            key: "tenantId",
            label: "Tenant",
            type: "select",
            options: [{ label: "Factory A", value: "tenant-1" }],
          },
        ]}
        limit={10}
        page={1}
        paramKey="entities"
        statusFilter={{ enabled: true, options: ["active", "inactive"] }}
        total={1}
      />,
    );

    expect(screen.getByText("Status")).toBeInTheDocument();
    expect(screen.getByText("Kind")).toBeInTheDocument();
    expect(screen.getByText("Tenant")).toBeInTheDocument();
  });

  it("reports the full server total when no filter is active", () => {
    const { container } = render(
      <DataTable
        columns={columns}
        data={rows(...Array.from({ length: 20 }, (_, i) => `role-${i}`))}
        limit={20}
        page={1}
        paramKey="roles"
        total={350}
      />,
    );

    expect(footerText(container)).toContain("350 rows");
    expect(footerText(container)).toContain("Page 1 of 18");
  });

  it("counts the rows it filtered client-side instead of the unfiltered total", () => {
    // The backend has no text search for this resource, so the search narrows
    // the current page in the browser while `total` still counts every row.
    mocks.searchParams = new URLSearchParams("roles.q=needle");

    const { container } = render(
      <DataTable
        columns={columns}
        data={rows("needle", "haystack-1", "haystack-2")}
        limit={20}
        page={1}
        paramKey="roles"
        total={350}
      />,
    );

    expect(screen.getByText("needle")).toBeInTheDocument();
    expect(screen.queryByText("haystack-1")).not.toBeInTheDocument();
    expect(footerText(container)).toContain("1 row");
    expect(footerText(container)).not.toContain("350 rows");
    expect(footerText(container)).toContain("Page 1 of 1");
    expect(footerText(container)).not.toContain("Page 1 of 18");
  });

  it("keeps the server total when the backend applied the search", () => {
    mocks.searchParams = new URLSearchParams("roles.q=needle");

    const { container } = render(
      <DataTable
        columns={columns}
        data={rows("alpha", "beta")}
        limit={10}
        page={1}
        paramKey="roles"
        serverFilters={{ search: true }}
        total={12}
      />,
    );

    // Rows the backend matched survive even though they do not contain the
    // query themselves — re-filtering them here would drop valid matches.
    expect(screen.getByText("alpha")).toBeInTheDocument();
    expect(screen.getByText("beta")).toBeInTheDocument();
    expect(footerText(container)).toContain("12 rows");
    expect(footerText(container)).toContain("Page 1 of 2");
  });

  it("counts rows narrowed by a client-side status filter", () => {
    mocks.searchParams = new URLSearchParams("roles.status=active");

    const { container } = render(
      <DataTable
        columns={columns}
        data={[
          { name: "live", status: "active" },
          { name: "off-1", status: "disabled" },
          { name: "off-2", status: "disabled" },
        ]}
        limit={20}
        page={1}
        paramKey="roles"
        statusFilter={{ enabled: true, options: ["active", "disabled"] }}
        total={350}
      />,
    );

    expect(footerText(container)).toContain("1 row");
    expect(footerText(container)).not.toContain("350 rows");
  });

  it("clamps the displayed page once a client-side filter collapses the range", () => {
    mocks.searchParams = new URLSearchParams("roles.q=needle&roles.page=7");

    const { container } = render(
      <DataTable
        columns={columns}
        data={rows("needle", "haystack")}
        limit={20}
        page={7}
        paramKey="roles"
        total={350}
      />,
    );

    expect(footerText(container)).toContain("Page 1 of 1");
    expect(footerText(container)).not.toContain("Page 7 of 1");
  });
});
