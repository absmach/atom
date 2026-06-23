import type { ColumnDef } from "@tanstack/react-table";
import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { DataTable } from "@/components/ui/data-table";

const mocks = vi.hoisted(() => ({
  replace: vi.fn(),
}));

vi.mock("next/navigation", () => ({
  usePathname: () => "/roles",
  useRouter: () => ({ replace: mocks.replace }),
  useSearchParams: () => new URLSearchParams(),
}));

type Row = {
  name: string;
};

const columns: ColumnDef<Row>[] = [
  {
    accessorKey: "name",
    header: "Name",
  },
];

describe("DataTable", () => {
  beforeEach(() => {
    mocks.replace.mockReset();
  });

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
});
