import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { renderCell } from "@/components/crud/table/cell-rendering";

describe("renderCell", () => {
  it("allows long values to wrap inside nowrap table cells", () => {
    const value = "channels:0046e4c4-cdf0-4702-a0bc-41d992f21802:admin";

    render(
      <table>
        <tbody>
          <tr>
            <td className="whitespace-nowrap">{renderCell(value, "name")}</td>
          </tr>
        </tbody>
      </table>,
    );

    expect(screen.getByText(value)).toHaveClass(
      "w-40",
      "whitespace-normal",
      "break-all",
    );
  });
});
