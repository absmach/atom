import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { StatusBadge } from "@/components/crud/status-badge";

describe("StatusBadge", () => {
  it("renders status text", () => {
    render(<StatusBadge value="allow" />);
    expect(screen.getByText("allow")).toBeInTheDocument();
  });
});
