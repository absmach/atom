import { describe, expect, it } from "vitest";
import { isDeletedRow } from "@/components/crud/table/utils";

describe("isDeletedRow", () => {
  it("treats a tombstone as deleted even when status is unchanged", () => {
    expect(
      isDeletedRow({
        id: "resource-1",
        status: "active",
        deletedAt: "2026-06-24T12:00:00Z",
      }),
    ).toBe(true);
  });

  it("treats deleted tenant status as deleted", () => {
    expect(isDeletedRow({ id: "tenant-1", status: "deleted" })).toBe(true);
  });

  it("keeps live rows mutable", () => {
    expect(isDeletedRow({ id: "entity-1", status: "inactive" })).toBe(false);
  });
});
