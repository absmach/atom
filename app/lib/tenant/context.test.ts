import { describe, expect, it } from "vitest";
import { tenantLabel, tenantQueryValue } from "@/lib/tenant/context";

describe("tenant helpers", () => {
  it("treats global as a null GraphQL tenant filter", () => {
    expect(tenantLabel({ id: "global", name: "Global" })).toBe("Global");
    expect(tenantQueryValue({ id: "global", name: "Global" })).toBeNull();
  });

  it("returns tenant ids for tenant-scoped filters", () => {
    expect(tenantLabel({ id: "t1", name: "factory-a" })).toBe("factory-a");
    expect(tenantQueryValue({ id: "t1", name: "factory-a" })).toBe("t1");
  });
});
