import { describe, expect, it } from "vitest";
import { summarizePolicy } from "@/lib/policy/summary";

describe("summarizePolicy", () => {
  it("builds a human-readable policy sentence", () => {
    expect(
      summarizePolicy({
        effect: "allow",
        subjectKind: "group",
        subjectName: "devices in floor-sensors",
        grantKind: "action",
        grantName: "publish",
        scopeKind: "object_type",
        scopeRef: "resource:channel",
        conditions: [
          {
            path: "resource.attributes.env",
            operator: "equals",
            value: "prod",
          },
        ],
      }),
    ).toBe(
      "Allow devices in floor-sensors to publish on all resource:channel resources where resource.attributes.env=prod.",
    );
  });
});
