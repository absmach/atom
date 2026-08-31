import { describe, expect, it } from "vitest";
import { fieldsFromSchema } from "@/lib/profiles/schema-form";

describe("fieldsFromSchema", () => {
  it("maps basic JSON Schema properties to form fields", () => {
    expect(
      fieldsFromSchema({
        type: "object",
        required: ["name"],
        properties: {
          name: { type: "string" },
          env: { type: "string", enum: ["prod", "dev"] },
          enabled: { type: "boolean" },
          limit: { type: "number" },
          metadata: { type: "object" },
        },
      }).map((field) => [field.name, field.type, field.required]),
    ).toEqual([
      ["name", "text", true],
      ["env", "select", false],
      ["enabled", "checkbox", false],
      ["limit", "number", false],
      ["metadata", "json", false],
    ]);
  });

  it("uses UI schema for presentation hints without adding fields", () => {
    expect(
      fieldsFromSchema(
        {
          type: "object",
          properties: {
            serial_no: { type: "string" },
            enabled: { type: "boolean" },
          },
        },
        {
          "ui:order": ["enabled", "serial_no"],
          serial_no: {
            "ui:title": "Serial",
            "ui:placeholder": "SN-001",
          },
          phantom: {
            "ui:title": "Ignored",
          },
        },
      ).map((field) => [field.name, field.label, field.placeholder]),
    ).toEqual([
      ["enabled", "Enabled", undefined],
      ["serial_no", "Serial", "SN-001"],
    ]);
  });
});
