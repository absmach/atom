import { describe, expect, it } from "vitest";
import {
  entityFormInitialValues,
  resourceFormInitialValues,
} from "@/components/crud/table/initial-values";

describe("alias form initial values", () => {
  it("loads entity aliases for editing", () => {
    const values = entityFormInitialValues({
      id: "entity-1",
      name: "Sensor",
      alias: "sensor-01",
      kind: "device",
    });

    expect(values.alias).toBe("sensor-01");
  });

  it("loads resource aliases for editing", () => {
    const values = resourceFormInitialValues({
      id: "resource-1",
      kind: "resource:channel",
      name: "Telemetry",
      alias: "telemetry",
    });

    expect(values.alias).toBe("telemetry");
  });

  it("uses an empty alias when the row has none", () => {
    expect(entityFormInitialValues({ id: "entity-1" }).alias).toBe("");
    expect(resourceFormInitialValues({ id: "resource-1" }).alias).toBe("");
  });
});
