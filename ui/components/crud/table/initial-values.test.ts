import { describe, expect, it } from "vitest";
import {
  entityFormInitialValues,
  groupFormInitialValues,
  resourceFormInitialValues,
} from "@/components/crud/table/initial-values";

describe("alias form initial values", () => {
  it("loads entity aliases and external IDs for editing", () => {
    const values = entityFormInitialValues({
      id: "entity-1",
      name: "Sensor",
      alias: "sensor-01",
      externalId: "SN-001",
      kind: "device",
    });

    expect(values.alias).toBe("sensor-01");
    expect(values.externalId).toBe("SN-001");
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

  it("uses an empty external ID when the entity row has none", () => {
    expect(entityFormInitialValues({ id: "entity-1" }).externalId).toBe("");
  });
});

describe("group form initial values", () => {
  it("loads group type for editing", () => {
    expect(
      groupFormInitialValues({
        id: "group-1",
        name: "Operators",
        groupType: "principal",
      }).groupType,
    ).toBe("principal");
  });

  it("defaults missing group type to object", () => {
    expect(groupFormInitialValues({ id: "group-1" }).groupType).toBe("object");
  });
});
