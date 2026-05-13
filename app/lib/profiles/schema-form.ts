export type JsonSchema = {
  type?: string;
  title?: string;
  description?: string;
  required?: string[];
  properties?: Record<string, JsonSchema>;
  enum?: string[];
  default?: unknown;
};

export type UiSchema = {
  "ui:order"?: string[];
  [key: string]: unknown;
};

export type SchemaField = {
  name: string;
  label: string;
  type: "text" | "textarea" | "number" | "checkbox" | "select" | "json";
  required: boolean;
  description?: string;
  placeholder?: string;
  options?: string[];
  defaultValue?: unknown;
};

export function fieldsFromSchema(
  schema: JsonSchema,
  uiSchema: UiSchema = {},
): SchemaField[] {
  const required = new Set(schema.required ?? []);
  const properties = schema.properties ?? {};
  return orderedPropertyEntries(properties, uiSchema["ui:order"]).map(
    ([name, property]) => {
      const ui = fieldUiSchema(uiSchema, name);
      return {
        name,
        label: uiString(ui, "ui:title") ?? property.title ?? titleize(name),
        type: uiFieldType(ui) ?? fieldType(property),
        required: required.has(name),
        description:
          uiString(ui, "ui:description") ??
          uiString(ui, "ui:help") ??
          property.description,
        placeholder: uiString(ui, "ui:placeholder"),
        options: property.enum,
        defaultValue: property.default,
      };
    },
  );
}

function fieldType(schema: JsonSchema): SchemaField["type"] {
  if (schema.enum?.length) {
    return "select";
  }
  switch (schema.type) {
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "checkbox";
    case "string":
      return "text";
    default:
      return "json";
  }
}

function orderedPropertyEntries(
  properties: Record<string, JsonSchema>,
  order: string[] = [],
) {
  const entries = Object.entries(properties);
  const byName = new Map(entries);
  const ordered = order
    .filter((name) => name !== "*" && byName.has(name))
    .map((name) => [name, byName.get(name)] as [string, JsonSchema]);
  const orderedNames = new Set(ordered.map(([name]) => name));
  const rest = entries.filter(([name]) => !orderedNames.has(name));
  const wildcardIndex = order.indexOf("*");

  if (wildcardIndex === -1) {
    return [...ordered, ...rest];
  }

  const beforeWildcard = order
    .slice(0, wildcardIndex)
    .filter((name) => byName.has(name))
    .map((name) => [name, byName.get(name)] as [string, JsonSchema]);
  const beforeNames = new Set(beforeWildcard.map(([name]) => name));
  const afterWildcard = order
    .slice(wildcardIndex + 1)
    .filter((name) => byName.has(name))
    .map((name) => [name, byName.get(name)] as [string, JsonSchema]);
  const afterNames = new Set(afterWildcard.map(([name]) => name));
  const middle = entries.filter(
    ([name]) => !beforeNames.has(name) && !afterNames.has(name),
  );

  return [...beforeWildcard, ...middle, ...afterWildcard];
}

function fieldUiSchema(uiSchema: UiSchema, name: string): UiSchema {
  const ui = uiSchema[name];
  return ui && typeof ui === "object" && !Array.isArray(ui)
    ? (ui as UiSchema)
    : {};
}

function uiString(ui: UiSchema, key: string) {
  const value = ui[key];
  return typeof value === "string" ? value : undefined;
}

function uiFieldType(ui: UiSchema): SchemaField["type"] | undefined {
  switch (uiString(ui, "ui:widget")) {
    case "textarea":
      return "textarea";
    case "checkbox":
      return "checkbox";
    case "select":
      return "select";
    case "number":
      return "number";
    case "text":
    case "password":
    case "email":
    case "uri":
      return "text";
    default:
      return undefined;
  }
}

function titleize(value: string) {
  return value
    .replaceAll("_", " ")
    .replaceAll("-", " ")
    .replace(/\b\w/g, (char) => char.toUpperCase());
}
