const FIELD_KIND = {
  TEXT: "text",
  PASSWORD: "password",
  SELECT: "select",
  TEXTAREA: "textarea",
} as const;

export const REGISTRY_CREDENTIAL_SCHEMA_LIMITS = {
  MAX_FIELDS: 12,
  MAX_NAME_LENGTH: 50,
  MAX_TEXT_LENGTH: 200,
  MAX_ENUM_OPTIONS: 20,
} as const;

type FieldKind = (typeof FIELD_KIND)[keyof typeof FIELD_KIND];

export interface RegistryCredentialField {
  readonly name: string;
  readonly label: string;
  readonly description?: string;
  readonly kind: FieldKind;
  readonly options?: readonly string[];
  readonly required: boolean;
}

export interface RegistryCredentialSchema {
  readonly fields: readonly RegistryCredentialField[];
}

const ROOT = new Set("type title description properties required".split(" "));
const FIELD = new Set(
  "title description type format writeOnly enum default x-prowler-widget".split(
    " ",
  ),
);
const FORBIDDEN_NAMES = new Set(["__proto__", "prototype", "constructor"]);
const FIELD_NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === "object" &&
    value !== null &&
    !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype
  );
}

function isText(value: unknown, allowEmpty = false): value is string {
  return (
    typeof value === "string" &&
    value.length <= REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_TEXT_LENGTH &&
    (allowEmpty || value.length > 0)
  );
}

function hasOnly(
  record: Record<string, unknown>,
  allowed: Set<string>,
): boolean {
  for (const key in record) {
    if (Object.hasOwn(record, key) && !allowed.has(key)) return false;
  }
  return true;
}

export function parseRegistryCredentialSchema(
  value: unknown,
): RegistryCredentialSchema | null {
  if (!isRecord(value) || !hasOnly(value, ROOT) || value.type !== "object") {
    return null;
  }
  if (
    (value.title !== undefined && !isText(value.title)) ||
    (value.description !== undefined && !isText(value.description))
  ) {
    return null;
  }

  const properties = value.properties;
  if (!isRecord(properties)) return null;
  const entries: [string, unknown][] = [];
  for (const name in properties) {
    if (!Object.hasOwn(properties, name)) continue;
    if (entries.length === REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_FIELDS)
      return null;
    entries.push([name, properties[name]]);
  }

  const required = value.required ?? [];
  if (
    !Array.isArray(required) ||
    required.length > entries.length ||
    !required.every((name) => typeof name === "string")
  ) {
    return null;
  }
  const requiredNames = new Set(required);
  if (
    requiredNames.size !== required.length ||
    required.some((name) => !Object.hasOwn(properties, name))
  ) {
    return null;
  }

  const fields: RegistryCredentialField[] = [];
  for (const [name, property] of entries) {
    if (
      FORBIDDEN_NAMES.has(name) ||
      !FIELD_NAME.test(name) ||
      name.length > REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_NAME_LENGTH ||
      !isRecord(property) ||
      !hasOnly(property, FIELD) ||
      property.type !== "string"
    ) {
      return null;
    }

    const label = property.title ?? name;
    const description = property.description;
    const format = property.format;
    const widget = property["x-prowler-widget"];
    const defaultValue = property.default;
    const options = property.enum;
    const password = format === "password" && property.writeOnly === true;
    if (
      !isText(label) ||
      (description !== undefined && !isText(description)) ||
      ((format !== undefined || property.writeOnly !== undefined) &&
        !password) ||
      (widget !== undefined && widget !== "textarea") ||
      (defaultValue !== undefined && !isText(defaultValue, true))
    ) {
      return null;
    }

    if (options !== undefined) {
      if (
        format !== undefined ||
        widget !== undefined ||
        property.writeOnly !== undefined ||
        !Array.isArray(options) ||
        options.length === 0 ||
        options.length > REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_ENUM_OPTIONS ||
        !options.every((option) => isText(option)) ||
        new Set(options).size !== options.length ||
        (defaultValue !== undefined && !options.includes(defaultValue))
      ) {
        return null;
      }
      fields.push({
        name,
        label,
        ...(description ? { description } : {}),
        kind: FIELD_KIND.SELECT,
        options,
        required: requiredNames.has(name),
      });
      continue;
    }

    if (
      widget !== undefined &&
      (format !== undefined || property.writeOnly !== undefined)
    ) {
      return null;
    }
    fields.push({
      name,
      label,
      ...(description ? { description } : {}),
      kind: password
        ? FIELD_KIND.PASSWORD
        : widget === "textarea"
          ? FIELD_KIND.TEXTAREA
          : FIELD_KIND.TEXT,
      required: requiredNames.has(name),
    });
  }
  return { fields };
}
