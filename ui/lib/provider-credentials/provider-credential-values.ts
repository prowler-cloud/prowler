import type {
  RegistryCredentialSchema,
  RegistryCredentialValue,
} from "./provider-credential-schema";

export function getCredentialDefaults(
  schema: RegistryCredentialSchema,
): Record<string, RegistryCredentialValue> {
  return Object.fromEntries(
    schema.fields.flatMap((field) =>
      field.defaultValue !== undefined
        ? [[field.name, field.defaultValue]]
        : field.kind === "checkbox" && field.required
          ? [[field.name, false]]
          : [],
    ),
  );
}

export function validateCredentialValues(
  schema: RegistryCredentialSchema,
  values: unknown,
):
  | {
      valid: true;
      secret: Record<string, RegistryCredentialValue>;
      errors: Record<string, string>;
    }
  | { valid: false; errors: Record<string, string> } {
  if (!values || typeof values !== "object" || Array.isArray(values))
    return {
      valid: false,
      errors: { _form: "Enter the required credentials." },
    };
  const entries = Object.entries(values);
  if (
    entries.some(
      ([name]) => !schema.fields.some((field) => field.name === name),
    )
  )
    return {
      valid: false,
      errors: { _form: "The credential fields have changed. Reload the form." },
    };
  const fields = new Map(entries);
  const errors: Record<string, string> = {};
  const secret: Record<string, RegistryCredentialValue> = {};
  for (const field of schema.fields) {
    const value = fields.get(field.name);
    if (value === undefined || (value === "" && field.kind !== "checkbox")) {
      if (field.required) errors[field.name] = `${field.label} is required`;
    } else if (field.kind === "checkbox") {
      if (typeof value !== "boolean") {
        errors[field.name] = `Enter a valid ${field.label}`;
      } else {
        secret[field.name] = value;
      }
    } else if (field.kind === "integer") {
      const number =
        typeof value === "string" && /^[+-]?\d+$/.test(value)
          ? Number(value)
          : value;
      if (
        typeof number !== "number" ||
        !Number.isSafeInteger(number) ||
        (field.minimum !== undefined && number < field.minimum) ||
        (field.maximum !== undefined && number > field.maximum)
      ) {
        errors[field.name] = `Enter a valid ${field.label}`;
      } else {
        secret[field.name] = number;
      }
    } else if (
      typeof value !== "string" ||
      (field.options && !field.options.includes(value))
    ) {
      errors[field.name] = `Enter a valid ${field.label}`;
    } else {
      secret[field.name] = value;
    }
  }
  return Object.keys(errors).length > 0
    ? { valid: false, errors }
    : { valid: true, secret, errors };
}
