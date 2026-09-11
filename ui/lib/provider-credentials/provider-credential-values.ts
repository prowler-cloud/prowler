import type { RegistryCredentialSchema } from "./provider-credential-schema";

export function getCredentialDefaults(
  schema: RegistryCredentialSchema,
): Record<string, string> {
  return Object.fromEntries(
    schema.fields.flatMap((field) =>
      field.defaultValue !== undefined
        ? [[field.name, field.defaultValue]]
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
      secret: Record<string, string>;
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
  const secret: Record<string, string> = {};
  for (const field of schema.fields) {
    const value = fields.get(field.name);
    if (value === undefined || value === "") {
      if (field.required) errors[field.name] = `${field.label} is required`;
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
