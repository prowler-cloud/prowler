import { describe, expect, it } from "vitest";

import {
  parseRegistryCredentialSchema,
  REGISTRY_CREDENTIAL_SCHEMA_LIMITS,
} from "./provider-credential-schema";

// prettier-ignore
const schema = { type: "object", properties: { api_key: { title: "API Key", description: "The key.", type: "string", format: "password", writeOnly: true }, scheme: { title: "Scheme", type: "string", enum: ["bearer", "basic"], default: "bearer" }, notes: { title: "Notes", type: "string", "x-prowler-widget": "textarea", default: "" } }, required: ["api_key"] };

describe("parseRegistryCredentialSchema", () => {
  it("accepts the observed flat credential schema and preserves property order", () => {
    // Given
    const result = parseRegistryCredentialSchema(schema);

    // When / Then
    // prettier-ignore
    expect(result?.fields.map(({ name, kind }) => [name, kind])).toEqual([["api_key", "password"], ["scheme", "select"], ["notes", "textarea"]]);
    // prettier-ignore
    expect(result?.fields[0]).toMatchObject({ description: "The key.", label: "API Key", required: true });
  });

  // prettier-ignore
  it.each([["$ref", { $ref: "#/$defs/credential" }], ["$defs", { $defs: {} }], ["definitions", { definitions: {} }], ["combinators", { anyOf: [] }], ["additional properties", { additionalProperties: true }]])("rejects risky root keywords: %s", (_name, keyword) => {
    expect(parseRegistryCredentialSchema({ ...schema, ...keyword })).toBeNull();
  });

  // prettier-ignore
  it.each([["nested objects", { type: "object", properties: {} }], ["arrays", { type: "array" }], ["booleans", { type: "boolean" }], ["nullable unions", { type: ["string", "null"] }], ["unsupported formats", { type: "string", format: "email" }], ["passwords without writeOnly", { type: "string", format: "password" }], ["maps", { type: "string", additionalProperties: true }]])("rejects unsupported fields: %s", (_name, apiKey) => {
    expect(parseRegistryCredentialSchema({ ...schema, properties: { ...schema.properties, api_key: apiKey } })).toBeNull();
  });

  // prettier-ignore
  it.each([["invalid defaults", { type: "string", enum: ["bearer", "basic"], default: "token" }], ["duplicate values", { type: "string", enum: ["bearer", "bearer"] }]])("rejects enum definitions with %s", (_name, scheme) => {
    expect(parseRegistryCredentialSchema({ ...schema, properties: { ...schema.properties, scheme } })).toBeNull();
  });

  it("rejects unsafe names, invalid required fields, and over-limit metadata", () => {
    // Given
    // prettier-ignore
    const fields = Object.fromEntries(Array.from({ length: REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_FIELDS + 1 }, (_, index) => [`field${index}`, { type: "string" }]));
    // prettier-ignore
    const cases = [{ ...schema, required: ["missing"] }, JSON.parse('{"type":"object","properties":{"__proto__":{"type":"string"}}}'), { type: "object", properties: fields }, { ...schema, properties: { ...schema.properties, notes: { ...schema.properties.notes, title: "a".repeat(REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_TEXT_LENGTH + 1) } } }];

    // When / Then
    // prettier-ignore
    expect(cases.map(parseRegistryCredentialSchema)).toEqual([null, null, null, null]);
  });
});
