import { describe, expect, it } from "vitest";

import openaiSchema from "./fixtures/openai-credential-schema.json";
import templateSchema from "./fixtures/template-credential-schema.json";
import unionSchema from "./fixtures/union-credential-schema.json";
import {
  parseRegistryCredentialSchema,
  parseRegistryCredentialVariants,
  REGISTRY_CREDENTIAL_SCHEMA_LIMITS,
} from "./provider-credential-schema";

const schema = {
  type: "object",
  properties: {
    api_key: {
      title: "API Key",
      description: "The key.",
      type: "string",
      format: "password",
      writeOnly: true,
    },
    scheme: {
      title: "Scheme",
      type: "string",
      enum: ["bearer", "basic"],
      default: "bearer",
    },
    notes: {
      title: "Notes",
      type: "string",
      "x-prowler-widget": "textarea",
      default: "",
    },
  },
  required: ["api_key"],
};

describe("parseRegistryCredentialSchema", () => {
  it("accepts the installed Template 0.2.5 schema with typed fields and examples", () => {
    // Given / When
    const result = parseRegistryCredentialSchema(templateSchema);

    // Then
    expect(result?.fields.map(({ name, kind }) => [name, kind])).toEqual([
      ["api_url", "text"],
      ["api_key", "password"],
      ["ca_bundle", "textarea"],
      ["verify_tls", "checkbox"],
      ["timeout_seconds", "integer"],
      ["auth_scheme", "select"],
    ]);
    expect(result?.fields[0]).toMatchObject({
      placeholder: "https://api.acme.com",
      required: true,
    });
    expect(result?.fields[3].defaultValue).toBe(true);
    expect(result?.fields[4]).toMatchObject({
      defaultValue: 30,
      minimum: 1,
      maximum: 300,
    });
  });
  it.each([
    "api_key",
    "platform_api_key",
    "platform-api-key",
    "apiKey",
    "platformApiKey",
    "platformAPIKey",
    "API_KEY",
    "apikey",
  ])("masks the plain API key field %s without schema annotations", (name) => {
    // Given / When
    const result = parseRegistryCredentialSchema({
      type: "object",
      properties: { [name]: { type: "string" } },
    });

    // Then
    expect(result?.fields[0].kind).toBe("password");
  });

  it("keeps identifiers and explicitly configured widgets unchanged", () => {
    // Given / When
    const result = parseRegistryCredentialSchema({
      type: "object",
      properties: {
        api_key_id: { type: "string" },
        api_key_url: { type: "string" },
        selected_api_key: { type: "string", enum: ["primary", "secondary"] },
        multiline_api_key: { type: "string", "x-prowler-widget": "textarea" },
      },
    });

    // Then
    expect(result?.fields.map(({ kind }) => kind)).toEqual([
      "text",
      "text",
      "select",
      "textarea",
    ]);
  });

  it("accepts the installed OpenAI schema with its full description", () => {
    // Given / When: the materialized OpenAI 0.1.5 schema contains a long docstring.
    const result = parseRegistryCredentialSchema(openaiSchema);

    // Then
    expect(result?.fields.map(({ name }) => name)).toEqual([
      "organization_id",
      "platform_api_key",
      "base_url",
    ]);
    expect(result?.fields[2].defaultValue).toBe("https://api.openai.com/v1");
    expect(result?.fields.map(({ kind }) => kind)).toEqual([
      "text",
      "password",
      "text",
    ]);
  });

  it("preserves long field descriptions without treating them as input limits", () => {
    // Given
    const description = openaiSchema.description;

    // When
    const result = parseRegistryCredentialSchema({
      ...schema,
      properties: { token: { type: "string", description } },
      required: ["token"],
    });

    // Then
    expect(result?.fields[0].description).toBe(description);
  });

  it("accepts the observed flat credential schema and preserves property order", () => {
    // Given
    const result = parseRegistryCredentialSchema(schema);

    // When / Then

    expect(result?.fields.map(({ name, kind }) => [name, kind])).toEqual([
      ["api_key", "password"],
      ["scheme", "select"],
      ["notes", "textarea"],
    ]);

    expect(result?.fields[0]).toMatchObject({
      description: "The key.",
      label: "API Key",
      required: true,
    });
  });

  it.each([
    ["$ref", { $ref: "#/$defs/credential" }],
    ["$defs", { $defs: {} }],
    ["definitions", { definitions: {} }],
    ["combinators", { anyOf: [] }],
    ["additional properties", { additionalProperties: true }],
    ["typed additional properties", { additionalProperties: {} }],
  ])("rejects risky root keywords: %s", (_name, keyword) => {
    expect(parseRegistryCredentialSchema({ ...schema, ...keyword })).toBeNull();
  });

  it("accepts the closed object pydantic emits for extra='forbid'", () => {
    // Given / When
    const result = parseRegistryCredentialSchema({
      ...schema,
      additionalProperties: false,
    });

    // Then
    expect(result).toEqual(parseRegistryCredentialSchema(schema));
  });

  it.each([
    ["nested objects", { type: "object", properties: {} }],
    ["arrays", { type: "array" }],
    ["nullable unions", { type: ["string", "null"] }],
    ["unsupported formats", { type: "string", format: "email" }],
    ["passwords without writeOnly", { type: "string", format: "password" }],
    ["maps", { type: "string", additionalProperties: true }],
  ])("rejects unsupported fields: %s", (_name, apiKey) => {
    expect(
      parseRegistryCredentialSchema({
        ...schema,
        properties: { ...schema.properties, api_key: apiKey },
      }),
    ).toBeNull();
  });

  it.each([
    { type: "boolean", default: "true" },
    { type: "boolean", enum: [true] },
    { type: "integer", default: "30" },
    { type: "integer", default: 1.5 },
    { type: "integer", minimum: 1, default: 0 },
    { type: "integer", maximum: 300, default: 301 },
    { type: "integer", minimum: 10, maximum: 1 },
    { type: "integer", minimum: "1" },
    { type: "integer", maximum: Infinity },
    { type: "integer", multipleOf: 5 },
    { type: "string", examples: "not-an-array" },
    { type: "string", examples: [{ value: "unexpected" }] },
  ])(
    "rejects malformed annotations or unsupported constraints: %j",
    (property) => {
      expect(
        parseRegistryCredentialSchema({
          type: "object",
          properties: { field: property },
        }),
      ).toBeNull();
    },
  );

  it.each([
    [
      "invalid defaults",
      { type: "string", enum: ["bearer", "basic"], default: "token" },
    ],
    ["duplicate values", { type: "string", enum: ["bearer", "bearer"] }],
  ])("rejects enum definitions with %s", (_name, scheme) => {
    expect(
      parseRegistryCredentialSchema({
        ...schema,
        properties: { ...schema.properties, scheme },
      }),
    ).toBeNull();
  });

  it("rejects unsafe names, invalid required fields, and over-limit metadata", () => {
    // Given

    const fields = Object.fromEntries(
      Array.from(
        { length: REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_FIELDS + 1 },
        (_, index) => [`field${index}`, { type: "string" }],
      ),
    );

    const cases = [
      { ...schema, required: ["missing"] },
      { ...schema, description: { invalid: "not text" } },
      {
        ...schema,
        properties: { api_key: { type: "string", description: 123 } },
      },
      JSON.parse(
        '{"type":"object","properties":{"__proto__":{"type":"string"}}}',
      ),
      { type: "object", properties: fields },
      {
        ...schema,
        properties: {
          ...schema.properties,
          notes: {
            ...schema.properties.notes,
            title: "a".repeat(
              REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_TEXT_LENGTH + 1,
            ),
          },
        },
      },
    ];

    // When / Then

    expect(cases.map(parseRegistryCredentialSchema)).toEqual([
      null,
      null,
      null,
      null,
      null,
      null,
    ]);
  });
});

describe("parseRegistryCredentialVariants", () => {
  it("splits a pydantic union into variants that keep only their own fields", () => {
    // Given / When
    const result = parseRegistryCredentialVariants(unionSchema);

    // Then
    expect(
      result?.map(({ label, schema }) => [
        label,
        schema.fields.map(({ name, kind }) => [name, kind]),
      ]),
    ).toEqual([
      [
        "API token",
        [
          ["auth_method", "constant"],
          ["host", "text"],
          ["token", "password"],
        ],
      ],
      [
        "Username and password",
        [
          ["auth_method", "constant"],
          ["host", "text"],
          ["username", "text"],
          ["password", "password"],
        ],
      ],
    ]);
    expect(result?.[1].schema.fields[0].defaultValue).toBe("basic");
  });

  it("accepts anyOf, which pydantic emits for a union without discriminator", () => {
    // Given
    const { oneOf, discriminator: _discriminator, ...root } = unionSchema;

    // When
    const result = parseRegistryCredentialVariants({ ...root, anyOf: oneOf });

    // Then
    expect(result?.map(({ label }) => label)).toEqual([
      "API token",
      "Username and password",
    ]);
  });

  it.each([
    ["an unsupported variant", { oneOf: [templateSchema, { type: "array" }] }],
    ["no variants", { oneOf: [] }],
    ["variants that are not a list", { oneOf: templateSchema }],
    ["both combinators", { oneOf: [templateSchema], anyOf: [templateSchema] }],
    ["unknown root keywords", { oneOf: [templateSchema], $defs: {} }],
    [
      "a malformed discriminator",
      { oneOf: [templateSchema], discriminator: 1 },
    ],
    [
      "too many variants",
      {
        oneOf: Array.from(
          { length: REGISTRY_CREDENTIAL_SCHEMA_LIMITS.MAX_VARIANTS + 1 },
          () => templateSchema,
        ),
      },
    ],
  ])("rejects a union with %s", (_name, union) => {
    expect(parseRegistryCredentialVariants(union)).toBeNull();
  });

  it.each([
    { type: "string", const: "token", default: "basic" },
    { type: "string", const: "" },
    { type: "string", const: "token", enum: ["token"] },
    { type: "integer", const: 1 },
  ])("rejects a discriminator that is not one fixed string: %j", (property) => {
    expect(
      parseRegistryCredentialSchema({
        type: "object",
        properties: { auth_method: property },
      }),
    ).toBeNull();
  });

  it("returns a flat schema as its only variant", () => {
    // Given / When
    const result = parseRegistryCredentialVariants(templateSchema);

    // Then
    expect(result).toEqual([
      { schema: parseRegistryCredentialSchema(templateSchema) },
    ]);
  });
});
