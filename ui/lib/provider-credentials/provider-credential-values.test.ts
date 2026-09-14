import { describe, expect, it } from "vitest";

import templateSchema from "./fixtures/template-credential-schema.json";
import { parseRegistryCredentialSchema } from "./provider-credential-schema";
import {
  getCredentialDefaults,
  validateCredentialValues,
} from "./provider-credential-values";

const schema = parseRegistryCredentialSchema({
  type: "object",
  properties: {
    token: { type: "string", format: "password", writeOnly: true },
    region: { type: "string", enum: ["eu", "us"], default: "eu" },
    notes: { type: "string", "x-prowler-widget": "textarea" },
  },
  required: ["token"],
})!;

describe("dynamic credential validation", () => {
  const template = () => parseRegistryCredentialSchema(templateSchema)!;
  const templateValues = {
    api_url: "https://api.example.test",
    api_key: "fixture-key-not-a-secret",
    verify_tls: false,
    timeout_seconds: "60",
  };

  it("preserves typed Template defaults and submits booleans and integers", () => {
    // Given / When / Then
    expect(getCredentialDefaults(template())).toEqual({
      ca_bundle: "",
      verify_tls: true,
      timeout_seconds: 30,
      auth_scheme: "bearer",
    });
    expect(validateCredentialValues(template(), templateValues)).toEqual({
      valid: true,
      secret: { ...templateValues, timeout_seconds: 60 },
      errors: {},
    });
  });

  it.each([1, 300, "1", "300"])("accepts timeout boundary %j", (timeout) => {
    expect(
      validateCredentialValues(template(), {
        ...templateValues,
        timeout_seconds: timeout,
      }),
    ).toMatchObject({
      valid: true,
      secret: { timeout_seconds: Number(timeout) },
    });
  });

  it.each([
    0,
    301,
    1.5,
    "1.5",
    " ",
    "1second",
    "0x10",
    true,
    null,
    Infinity,
    NaN,
  ])("rejects invalid Template timeouts: %j", (timeout) => {
    expect(
      validateCredentialValues(template(), {
        ...templateValues,
        timeout_seconds: timeout,
      }),
    ).toMatchObject({
      valid: false,
      errors: { timeout_seconds: expect.any(String) },
    });
  });

  it.each(["true", "false", 0, 1, null])(
    "rejects non-boolean TLS values: %j",
    (verifyTls) => {
      expect(
        validateCredentialValues(template(), {
          ...templateValues,
          verify_tls: verifyTls,
        }),
      ).toMatchObject({
        valid: false,
        errors: { verify_tls: expect.any(String) },
      });
    },
  );

  it("accepts false and zero for required fields without treating them as missing", () => {
    const requiredSchema = parseRegistryCredentialSchema({
      type: "object",
      properties: {
        enabled: { type: "boolean" },
        retries: { type: "integer" },
      },
      required: ["enabled", "retries"],
    })!;
    expect(getCredentialDefaults(requiredSchema)).toEqual({ enabled: false });
    expect(
      validateCredentialValues(requiredSchema, { enabled: false, retries: 0 }),
    ).toEqual({
      valid: true,
      secret: { enabled: false, retries: 0 },
      errors: {},
    });
    expect(validateCredentialValues(requiredSchema, {})).toMatchObject({
      valid: false,
      errors: { enabled: expect.any(String), retries: expect.any(String) },
    });
  });
  it("uses declared defaults and preserves credential bytes", () => {
    expect(getCredentialDefaults(schema)).toEqual({ region: "eu" });
    expect(
      validateCredentialValues(schema, { token: " secret ", region: "eu" }),
    ).toEqual({
      valid: true,
      secret: { token: " secret ", region: "eu" },
      errors: {},
    });
  });
  it.each([
    {},
    { token: "" },
    { token: "secret", region: "invalid" },
    { token: 12 },
    { token: "secret", extra: "hidden" },
  ])("rejects invalid or undeclared values: %j", (values) => {
    expect(validateCredentialValues(schema, values).valid).toBe(false);
  });
});
