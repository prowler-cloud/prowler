import { describe, expect, it } from "vitest";

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
