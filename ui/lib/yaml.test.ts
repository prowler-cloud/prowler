import { describe, expect, it } from "vitest";

import { validateYaml } from "./yaml";

// The Scan Configuration editor (like the Mutelist editor) validates only YAML
// *syntax* on the client; the API validates the configuration values
// (ranges/enums) on create/update. These cover the syntax check the editor and
// `scanConfigurationFormSchema` rely on.
describe("validateYaml", () => {
  it("accepts a mapping with provider sections", () => {
    // When
    const result = validateYaml("aws:\n  max_unused_access_keys_days: 45");

    // Then
    expect(result.isValid).toBe(true);
  });

  it("accepts a key with no value yet (the `aws:` typing state)", () => {
    // When — `aws:` parses to { aws: null }, still a mapping
    const result = validateYaml("aws:");

    // Then
    expect(result.isValid).toBe(true);
  });

  it("rejects malformed YAML with a syntax error", () => {
    // When — unmatched bracket is invalid flow syntax
    const result = validateYaml("aws: [1, 2");

    // Then
    expect(result.isValid).toBe(false);
    expect(result.error).toBeTruthy();
  });

  it("rejects a top-level list (config must be a mapping)", () => {
    // When
    const result = validateYaml("- aws\n- azure");

    // Then
    expect(result.isValid).toBe(false);
  });

  it("rejects empty content", () => {
    // When
    const result = validateYaml("");

    // Then
    expect(result.isValid).toBe(false);
  });

  it("rejects a scalar (not a mapping)", () => {
    // When — a bare word parses to the string "aws", not a mapping
    const result = validateYaml("aws");

    // Then
    expect(result.isValid).toBe(false);
  });
});
