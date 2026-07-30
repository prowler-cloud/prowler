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

  // Users author these documents by hand in the Mutelist and Scan Configuration
  // editors, so anchors, aliases and merge keys are legitimate input the syntax
  // check must keep accepting across js-yaml upgrades (4.3.0 rewrote merge-key
  // handling for CVE-2026-59869).
  it("accepts anchors, aliases and merge keys", () => {
    // When
    const result = validateYaml(
      [
        "defaults: &defaults",
        "  max_unused_access_keys_days: 45",
        "aws:",
        "  <<: *defaults",
        "  max_console_access_days: 45",
      ].join("\n"),
    );

    // Then
    expect(result.isValid).toBe(true);
  });

  it("rejects a merge-key amplification document (CVE-2026-59869 shape)", () => {
    // Given — each mapping merges the previous one and adds a distinct key, so
    // merged-key copies grow quadratically (~45k total here). js-yaml 4.3.0
    // fixes the CVE by capping that work (maxTotalMergeKeys) and rejecting the
    // document; a vulnerable parser accepts it instead, turning the assertion
    // below red without relying on timing or suite timeouts.
    const chain = ["a0: &a0 { k0: 0 }"];
    for (let i = 1; i < 300; i++) {
      chain.push(`a${i}: &a${i} { <<: *a${i - 1}, k${i}: ${i} }`);
    }

    // When
    const result = validateYaml(chain.join("\n"));

    // Then
    expect(result.isValid).toBe(false);
    expect(result.error).toMatch(/merge keys/i);
  });
});
