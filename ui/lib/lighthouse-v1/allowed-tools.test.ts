import { describe, expect, it } from "vitest";

import { isAllowedTool } from "./allowed-tools";

describe("isAllowedTool", () => {
  it("should accept a whitelisted tool using the current namespace", () => {
    // Given
    const toolName = "prowler_search_security_findings";

    // When
    const result = isAllowedTool(toolName);

    // Then
    expect(result).toBe(true);
  });

  it("should accept a whitelisted tool using the legacy namespace", () => {
    // Given
    const toolName = "prowler_app_search_security_findings";

    // When
    const result = isAllowedTool(toolName);

    // Then
    expect(result).toBe(true);
  });

  it("should reject a non-whitelisted tool after normalizing the legacy namespace", () => {
    // Given
    const toolName = "prowler_app_delete_provider";

    // When
    const result = isAllowedTool(toolName);

    // Then
    expect(result).toBe(false);
  });
});
