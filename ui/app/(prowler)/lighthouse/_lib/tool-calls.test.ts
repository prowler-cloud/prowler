import { describe, expect, it } from "vitest";

import {
  formatToolName,
  getToolCallContent,
  isToolCallError,
} from "./tool-calls";

describe("getToolCallContent", () => {
  it("should normalize the snake_case backend blob to camelCase", () => {
    // Given
    const content = {
      tool_call_id: "call_1",
      tool_name: "prowler_app_search_security_findings",
      arguments: { severity: "high" },
      result: { count: 3 },
      outcome: "success",
    };

    // When
    const parsed = getToolCallContent(content);

    // Then
    expect(parsed).toEqual({
      toolCallId: "call_1",
      toolName: "prowler_app_search_security_findings",
      arguments: { severity: "high" },
      result: { count: 3 },
      outcome: "success",
    });
  });

  it("should default missing optional fields without throwing", () => {
    // Given a blob with only the required tool_name
    const parsed = getToolCallContent({ tool_name: "search_tools" });

    // Then
    expect(parsed).toEqual({
      toolCallId: "",
      toolName: "search_tools",
      arguments: null,
      result: null,
      outcome: null,
    });
  });

  it("should return null for non-tool-call content", () => {
    expect(getToolCallContent(null)).toBeNull();
    expect(getToolCallContent("text")).toBeNull();
    expect(getToolCallContent({ text: "hi" })).toBeNull();
  });
});

describe("formatToolName", () => {
  it("should strip the prowler prefix and title-case", () => {
    expect(formatToolName("prowler_app_search_security_findings")).toBe(
      "Search security findings",
    );
    expect(formatToolName("prowler_hub_list_checks")).toBe("List checks");
  });

  it("should humanize prefix-less tools", () => {
    expect(formatToolName("search_tools")).toBe("Search tools");
  });
});

describe("isToolCallError", () => {
  it("should treat success and absent outcomes as non-errors", () => {
    expect(isToolCallError("success")).toBe(false);
    expect(isToolCallError(null)).toBe(false);
  });

  it("should treat any other outcome as an error", () => {
    expect(isToolCallError("timeout")).toBe(true);
    expect(isToolCallError("mcp_tool_error")).toBe(true);
  });
});
