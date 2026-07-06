import type { LighthouseV2ToolCallContent } from "@/app/(prowler)/lighthouse/_types";

// Prefixes shared by the MCP-sourced tools; stripped for display so a name like
// `prowler_app_search_security_findings` reads as "Search security findings".
const TOOL_NAME_PREFIXES = [
  "prowler_app_",
  "prowler_hub_",
  "prowler_docs_",
] as const;

// Reads the snake_case TOOL_CALL blob the backend persists and normalizes it to
// the camelCase UI shape. Returns null when `content` isn't a tool-call object.
export function getToolCallContent(
  content: unknown,
): LighthouseV2ToolCallContent | null {
  if (typeof content !== "object" || content === null) {
    return null;
  }
  const record = content as Record<string, unknown>;
  if (typeof record.tool_name !== "string") {
    return null;
  }
  return {
    toolCallId:
      typeof record.tool_call_id === "string" ? record.tool_call_id : "",
    toolName: record.tool_name,
    arguments: record.arguments ?? null,
    result: record.result ?? null,
    outcome: typeof record.outcome === "string" ? record.outcome : null,
  };
}

// Turns a raw tool name into a human label by dropping the known prefix and
// title-casing, e.g. `prowler_hub_list_checks` -> "List checks". A humanizer
// (not a hardcoded map) keeps this in sync as the MCP tool whitelist grows.
export function formatToolName(toolName: string): string {
  const prefix = TOOL_NAME_PREFIXES.find((value) => toolName.startsWith(value));
  const stripped = prefix ? toolName.slice(prefix.length) : toolName;
  const words = stripped.replace(/_/g, " ").trim();
  if (!words) {
    return toolName;
  }
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// A tool call succeeded when its outcome is absent or the literal "success";
// any other outcome is an error surfaced to the user.
export function isToolCallError(outcome: string | null): boolean {
  return outcome !== null && outcome.toLowerCase() !== "success";
}
