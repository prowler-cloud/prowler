import "server-only";

import type { StructuredTool } from "@langchain/core/tools";
import { tool } from "@langchain/core/tools";
import { addBreadcrumb, captureException } from "@sentry/nextjs";
import { z } from "zod";

import { getMCPTools, isMCPAvailable } from "@/lib/lighthouse/mcp-client";
import { isAllowedTool } from "@/lib/lighthouse/workflow";

/** Input type for describe_tool */
interface DescribeToolInput {
  toolName: string;
}

/** Input type for execute_tool */
interface ExecuteToolInput {
  toolName: string;
  toolInput: Record<string, unknown>;
}

/**
 * Get all available tools (MCP only)
 */
function getAllTools(): StructuredTool[] {
  if (!isMCPAvailable()) {
    return [];
  }
  return getMCPTools();
}

/**
 * Describe a tool by getting its full schema
 */
export const describeTool = tool(
  async ({ toolName }: DescribeToolInput) => {
    // Only allow whitelisted tools to be described
    if (!isAllowedTool(toolName)) {
      return {
        found: false,
        message: `Tool '${toolName}' is not available.`,
      };
    }

    const allTools = getAllTools();

    if (allTools.length === 0) {
      addBreadcrumb({
        category: "meta-tool",
        message: "describe_tool called but no tools available",
        level: "warning",
        data: { toolName },
      });

      return {
        found: false,
        message: "No tools available. MCP server may not be connected.",
      };
    }

    // Find exact tool by name
    const targetTool = allTools.find((t) => t.name === toolName);

    if (!targetTool) {
      addBreadcrumb({
        category: "meta-tool",
        message: `Tool not found: ${toolName}`,
        level: "info",
        data: { toolName, availableCount: allTools.length },
      });

      return {
        found: false,
        message: `Tool '${toolName}' not found.`,
        hint: "Check the tool list in the system prompt for exact tool names.",
        availableToolsCount: allTools.length,
      };
    }

    return {
      found: true,
      name: targetTool.name,
      description: targetTool.description || "No description available",
      schema: targetTool.schema
        ? JSON.stringify(targetTool.schema, null, 2)
        : "{}",
      message: "Tool schema retrieved. Use execute_tool to run it.",
    };
  },
  {
    name: "describe_tool",
    description: `Get the full schema and parameter details for a specific Prowler tool.

Use this to understand what parameters a tool requires before executing it.
Tool names are listed in your system prompt - use the exact name.

You must always provide the toolName key in the JSON object.
Example: describe_tool({ "toolName": "prowler_app_search_security_findings" })

Returns:
- Full parameter schema with types and descriptions
- Tool description
- Required and optional parameters`,
    schema: z.object({
      toolName: z
        .string()
        .describe(
          "Exact name of the tool to describe (e.g., 'prowler_hub_list_compliances'). You must always provide the toolName key in the JSON object.",
        ),
    }),
  },
);

/**
 * Execute a tool with parameters
 */
export const executeTool = tool(
  async ({ toolName, toolInput }: ExecuteToolInput) => {
    // Only allow whitelisted tools to be executed
    if (!isAllowedTool(toolName)) {
      addBreadcrumb({
        category: "meta-tool",
        message: `execute_tool: Non-whitelisted tool attempted: ${toolName}`,
        level: "warning",
        data: { toolName, toolInput },
      });

      return {
        error: `Tool '${toolName}' is not available for execution.`,
        suggestion:
          "This operation must be performed through the Prowler UI directly.",
      };
    }

    const allTools = getAllTools();
    const targetTool = allTools.find((t) => t.name === toolName);

    if (!targetTool) {
      addBreadcrumb({
        category: "meta-tool",
        message: `execute_tool: Tool not found: ${toolName}`,
        level: "warning",
        data: { toolName, toolInput },
      });

      return {
        error: `Tool '${toolName}' not found. Use describe_tool to check available tools.`,
        suggestion:
          "Check the tool list in your system prompt for exact tool names. You must always provide the toolName key in the JSON object.",
      };
    }

    try {
      // Use empty object for empty inputs, otherwise use the provided input
      const input =
        !toolInput || Object.keys(toolInput).length === 0 ? {} : toolInput;

      addBreadcrumb({
        category: "meta-tool",
        message: `Executing tool: ${toolName}`,
        level: "info",
        data: { toolName, hasInput: !!input },
      });

      // Execute the tool directly - let errors propagate so LLM can handle retries
      const result = await targetTool.invoke(input);

      return {
        success: true,
        toolName,
        result,
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);

      captureException(error, {
        tags: {
          component: "meta-tool",
          tool_name: toolName,
          error_type: "tool_execution_failed",
        },
        level: "error",
        contexts: {
          tool_execution: {
            tool_name: toolName,
            tool_input: JSON.stringify(toolInput),
          },
        },
      });

      return {
        error: `Failed to execute '${toolName}': ${errorMessage}`,
        toolName,
        toolInput,
      };
    }
  },
  {
    name: "execute_tool",
    description: `Execute a Prowler MCP tool with the specified parameters.

Provide the exact tool name and its input parameters as specified in the tool's schema.

You must always provide the toolName and toolInput keys in the JSON object.
Example: execute_tool({ "toolName": "prowler_app_search_security_findings", "toolInput": {} })

All input to the tool must be provided in the toolInput key as a JSON object.
Example: execute_tool({ "toolName": "prowler_hub_list_compliances", "toolInput": { "provider": ["aws"] } })

Always describe the tool first to understand:
1. What parameters it requires
2. The expected input format
3. Which parameters are mandatory and which are optional`,
    schema: z.object({
      toolName: z
        .string()
        .describe(
          "Exact name of the tool to execute (from system prompt tool list)",
        ),
      toolInput: z
        .record(z.string(), z.unknown())
        .default({})
        .describe(
          "Input parameters for the tool as a JSON object. Use empty object {} if tool requires no parameters or it has defined defaults or only optional parameters.",
        ),
    }),
  },
);
