import type { StructuredTool } from "@langchain/core/tools";
import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getMCPTools, isMCPAvailable } from "@/lib/lighthouse/mcp-client";

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
  async ({ toolName }) => {
    const allTools = getAllTools();

    if (allTools.length === 0) {
      return {
        found: false,
        message: "No tools available. MCP server may not be connected.",
      };
    }

    // Find exact tool by name
    const targetTool = allTools.find((tool) => tool.name === toolName);

    if (!targetTool) {
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
    description: `Get the full schema and parameter details for a specific Prowler Hub tool.

Use this to understand what parameters a tool requires before executing it.
Tool names are listed in your system prompt - use the exact name.

You must always provide the toolName key in the JSON object.
Example: describe_tool({ "toolName": "prowler_hub_list_providers" })

Returns:
- Full parameter schema with types and descriptions
- Tool description
- Required vs optional parameters`,
    schema: z.object({
      toolName: z
        .string()
        .describe(
          "Exact name of the tool to describe (e.g., 'prowler_hub_list_providers'). You must always provide the toolName key in the JSON object.",
        ),
    }),
  },
);

/**
 * Execute a tool with parameters
 */
export const executeTool = tool(
  async ({ toolName, toolInput }) => {
    const allTools = getAllTools();
    const targetTool = allTools.find((tool) => tool.name === toolName);

    if (!targetTool) {
      return {
        error: `Tool '${toolName}' not found. Use describe_tool to check available tools.`,
        suggestion:
          "Check the tool list in your system prompt for exact tool names. You must always provide the toolName key in the JSON object.",
      };
    }

    try {
      // Use undefined for empty inputs, otherwise use the provided input
      const input =
        !toolInput || Object.keys(toolInput).length === 0
          ? undefined
          : toolInput;

      // Execute the tool directly - let errors propagate so LLM can handle retries
      const result = await targetTool.invoke(input);

      return {
        success: true,
        toolName,
        result,
      };
    } catch (error) {
      return {
        error: `Failed to execute '${toolName}': ${error instanceof Error ? error.message : String(error)}`,
        toolName,
        toolInput,
      };
    }
  },
  {
    name: "execute_tool",
    description: `Execute a Prowler Hub MCP tool with the specified parameters.

Provide the exact tool name and its input parameters as specified in the tool's schema.

You must always provide the toolName and toolInput keys in the JSON object.
Example: execute_tool({ "toolName": "prowler_hub_list_providers", "toolInput": {} })

All input to the tool must be provided in the toolInput key as a JSON object.
Example: execute_tool({ "toolName": "prowler_hub_list_providers", "toolInput": { "query": "value1", "page": 1, "pageSize": 10 } })

Always describe the tool first to understand:
1. What parameters it requires
2. The expected input format
3. Required vs optional parameters`,
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
          "Input parameters for the tool as a JSON object. Use empty object {} if tool requires no parameters.",
        ),
    }),
  },
);
