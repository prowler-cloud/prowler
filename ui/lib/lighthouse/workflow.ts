import { createAgent } from "langchain";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import type { ProviderType } from "@/lib/lighthouse/llm-factory";
import { createLLM } from "@/lib/lighthouse/llm-factory";
import {
  initializeMCPClient,
  isMCPAvailable,
  getMCPTools,
} from "@/lib/lighthouse/mcp-client";
import {
  describeTool,
  executeTool,
} from "@/lib/lighthouse/tools/meta-tool";
import { getModelParams } from "@/lib/lighthouse/utils";

export interface RuntimeConfig {
  model?: string;
  provider?: string;
}

/**
 * Truncate description to specified length
 */
function truncateDescription(desc: string | undefined, maxLen: number): string {
  if (!desc) return "No description available";

  const cleaned = desc.replace(/\n/g, " ").replace(/\s+/g, " ").trim();

  if (cleaned.length <= maxLen) return cleaned;

  return cleaned.substring(0, maxLen) + "...";
}

/**
 * Generate dynamic tool listing from MCP tools
 */
function generateToolListing(): string {
  if (!isMCPAvailable()) {
    return "\nMCP Server Unavailable. No Prowler Hub tools are currently accessible.\n";
  }

  const mcpTools = getMCPTools();

  if (mcpTools.length === 0) {
    return "\nNo Tools Available. No MCP tools were loaded.\n";
  }

  let listing = "\n## Available Prowler Hub Tools\n\n";
  listing += `${mcpTools.length} tools loaded from Prowler Hub\n\n`;

  for (const tool of mcpTools) {
    const desc = truncateDescription(tool.description, 100);
    listing += `- **${tool.name}**: ${desc}\n`;
  }

  listing += "\nUse describe_tool with exact tool name to see full schema and parameters.\n";

  return listing;
}

/**
 * System prompt template for the unified Lighthouse agent
 * {{TOOL_LISTING}} will be replaced with dynamically generated tool list
 */
const LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE = `
You are an Autonomous Cloud Security Analyst powered by Prowler, specializing in cloud security analysis through Prowler Hub.

{{TOOL_LISTING}}

## Tool Usage

You have access to TWO meta-tools:

1. **describe_tool** - Get detailed schema for a specific tool
   - Use exact tool name from the list above
   - Returns full parameter schema and requirements
   - Example: describe_tool({ "toolName": "prowler_hub_list_providers" })

2. **execute_tool** - Run a tool with its parameters
   - Provide exact tool name and required parameters
   - Use empty object {} for tools with no parameters
   - You must always provide the toolName and toolInput keys in the JSON object.
   - Example: execute_tool({ "toolName": "prowler_hub_list_providers", "toolInput": {} })
   - Example: execute_tool({ "toolName": "prowler_hub_list_providers", "toolInput": { "query": "value1" } })

## Workflow

1. **Select**: Choose the right tool from the list above based on user query
2. **Describe**: Use describe_tool with exact tool name to get full schema
3. **Execute**: Use execute_tool with correct parameters from schema
4. **Respond**: Format and present results to user

## Guidelines

- Tool names are listed above - pick the correct one directly
- Always describe the tool first to see its required parameters
- If a tool has no parameters in schema, pass empty object {} as toolInput
- Always send complete JSON with "toolName" and "toolInput" keys
- Keep responses concise and actionable
`;

export async function initLighthouseWorkflow(runtimeConfig?: RuntimeConfig) {
  await initializeMCPClient();

  const mcpIsAvailable = isMCPAvailable();
  const toolListing = generateToolListing();

  const systemPrompt = LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE.replace(
    "{{TOOL_LISTING}}",
    toolListing,
  );

  const tenantConfigResult = await getTenantConfig();
  const tenantConfig = tenantConfigResult?.data?.attributes;

  const defaultProvider = tenantConfig?.default_provider || "openai";
  const defaultModels = tenantConfig?.default_models || {};
  const defaultModel = defaultModels[defaultProvider] || "gpt-4o";

  const providerType = (runtimeConfig?.provider ||
    defaultProvider) as ProviderType;
  const modelId = runtimeConfig?.model || defaultModel;

  // Get credentials
  const providerConfig = await getProviderCredentials(providerType);
  const { credentials, base_url: baseUrl } = providerConfig;

  // Get model params
  const modelParams = getModelParams({ model: modelId });

  // Initialize LLM
  const llm = createLLM({
    provider: providerType,
    model: modelId,
    credentials,
    baseUrl,
    streaming: true,
    tags: ["lighthouse-agent"],
    modelParams,
  });

  const agent = createAgent({
    model: llm,
    tools: [describeTool, executeTool],
    systemPrompt,
  });

  return agent;
}
