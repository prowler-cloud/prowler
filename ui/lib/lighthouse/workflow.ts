import { createAgent } from "langchain";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { TOOLS_UNAVAILABLE_MESSAGE } from "@/lib/lighthouse/constants";
import type { ProviderType } from "@/lib/lighthouse/llm-factory";
import { createLLM } from "@/lib/lighthouse/llm-factory";
import {
  getMCPTools,
  initializeMCPClient,
  isMCPAvailable,
} from "@/lib/lighthouse/mcp-client";
import {
  generateUserDataSection,
  LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE,
} from "@/lib/lighthouse/system-prompt";
import { describeTool, executeTool } from "@/lib/lighthouse/tools/meta-tool";
import { getModelParams } from "@/lib/lighthouse/utils";

export interface RuntimeConfig {
  model?: string;
  provider?: string;
  businessContext?: string;
  currentData?: string;
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
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  const mcpTools = getMCPTools();

  if (mcpTools.length === 0) {
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  let listing = "\n## Available Prowler Tools\n\n";
  listing += `${mcpTools.length} tools loaded from Prowler MCP\n\n`;

  for (const tool of mcpTools) {
    const desc = truncateDescription(tool.description, 150);
    listing += `- **${tool.name}**: ${desc}\n`;
  }

  listing +=
    "\nUse describe_tool with exact tool name to see full schema and parameters.\n";

  return listing;
}

export async function initLighthouseWorkflow(runtimeConfig?: RuntimeConfig) {
  await initializeMCPClient();

  const toolListing = generateToolListing();

  let systemPrompt = LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE.replace(
    "{{TOOL_LISTING}}",
    toolListing,
  );

  // Add user-provided data section if available
  const userDataSection = generateUserDataSection(
    runtimeConfig?.businessContext,
    runtimeConfig?.currentData,
  );

  if (userDataSection) {
    systemPrompt += userDataSection;
  }

  const tenantConfigResult = await getTenantConfig();
  const tenantConfig = tenantConfigResult?.data?.attributes;

  const defaultProvider = tenantConfig?.default_provider || "openai";
  const defaultModels = tenantConfig?.default_models || {};
  const defaultModel = defaultModels[defaultProvider] || "gpt-5.2";

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
