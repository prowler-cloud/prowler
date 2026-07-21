import { createAgent } from "langchain";

import {
  getProviderCredentials,
  getTenantConfig,
} from "@/actions/lighthouse-v1/lighthouse";
import { isAllowedTool } from "@/lib/lighthouse-v1/allowed-tools";
import { TOOLS_UNAVAILABLE_MESSAGE } from "@/lib/lighthouse-v1/constants";
import type { ProviderType } from "@/lib/lighthouse-v1/llm-factory";
import { createLLM } from "@/lib/lighthouse-v1/llm-factory";
import {
  getMCPTools,
  initializeMCPClient,
  isMCPAvailable,
} from "@/lib/lighthouse-v1/mcp-client";
import { getAllSkillMetadata } from "@/lib/lighthouse-v1/skills/index";
import {
  generateSkillCatalog,
  generateUserDataSection,
  LIGHTHOUSE_SYSTEM_PROMPT_TEMPLATE,
} from "@/lib/lighthouse-v1/system-prompt";
import { loadSkill } from "@/lib/lighthouse-v1/tools/load-skill";
import { describeTool, executeTool } from "@/lib/lighthouse-v1/tools/meta-tool";
import { getModelParams } from "@/lib/lighthouse-v1/utils";

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
 * Generate dynamic tool listing from MCP tools.
 * Only includes tools that are explicitly whitelisted.
 */
function generateToolListing(): string {
  if (!isMCPAvailable()) {
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  const mcpTools = getMCPTools();

  if (mcpTools.length === 0) {
    return TOOLS_UNAVAILABLE_MESSAGE;
  }

  // Only include whitelisted tools
  const safeTools = mcpTools.filter((tool) => isAllowedTool(tool.name));

  let listing = "\n## Available Prowler Tools\n\n";
  listing += `${safeTools.length} tools loaded from Prowler MCP\n\n`;

  for (const tool of safeTools) {
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

  // Generate and inject skill catalog
  const skillCatalog = generateSkillCatalog(getAllSkillMetadata());
  systemPrompt = systemPrompt.replace("{{SKILL_CATALOG}}", skillCatalog);

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
    tools: [describeTool, executeTool, loadSkill],
    systemPrompt,
  });

  return agent;
}
