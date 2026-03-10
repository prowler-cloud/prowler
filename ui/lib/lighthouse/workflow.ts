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
 * Tools explicitly allowed for the LLM to list and execute.
 * Follows the principle of least privilege - only these tools are accessible.
 * All other tools are blocked by default.
 */
const ALLOWED_TOOLS = new Set([
  // === Prowler Hub Tools - read-only ===
  "prowler_hub_list_checks",
  "prowler_hub_semantic_search_checks",
  "prowler_hub_get_check_details",
  "prowler_hub_get_check_code",
  "prowler_hub_get_check_fixer",
  "prowler_hub_list_compliances",
  "prowler_hub_semantic_search_compliances",
  "prowler_hub_get_compliance_details",
  "prowler_hub_list_providers",
  "prowler_hub_get_provider_services",
  // === Prowler Docs Tools - read-only ===
  "prowler_docs_search",
  "prowler_docs_get_document",
  // === Prowler App Tools - read-only ===
  // Findings
  "prowler_app_search_security_findings",
  "prowler_app_get_finding_details",
  "prowler_app_get_findings_overview",
  // Providers
  "prowler_app_search_providers",
  // Scans
  "prowler_app_list_scans",
  "prowler_app_get_scan",
  // Muting
  "prowler_app_get_mutelist",
  "prowler_app_list_mute_rules",
  "prowler_app_get_mute_rule",
  // Compliance
  "prowler_app_get_compliance_overview",
  "prowler_app_get_compliance_framework_state_details",
  // Resources
  "prowler_app_list_resources",
  "prowler_app_get_resource",
  "prowler_app_get_resources_overview",
  // Attack Paths
  "prowler_app_list_attack_paths_queries",
  "prowler_app_list_attack_paths_scans",
  "prowler_app_run_attack_paths_query",
]);

/**
 * Check if a tool is allowed for LLM access.
 * Returns true only if the tool is explicitly in the whitelist.
 */
export function isAllowedTool(toolName: string): boolean {
  return ALLOWED_TOOLS.has(toolName);
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
