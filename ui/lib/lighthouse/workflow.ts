import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { createSupervisor } from "@langchain/langgraph-supervisor";
import { ChatOpenAI } from "@langchain/openai";

import {
  getProviderApiKey,
  getTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import {
  complianceAgentPrompt,
  findingsAgentPrompt,
  overviewAgentPrompt,
  providerAgentPrompt,
  resourcesAgentPrompt,
  rolesAgentPrompt,
  scansAgentPrompt,
  supervisorPrompt,
  userInfoAgentPrompt,
} from "@/lib/lighthouse/prompts";
import {
  getProviderCheckDetailsTool,
  getProviderChecksTool,
} from "@/lib/lighthouse/tools/checks";
import {
  getComplianceFrameworksTool,
  getComplianceOverviewTool,
  getCompliancesOverviewTool,
} from "@/lib/lighthouse/tools/compliances";
import {
  getFindingsTool,
  getMetadataInfoTool,
} from "@/lib/lighthouse/tools/findings";
import {
  getFindingsBySeverityTool,
  getFindingsByStatusTool,
  getProvidersOverviewTool,
} from "@/lib/lighthouse/tools/overview";
import {
  getProvidersTool,
  getProviderTool,
} from "@/lib/lighthouse/tools/providers";
import {
  getLatestResourcesTool,
  getResourcesTool,
  getResourceTool,
} from "@/lib/lighthouse/tools/resources";
import { getRolesTool, getRoleTool } from "@/lib/lighthouse/tools/roles";
import { getScansTool, getScanTool } from "@/lib/lighthouse/tools/scans";
import {
  getMyProfileInfoTool,
  getUsersTool,
} from "@/lib/lighthouse/tools/users";
import { getModelParams } from "@/lib/lighthouse/utils";

export interface RuntimeConfig {
  model?: string;
}

export async function initLighthouseWorkflow(runtimeConfig?: RuntimeConfig) {
  const tenantConfigResult = await getTenantConfig();
  const tenantConfig = tenantConfigResult?.data?.attributes;

  // Get the default provider and model
  const defaultProvider = tenantConfig?.default_provider || "openai";
  const defaultModels = tenantConfig?.default_models || {};
  const defaultModel = defaultModels[defaultProvider] || "gpt-4o";

  // Get API key from the provider
  const apiKey = await getProviderApiKey(defaultProvider);

  // Merge runtime config with database config (runtime model takes priority)
  const finalConfig = {
    model: runtimeConfig?.model || defaultModel,
  };

  const modelParams = getModelParams(finalConfig);

  // Initialize models with runtime config
  const llm = new ChatOpenAI({
    model: finalConfig.model,
    apiKey: apiKey,
    tags: ["agent"],
    ...modelParams,
  });

  const supervisorllm = new ChatOpenAI({
    model: finalConfig.model,
    apiKey: apiKey,
    streaming: true,
    tags: ["supervisor"],
    ...modelParams,
  });

  const providerAgent = createReactAgent({
    llm: llm,
    tools: [getProvidersTool, getProviderTool],
    name: "provider_agent",
    prompt: providerAgentPrompt,
  });

  const userInfoAgent = createReactAgent({
    llm: llm,
    tools: [getUsersTool, getMyProfileInfoTool],
    name: "user_info_agent",
    prompt: userInfoAgentPrompt,
  });

  const scansAgent = createReactAgent({
    llm: llm,
    tools: [getScansTool, getScanTool],
    name: "scans_agent",
    prompt: scansAgentPrompt,
  });

  const complianceAgent = createReactAgent({
    llm: llm,
    tools: [
      getCompliancesOverviewTool,
      getComplianceOverviewTool,
      getComplianceFrameworksTool,
    ],
    name: "compliance_agent",
    prompt: complianceAgentPrompt,
  });

  const findingsAgent = createReactAgent({
    llm: llm,
    tools: [
      getFindingsTool,
      getMetadataInfoTool,
      getProviderChecksTool,
      getProviderCheckDetailsTool,
    ],
    name: "findings_agent",
    prompt: findingsAgentPrompt,
  });

  const overviewAgent = createReactAgent({
    llm: llm,
    tools: [
      getProvidersOverviewTool,
      getFindingsByStatusTool,
      getFindingsBySeverityTool,
    ],
    name: "overview_agent",
    prompt: overviewAgentPrompt,
  });

  const rolesAgent = createReactAgent({
    llm: llm,
    tools: [getRolesTool, getRoleTool],
    name: "roles_agent",
    prompt: rolesAgentPrompt,
  });

  const resourcesAgent = createReactAgent({
    llm: llm,
    tools: [getResourceTool, getResourcesTool, getLatestResourcesTool],
    name: "resources_agent",
    prompt: resourcesAgentPrompt,
  });

  const agents = [
    userInfoAgent,
    providerAgent,
    overviewAgent,
    scansAgent,
    complianceAgent,
    findingsAgent,
    rolesAgent,
    resourcesAgent,
  ];

  // Create supervisor workflow
  const workflow = createSupervisor({
    agents: agents,
    llm: supervisorllm,
    prompt: supervisorPrompt,
    outputMode: "last_message",
  });

  // Compile and run
  const app = workflow.compile();
  return app;
}
