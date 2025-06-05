import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { createSupervisor } from "@langchain/langgraph-supervisor";
import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import {
  complianceAgentPrompt,
  findingsAgentPrompt,
  overviewAgentPrompt,
  providerAgentPrompt,
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
import { getRolesTool, getRoleTool } from "@/lib/lighthouse/tools/roles";
import { getScansTool, getScanTool } from "@/lib/lighthouse/tools/scans";
import {
  getMyProfileInfoTool,
  getUsersTool,
} from "@/lib/lighthouse/tools/users";

export async function initLighthouseWorkflow() {
  const apiKey = await getAIKey();
  const aiConfig = await getLighthouseConfig();
  const modelConfig = aiConfig?.data?.attributes;

  // Initialize models without API keys
  const llm = new ChatOpenAI({
    model: modelConfig?.model || "gpt-4o",
    temperature: modelConfig?.temperature || 0,
    maxTokens: modelConfig?.max_tokens || 4000,
    apiKey: apiKey,
    tags: ["agent"],
  });

  const supervisorllm = new ChatOpenAI({
    model: modelConfig?.model || "gpt-4o",
    temperature: modelConfig?.temperature || 0,
    maxTokens: modelConfig?.max_tokens || 4000,
    apiKey: apiKey,
    streaming: true,
    tags: ["supervisor"],
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

  const agents = [
    userInfoAgent,
    providerAgent,
    overviewAgent,
    scansAgent,
    complianceAgent,
    findingsAgent,
    rolesAgent,
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
