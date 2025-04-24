import { createReactAgent } from "@langchain/langgraph/prebuilt";
import { createSupervisor } from "@langchain/langgraph-supervisor";
import { ChatOpenAI } from "@langchain/openai";
import { LangChainAdapter, Message } from "ai";

import { getAIConfiguration, getAIKey } from "@/actions/lighthouse/lighthouse";

import { getUserCache } from "../cache/lib/cache";
import { getProviderChecksTool } from "./(tools)/checks";
import {
  getComplianceFrameworksTool,
  getComplianceOverviewTool,
  getCompliancesOverviewTool,
} from "./(tools)/compliances";
import { getFindingsTool, getMetadataInfoTool } from "./(tools)/findings";
import {
  getFindingsBySeverityTool,
  getFindingsByStatusTool,
  getProvidersOverviewTool,
} from "./(tools)/overview";
import { getProvidersTool, getProviderTool } from "./(tools)/providers";
import { getRolesTool, getRoleTool } from "./(tools)/roles";
import { getScansTool, getScanTool } from "./(tools)/scans";
import { getMyProfileInfoTool, getUsersTool } from "./(tools)/users";
import {
  complianceAgentPrompt,
  findingsAgentPrompt,
  overviewAgentPrompt,
  providerAgentPrompt,
  rolesAgentPrompt,
  scansAgentPrompt,
  supervisorPrompt,
  userInfoAgentPrompt,
} from "./prompts";
import {
  convertLangChainMessageToVercelMessage,
  convertVercelMessageToLangChainMessage,
} from "./utils";

// Function to get user and provider data from cache
const getCachedDataSection = async (): Promise<string> => {
  try {
    const cacheData = await getUserCache();
    if (cacheData) {
      return `
**CURRENT USER DATA:**
Information about the current user interacting with the chatbot:
User: ${cacheData.user.name}
Email: ${cacheData.user.email}
Company: ${cacheData.user.company}

**CURRENT PROVIDER DATA:**
${cacheData.providers
  .map(
    (provider, index) => `
Provider ${index + 1}:
- Name: ${provider.name}
- Type: ${provider.provider_type}
- Alias: ${provider.alias}
- Provider ID: ${provider.id}
- Last Checked: ${provider.last_checked_at}
${
  provider.scan_id
    ? `- Latest Scan ID: ${provider.scan_id}
- Scan Duration: ${provider.scan_duration || "Unknown"}
- Resource Count: ${provider.resource_count || "Unknown"}`
    : "- No completed scans found"
}
`,
  )
  .join("\n")}
`;
    }
    return "";
  } catch (error) {
    console.error("Failed to retrieve cached data:", error);
    return "**CURRENT DATA: Not available**";
  }
};

const initializeModels = async () => {
  const apiKey = await getAIKey();
  const aiConfig = await getAIConfiguration();
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
    tools: [getFindingsTool, getMetadataInfoTool, getProviderChecksTool],
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
};

export async function POST(req: Request) {
  try {
    const {
      messages,
    }: {
      messages: Message[];
    } = await req.json();

    if (!messages) {
      return Response.json({ error: "No messages provided" }, { status: 400 });
    }

    // Create a new array for processed messages
    const processedMessages = [...messages];

    // Get AI configuration to access business context
    const aiConfig = await getAIConfiguration();
    const businessContext = aiConfig?.data?.attributes?.business_context;

    // Get cached data
    const cachedData = await getCachedDataSection();

    // Add context messages at the beginning
    const contextMessages: Message[] = [];

    // Add business context if available
    if (businessContext) {
      contextMessages.push({
        id: "business-context",
        role: "assistant",
        content: `Business Context Information:\n${businessContext}`,
      });
    }

    // Add cached data if available
    if (cachedData) {
      contextMessages.push({
        id: "cached-data",
        role: "assistant",
        content: cachedData,
      });
    }

    // Insert all context messages at the beginning
    processedMessages.unshift(...contextMessages);

    const app = await initializeModels();

    const agentStream = app.streamEvents(
      {
        messages: processedMessages
          .filter(
            (message: Message) =>
              message.role === "user" || message.role === "assistant",
          )
          .map(convertVercelMessageToLangChainMessage),
      },
      {
        streamMode: ["values", "messages", "custom"],
        version: "v2",
      },
    );

    const stream = new ReadableStream({
      async start(controller) {
        for await (const { event, data, tags } of agentStream) {
          if (event === "on_chat_model_stream") {
            if (data.chunk.content && !!tags && tags.includes("supervisor")) {
              const chunk = data.chunk;
              const aiMessage = convertLangChainMessageToVercelMessage(chunk);
              controller.enqueue(aiMessage);
            }
          }
        }
        controller.close();
      },
    });

    return LangChainAdapter.toDataStreamResponse(stream);
  } catch (error) {
    console.error("Error in POST request:", error);
    return Response.json({ error: "An error occurred" }, { status: 500 });
  }
}
