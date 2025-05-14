import { PromptTemplate } from "@langchain/core/prompts";
import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import {
  getFindingsByService,
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import { getCachedDataSection } from "@/lib/lighthouse/cache";

// In-memory cache for nudges
type NudgeCache = {
  [userId: string]: {
    nudges: any;
    timestamp: number;
    isFetching: boolean;
    fetchPromise?: Promise<void>;
  };
};

export const nudgeCache: NudgeCache = {};

// Default nudges when API key is not configured
const defaultNudges = {
  nudges: [
    {
      nudge: "Activate Lighthouse for AI-powered cloud security!",
      llm_query: "",
    },
    {
      nudge: "Resolve cloud security issues effortlessly with Lighthouse",
      llm_query: "",
    },
    {
      nudge: "Fix cloud security issues the smart way with Lighthouse",
      llm_query: "",
    },
  ],
};

// Function to fetch nudges asynchronously
export async function fetchNudges(userId: string) {
  try {
    // If there's already a fetch in progress, wait for it
    if (nudgeCache[userId]?.fetchPromise) {
      await nudgeCache[userId].fetchPromise;
      return;
    }

    // Get AI configuration to access business context
    const aiConfig = await getLighthouseConfig();
    const modelConfig = aiConfig?.data?.attributes?.model_config;
    const apiKey = await getAIKey();

    // If no API key is configured, return default nudges
    if (!apiKey) {
      nudgeCache[userId] = {
        nudges: defaultNudges,
        timestamp: Date.now(),
        isFetching: false,
      };
      return;
    }

    // Get cached data
    const cachedData = await getCachedDataSection();

    // Initialize the chat model with backend config
    const model = new ChatOpenAI({
      modelName: modelConfig?.model || "gpt-4o",
      temperature: modelConfig?.temperature || 0,
      maxTokens: modelConfig?.max_tokens || 4000,
      apiKey: apiKey,
    });

    // Create the prompt template
    // Use double curly braces for the JSON output - https://github.com/langchain-ai/langchain/issues/1660#issuecomment-1469320129
    const prompt = PromptTemplate.fromTemplate(`
You are a UX assistant for a cloud security dashboard. Your task is to generate 3 short, accurate, and helpful one-liners based on the provided JSON security data. These alerts will be shown in the top right corner of the dashboard as clickable pop-ups.

Each alert should:
- Be grounded in the provided JSON data (findings, compliance scores, posture drift, etc.).
- Rotate focus across findings, score trends, and region/account-level security posture.
- Mention how the AI assistant ("Lighthouse") can help the user fix these issues.
- Be informative and calm — avoid dramatic or fear-based language.
- Be under 15 words.
- Output must only contain the JSON output. No other text or formatting. It should NOT contain backticks or markdown formatting.
- If no data is available, return 3 different nudges where each nudge tells to connect user's cloud accounts to Prowler and use Lighthouse to fix security issues in them. Keep LLM query empty.
- You should never give a non JSON output or a JSON output that doesn't match the expected format.

Additionally, for each alert, generate an LLM query that Lighthouse can use to assist the user in fixing the specific issue.

Output format (JSON):
"""
{{
  "nudges": [
    {{
      "nudge": "<nedge sentence>",
      "llm_query": "<llm query for lighthouse>",
    }},
    {{
      "nudge": "<nedge sentence>",
      "llm_query": "<llm query for lighthouse>",
    }},
    {{
      "nudge": "<nedge sentence>",
      "llm_query": "<llm query for lighthouse>",
    }},
  ]
}}
"""

User Data:

{cachedData}

Provider Overview:

{providerOverview}

Findings Status Overview:

{findingsStatusOverview}

Findings Service Overview:

{findingsServiceOverview}

`);

    // Create a promise for this fetch operation
    const fetchPromise = (async () => {
      try {
        // Get all overview data
        const providerOverview = await getProvidersOverview({
          page: 1,
          query: "",
          sort: "",
          filters: {},
        });

        const findingsStatusOverview = await getFindingsByStatus({
          page: 1,
          query: "",
          sort: "",
          filters: {},
        });

        const findingsServiceOverview = await getFindingsByService({
          page: 1,
          query: "",
          sort: "",
          filters: { "filter[inserted_at__gte]": "2025-01-01" },
        });

        // Generate the response
        const response = await model.invoke(
          await prompt.format({
            cachedData,
            providerOverview,
            findingsStatusOverview,
            findingsServiceOverview,
          }),
        );

        // Parse the response to ensure it's valid JSON
        const nudges = JSON.parse(response.content.toString());

        // Store the response in cache
        nudgeCache[userId] = {
          nudges,
          timestamp: Date.now(),
          isFetching: false,
        };
      } catch (error) {
        console.error("Error fetching nudges:", error);
        // Clear the fetching flag in case of error
        if (nudgeCache[userId]) {
          nudgeCache[userId].isFetching = false;
        }
        throw error;
      }
    })();

    // Store the promise in the cache
    nudgeCache[userId] = {
      ...nudgeCache[userId],
      isFetching: true,
      fetchPromise,
    };

    // Wait for the fetch to complete
    await fetchPromise;
  } catch (error) {
    console.error("Error in fetchNudges:", error);
    throw error;
  }
}
