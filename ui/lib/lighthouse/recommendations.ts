import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";

export const generateRecommendation = async (
  scanSummary: string,
): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "";
    }

    // Get lighthouse configuration
    const lighthouseConfig = await getLighthouseConfig();
    if (!lighthouseConfig?.attributes) {
      return "";
    }

    const config = lighthouseConfig.attributes;
    const finalBusinessContext = config.business_context || "";

    const llm = new ChatOpenAI({
      model: config.model || "gpt-4o",
      temperature: config.temperature || 0,
      maxTokens: 150,
      apiKey: apiKey,
    });

    // Build the prompt with business context awareness
    let systemPrompt = `You are a cloud security analyst creating concise business recommendations for a banner notification.

IMPORTANT: Your response must be a single, short sentence (max 80 characters) that would make a user want to click on a banner to learn more.

GUIDELINES:
- Frame recommendations in business terms, not technical jargon
- Focus on actionable insights
- Make it clickable and engaging
- Don't use phrases like "Lighthouse says" or "Lighthouse recommends"
- Be specific about the type of improvement when possible
- Use only information from the security scan summary to generate the recommendation
- Add words like "Lighthouse" to the recommendation
- Don't end with a question mark or full stop
- Don't use words like "urges" or "requires"
- Don't wrap the message in double quotes or single quotes
- Use words like "detected" or "found" to describe the issue

EXAMPLES OF GOOD RESPONSES:
- Lighthouse detected critical issues in authentication services
- Lighthouse found a new exposed S3 bucket in recent scan
- Lighthouse identified fixing one check could resolve 30 open findings

Based on the below security scan summary, generate ONE short business recommendation:`;

    if (finalBusinessContext) {
      systemPrompt += `\n\nBUSINESS CONTEXT: ${finalBusinessContext}`;
    }

    systemPrompt += `\n\nBased on this security scan summary, generate 1 engaging banner message:\n\n${scanSummary}`;

    const response = await llm.invoke([
      {
        role: "system",
        content: systemPrompt,
      },
    ]);

    const recommendation = response.content.toString().trim();

    return recommendation.length > 0 ? recommendation : "";
  } catch (error) {
    console.error("Error generating recommendation:", error);
    return "";
  }
};
