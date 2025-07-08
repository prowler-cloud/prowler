import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";

import { type SuggestedAction } from "./suggested-actions";
import { initLighthouseWorkflow } from "./workflow";

export const generateDetailedRecommendation = async (
  scanSummary: string,
): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "";
    }

    const lighthouseConfig = await getLighthouseConfig();
    if (!lighthouseConfig?.attributes) {
      return "";
    }

    const config = lighthouseConfig.attributes;
    const businessContext = config.business_context || "";

    const llm = new ChatOpenAI({
      model: config.model || "gpt-4o",
      temperature: config.temperature || 0,
      maxTokens: 1500,
      apiKey: apiKey,
    });

    let systemPrompt = `You are a cloud security analyst providing focused, actionable recommendations.

IMPORTANT: Focus on ONE of these high-impact opportunities:
1. The most CRITICAL finding that needs immediate attention
2. A pattern where fixing one check ID resolves many findings (e.g., "Fix aws_s3_bucket_public_access_block to resolve 15 findings")
3. The issue with highest business impact

Your response should be a comprehensive analysis of this ONE focus area including:

**Issue Description:**
- What exactly is the problem
- Why it's critical or high-impact
- How many findings it affects

**Affected Resources:**
- Specific resources, services, or configurations involved
- Number of affected resources

**Business Impact:**
- Security risks and potential consequences
- Compliance violations (mention specific frameworks if applicable)
- Operational impact

**Remediation Steps:**
- Clear, step-by-step instructions
- Specific commands or configuration changes where applicable
- Expected outcome after fix

Be specific with numbers (e.g., "affects 12 S3 buckets", "resolves 15 findings"). Focus on actionable guidance that will have the biggest security improvement.`;

    if (businessContext) {
      systemPrompt += `\n\nBUSINESS CONTEXT: ${businessContext}`;
    }

    systemPrompt += `\n\nSecurity Scan Summary:\n${scanSummary}`;

    const response = await llm.invoke([
      {
        role: "system",
        content: systemPrompt,
      },
    ]);

    return response.content.toString().trim();
  } catch (error) {
    console.error("Error generating detailed recommendation:", error);
    return "";
  }
};

export const generateBannerFromDetailed = async (
  detailedRecommendation: string,
): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "";
    }

    const lighthouseConfig = await getLighthouseConfig();
    if (!lighthouseConfig?.attributes) {
      return "";
    }

    const config = lighthouseConfig.attributes;

    const llm = new ChatOpenAI({
      model: config.model || "gpt-4o",
      temperature: config.temperature || 0,
      maxTokens: 100,
      apiKey: apiKey,
    });

    const systemPrompt = `Create a short, engaging banner message from this detailed security analysis.

REQUIREMENTS:
- Maximum 80 characters
- Include "Lighthouse" in the message
- Focus on the key insight or opportunity
- Make it clickable and business-focused
- Use action words like "detected", "found", "identified"
- Don't end with punctuation

EXAMPLES:
- Lighthouse found fixing 1 S3 check resolves 15 findings
- Lighthouse detected critical RDS encryption gaps
- Lighthouse identified 3 exposed databases needing attention

Based on this detailed analysis, create one engaging banner message:

${detailedRecommendation}`;

    const response = await llm.invoke([
      {
        role: "system",
        content: systemPrompt,
      },
    ]);

    return response.content.toString().trim();
  } catch (error) {
    console.error(
      "Error generating banner from detailed recommendation:",
      error,
    );
    return "";
  }
};

// Legacy function for backward compatibility
export const generateRecommendation = async (
  scanSummary: string,
): Promise<string> => {
  const detailed = await generateDetailedRecommendation(scanSummary);
  if (!detailed) return "";

  return await generateBannerFromDetailed(detailed);
};

export const generateQuestionAnswers = async (
  questions: SuggestedAction[],
): Promise<Record<string, string>> => {
  const answers: Record<string, string> = {};

  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return answers;
    }

    // Initialize the workflow system
    const workflow = await initLighthouseWorkflow();

    for (const question of questions) {
      if (!question.questionRef) continue;

      try {
        // Use the existing workflow to answer the question
        const result = await workflow.invoke({
          messages: [
            {
              role: "user",
              content: question.action,
            },
          ],
        });

        // Extract the final message content
        const finalMessage = result.messages[result.messages.length - 1];
        if (finalMessage?.content) {
          answers[question.questionRef] = finalMessage.content
            .toString()
            .trim();
        }
      } catch (error) {
        console.error(
          `Error generating answer for question ${question.questionRef}:`,
          error,
        );
        continue;
      }
    }
  } catch (error) {
    console.error("Error generating question answers:", error);
  }

  return answers;
};
