import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";

import { type SuggestedAction } from "./suggested-actions";
import { initLighthouseWorkflow } from "./workflow";

export const generateDetailedRecommendation = async (): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "";
    }

    const lighthouseConfig = await getLighthouseConfig();
    if (!lighthouseConfig?.attributes) {
      return "";
    }

    const workflow = await initLighthouseWorkflow();
    const response = await workflow.invoke({
      messages: [
        {
          role: "user",
          content: `Create focused and actionable recommendations to Security Engineering Manager based on findings from all recent completed scans.

Your output should include both an overview of recent scans and your analysis about the findings. Your analysis should include the most urgent bug that needs to be fixed first (even if there are multiple bugs with different severities).

Your output should contain the following:
- Overview of the recent scans and findings
- Comprehensive analysis of finding/pattern that users need to fix immediately

When you're talking about any issue, be clear. For example:

- When talking about findings, give the details of resources, account IDs, etc instead of just providing UUIDs of findings, resources, etc.
- When giving issue description, convey what exactly is the problem and the reason you think why it should be fixed first.
- When finding patterns, convey if users must focus on a particular bug class or particular cloud service or they must focus on a particular finding to improve their cloud security posture.
- When mentioning the affected resources, try to give the names of resources and account IDs instead of just providing UUIDs of findings, resources, etc.
- When giving business impact, tell the actual security risks of findings and potential consequences (possible bruteforce attacks on resources, compliance violation, etc)
- When giving remediation steps, give clear step-by-step instructions and any gotcha's they need to check before fix (if applicable).
- Be specific with numbers (e.g., "affects 12 S3 buckets", "resolves 15 findings"). Focus on actionable guidance that will have the biggest security improvement.

Guidelines for checking findings:
- Go by the severity: critical, high, medium, low
- When fetching findings, order by severity
- Ignore muted findings

Guidelines for writing the output:
- Use a formal yet casual tone.
- Don't make it look like a report. The output is read by humans.
- The output need not contain subheadings like issue description, affected resources, etc.
- First, give a few sentence overview about the recent scans and findings, then dig deeper into the critical top findings that user must focus on.
- Don't burden the user with too many findings. Evaluate the findings and tell them what they should focus on.`,
        },
      ],
    });

    const lastMessage =
      response.messages[response.messages.length - 1]?.content?.toString?.();
    return lastMessage;
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
