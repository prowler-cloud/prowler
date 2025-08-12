import { ChatOpenAI } from "@langchain/openai";

import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { getCurrentDataSection } from "@/lib/lighthouse/data";

import { type SuggestedAction } from "./suggested-actions";
import { initLighthouseWorkflow } from "./workflow";

export const generateDetailedRecommendation = async ({
  scanIds,
}: {
  scanIds: string[];
}): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "";
    }

    const currentDataSection = await getCurrentDataSection();

    const lighthouseConfig = await getLighthouseConfig();
    if (!lighthouseConfig?.attributes) {
      return "";
    }
    const businessContext =
      lighthouseConfig?.data?.attributes?.business_context;

    const workflow = await initLighthouseWorkflow();
    const response = await workflow.invoke({
      messages: [
        {
          id: "business-context",
          role: "assistant",
          content: `Business Context Information:\n${businessContext}`,
        },
        {
          id: "providers",
          role: "assistant",
          content: `${currentDataSection}`,
        },
        {
          id: "scan-ids",
          role: "user",
          content: `Scan IDs in focus: ${scanIds}`,
        },
        {
          role: "user",
          content: `Based on findings from mentioned scans AND business context (if available), provide detailed recommendations about issues that need to be fixed first along with remediation steps. Call all necessary tools and give actionable next steps.

## Core Principles

1. **Data-Driven Analysis Only**: Base all recommendations solely on verified findings from tool calls
2. **No Assumptions**: If data is unavailable or insufficient, clearly state this limitation
3. **Factual Reporting**: Report only what tools return - no speculation or gap-filling

## Required Process

You MUST follow all the following steps in order. Do NOT skip any step.

### Step 1: Overview Agent gives Overview
- Fetch overview of findings across scans using overview agent to get high level view of security posture
- Overview agent must provide the high level overview of findings based on tools getProvidersOverviewTool, getFindingsByStatusTool and getFindingsBySeverityTool
- Strictly use overview agent only for overview and findings agent for specific findings
- Overview agent must not provide any information apart from overview. Example, it must not provide data about checks, check IDs and individual findings.

### Step 2: Findings Agent gives Findings
- Fetch newly detected findings in the previous scans (if any)
- Fetch failed findings sorted by severity - critical, high and medium. Paginate to fetch all findings
- Ensure you went through all failed findings
- Group findings to find patterns (if any). For example: multiple findings for the same check ID

### Step 3: Resource Agent gives Resource Information (Optional)
- If the findings data doesn't contain sufficient information about resources, use resource agent to get the resource information
- Verify that findings data is complete and actionable
- Confirm that severity levels and resource details are available

### Step 4: Output
- Based on information from previous steps, give a detailed recommendation about issues that need to be fixed first along with remediation steps.
- This is the final summary recommendation. Do NOT add any other information about agents or tools.

## Report Structure (Conditional)

Generate a report ONLY if you have verified findings:

### Format Requirements
- Use markdown formatting
- No bullet points except for Resource Details sections
- No emojis or decorative elements
- Keep sentences concise - use 1-2 sentences maximum per concept
- Strip any unnecessary descriptive language that doesn't add value

### Required Sections

- Opening Statement: Single sentence stating you analyzed the environment and found X vulnerabilities
- Two sentences maximum giving executive summary of the findings and impact
- First Focus: (H2 heading) - Name the specific vulnerability type, not severity levels
- Second Focus: (H2 heading) - Name the specific vulnerability type, not severity levels
- Immediate Actions Required: (H2 heading) - Implementation guidance

### Content Structure for Each Vulnerability

- Start with 1-2 sentences explaining what's wrong and why it matters
- Include "Resource Details:" section with exactly these bullet points:
  - Resource name/identifier
  - Service
  - Account
  - Severity level
  - Impact description
- Always prefer using the accurate resource information from tool output instead of adding placeholder
- Mention the account alias (if available) along with account ID in account section. If there's no account alias, only mention the account ID.
- Include "Remediation:" section with the exact CLI command in a code block along with other ways to remediate (example: terraform)
- Use technical language, avoid storytelling or dramatic descriptions

## Failure Conditions

If any of these conditions occur, DO NOT generate a standard report:

- Overview agent returns no data or errors
- Findings agent returns empty results
- Tool calls fail or timeout
- Data is incomplete or unclear

Instead, provide a brief status explaining:
- What data collection was attempted
- What information is missing or unavailable
- What steps are needed to obtain the required data

## Style Guidelines

- Direct, technical, professional
- No detective stories, narratives, or analogies
- Focus on facts and actionable information
- Assume technical audience familiar with AWS
- Keep it clean and scannable

## Output Length

- Approximately 400-500 words total
- Each vulnerability section should be roughly equal length
- Adjust length based on actual findings complexity`,
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
