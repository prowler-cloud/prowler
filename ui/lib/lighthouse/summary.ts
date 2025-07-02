import { ChatOpenAI } from "@langchain/openai";

import { getLighthouseCheckDetails } from "@/actions/lighthouse/checks";
import { getLighthouseFindings } from "@/actions/lighthouse/findings";
import { getAIKey, getLighthouseConfig } from "@/actions/lighthouse/lighthouse";
import { getScans } from "@/actions/scans/scans";
import { CheckDetails, FindingSummary } from "@/types/lighthouse/summary";

import { getNewFailedFindingsSummary } from "./tools/findings";

const getTopFailedFindingsSummary = async (
  scanId: string,
  limit: number = 10,
): Promise<FindingSummary[]> => {
  const response = await getLighthouseFindings({
    page: 1,
    pageSize: limit,
    sort: "severity",
    filters: {
      "fields[findings]": "check_id,severity",
      "filter[scan]": scanId,
      "filter[status]": "FAIL",
      "filter[muted]": "false",
    },
  });

  if (!response?.data) {
    return [];
  }

  return response.data.map((finding: any) => ({
    checkId: finding.attributes.check_id,
    severity: finding.attributes.severity,
    count: 1,
    findingIds: [finding.id],
  }));
};

export const generateSecurityScanSummary = async (): Promise<string> => {
  try {
    // Get the most recently completed scan
    const scansResponse = await getScans({
      page: 1,
      pageSize: 1,
      filters: {
        "filter[state]": "completed",
      },
      sort: "-updated_at",
    });

    console.log(scansResponse);

    if (!scansResponse?.data || scansResponse.data.length === 0) {
      return "No completed scans found";
    }

    const latestScan = scansResponse.data[0];
    const scanId = latestScan.id;

    // TODO: Check if the scan summary was already cached for the scan ID

    // Try to get new failed findings from this scan using the existing function
    let newFailedFindingsSummary: Record<
      string,
      Record<string, { count: number; finding_ids: string[] }>
    > = {};
    let hasNewFailedFindings = false;

    try {
      newFailedFindingsSummary = await getNewFailedFindingsSummary(scanId);
      hasNewFailedFindings = Object.keys(newFailedFindingsSummary).length > 0;
    } catch (error) {
      console.error("Error fetching new failed findings:", error);
    }

    // If no new failed findings, get top 10 failed findings by severity
    let findingsToProcess: FindingSummary[] = [];

    if (!hasNewFailedFindings) {
      try {
        findingsToProcess = await getTopFailedFindingsSummary(scanId, 10);
      } catch (error) {
        console.error("Error fetching top failed findings:", error);
      }
    } else {
      Object.entries(newFailedFindingsSummary).forEach(([severity, checks]) => {
        Object.entries(checks).forEach(([checkId, summary]) => {
          findingsToProcess.push({
            checkId,
            severity,
            count: summary.count,
            findingIds: summary.finding_ids,
          });
        });
      });
    }

    // If no failed findings at all, return positive message
    if (findingsToProcess.length === 0) {
      return `Scan ID: ${scanId}\nSummary: There are no failed findings detected in the latest scan. Well done!`;
    }

    // Get check details and remediation for each unique check
    const uniqueCheckIds = Array.from(
      new Set(findingsToProcess.map((f) => f.checkId)),
    );
    const checkDetailsMap = new Map<string, CheckDetails>();

    for (const checkId of uniqueCheckIds) {
      try {
        const checkDetails = await getLighthouseCheckDetails({ checkId });
        if (checkDetails) {
          checkDetailsMap.set(checkId, checkDetails);
        }
      } catch (error) {
        console.error(`Error fetching check details for ${checkId}:`, error);
        // Add a fallback check details object
        checkDetailsMap.set(checkId, {
          id: checkId,
          title: checkId,
          description: "",
          risk: "",
          remediation: {},
        });
      }
    }

    // Build the summary text
    let summaryText = `Scan ID: ${scanId}\n`;

    if (hasNewFailedFindings) {
      const totalNewFindings = findingsToProcess.reduce(
        (sum, f) => sum + f.count,
        0,
      );
      summaryText += `Summary: There were ${totalNewFindings} new findings detected in the previous scan.\nThey are as follows:\n\n`;
    } else {
      summaryText += `Summary: There were no new findings detected in the previous scan. These are the following top ${findingsToProcess.length} findings in the account:\n\n`;
    }

    // Sort findings by severity
    const severityOrder = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      informational: 4,
    };
    findingsToProcess.sort(
      (a, b) =>
        severityOrder[a.severity as keyof typeof severityOrder] -
        severityOrder[b.severity as keyof typeof severityOrder],
    );

    for (const finding of findingsToProcess) {
      const checkDetails = checkDetailsMap.get(finding.checkId);

      summaryText += `- Title: ${checkDetails?.title || finding.checkId}\n`;
      summaryText += `   Severity: ${finding.severity.toUpperCase()}\n`;
      summaryText += `   Check Summary: ${checkDetails?.description || "Description not available"}\n`;
      summaryText += `   Number of failed findings associated with check ID: ${finding.count}\n`;
      summaryText += `   Finding IDs: ${finding.findingIds.join(", ")}\n`;
      summaryText += "   Remediation:\n";

      const remediation = checkDetails?.remediation;
      if (remediation?.terraform) {
        summaryText += `   - Terraform: ${remediation.terraform.description}\n`;
        if (remediation.terraform.reference) {
          summaryText += `     Reference: ${remediation.terraform.reference}\n`;
        }
      }
      if (remediation?.cli) {
        summaryText += `   - AWS CLI: ${remediation.cli.description}\n`;
        if (remediation.cli.reference) {
          summaryText += `     Reference: ${remediation.cli.reference}\n`;
        }
      }
      if (remediation?.nativeiac) {
        summaryText += `   - Native IAC: ${remediation.nativeiac.description}\n`;
        if (remediation.nativeiac.reference) {
          summaryText += `     Reference: ${remediation.nativeiac.reference}\n`;
        }
      }
      if (remediation?.other) {
        summaryText += `   - Other: ${remediation.other.description}\n`;
        if (remediation.other.reference) {
          summaryText += `     Reference: ${remediation.other.reference}\n`;
        }
      }
      if (remediation?.wui) {
        summaryText += `   - WUI: ${remediation.wui.description}\n`;
        if (remediation.wui.reference) {
          summaryText += `     Reference: ${remediation.wui.reference}\n`;
        }
      }

      if (
        !remediation?.terraform &&
        !remediation?.cli &&
        !remediation?.nativeiac &&
        !remediation?.other &&
        !remediation?.wui
      ) {
        summaryText += "   - No specific remediation commands available\n";
      }

      summaryText += "\n";
    }

    return summaryText;
  } catch (error) {
    console.error("Error generating security scan summary:", error);
    return "Error generating security scan summary. Please try again later.";
  }
};

export const generateBusinessRecommendations = async (
  securitySummary: string,
): Promise<string> => {
  try {
    const apiKey = await getAIKey();
    if (!apiKey) {
      return "Unable to generate recommendations: API key not configured";
    }

    // Get lighthouse configuration including business context
    const lighthouseConfig = await getLighthouseConfig();

    if (!lighthouseConfig?.attributes) {
      return "Unable to generate recommendations: Lighthouse configuration not found";
    }

    const config = lighthouseConfig.attributes;
    const businessContext = config.business_context || "";

    const llm = new ChatOpenAI({
      model: config.model || "gpt-4o",
      temperature: config.temperature || 0,
      maxTokens: 200,
      apiKey: apiKey,
    });

    // Create the prompt based on whether business context is provided
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
- Use words like "detected" or "found" to describe the issue

EXAMPLES OF GOOD RESPONSES:
- "Lighthouse detected critical issues in authentication services"
- "Lighthouse found a new exposed S3 bucket in recent scan"
- "Lighthouse identified that fixing one check could resolve 30 open findings"

Based on the below security scan summary, generate ONE short business recommendation:`;

    if (businessContext.trim()) {
      systemPrompt += `\n\nBUSINESS CONTEXT: ${businessContext}`;
    }

    const userPrompt = `Security Summary:\n${securitySummary}`;

    try {
      const response = await llm.invoke([
        { role: "system", content: systemPrompt },
        { role: "user", content: userPrompt },
      ]);

      const recommendation = response.content.toString().trim();

      return recommendation;
    } catch (llmError) {
      console.error("Error calling LLM:", llmError);
      return "";
    }
  } catch (error) {
    console.error("Error generating business recommendations:", error);
    return "";
  }
};
