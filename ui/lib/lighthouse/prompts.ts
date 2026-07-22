export interface FindingAnalysisPromptInput {
  findingId: string | null | undefined;
  providerUid: string | null | undefined;
  resourceUid: string | null | undefined;
  checkId: string | null | undefined;
  severity: string | null | undefined;
  status: string | null | undefined;
  detail: string | null | undefined;
  risk: string | null | undefined;
}

function getPromptValue(value: string | null | undefined): string {
  return typeof value === "string" && value.trim().length > 0
    ? value
    : "unknown";
}

export function buildFindingAnalysisPrompt({
  findingId,
  providerUid,
  resourceUid,
  checkId,
  severity,
  status,
  detail,
  risk,
}: FindingAnalysisPromptInput): string {
  return [
    "Get all the possible information from Prowler Application and from Prowler Hub to have the full context.",
    "",
    "Analyze this security finding and provide remediation guidance:",
    "",
    `- **Finding ID**: ${getPromptValue(findingId)}`,
    `- **Provider UID**: ${getPromptValue(providerUid)}`,
    `- **Resource UID**: ${getPromptValue(resourceUid)}`,
    `- **Check ID**: ${getPromptValue(checkId)}`,
    `- **Severity**: ${getPromptValue(severity)}`,
    `- **Status**: ${getPromptValue(status)}`,
    `- **Detail**: ${getPromptValue(detail)}`,
    `- **Risk**: ${getPromptValue(risk)}`,
  ].join("\n");
}
