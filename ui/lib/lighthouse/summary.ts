import { getLighthouseCheckDetails } from "@/actions/lighthouse/checks";
import { getLighthouseFindings } from "@/actions/lighthouse/findings";
import { getScans } from "@/actions/scans/scans";
import { CheckDetails, FindingSummary } from "@/types/lighthouse/summary";

import { getNewFailedFindingsSummary } from "./tools/findings";

const getCompletedScansLast24h = async (): Promise<string[]> => {
  const twentyFourHoursAgo = new Date();
  twentyFourHoursAgo.setHours(twentyFourHoursAgo.getHours() - 24);

  const scansResponse = await getScans({
    page: 1,
    pageSize: 50,
    filters: {
      "fields[scans]": "completed_at",
      "filter[state]": "completed",
      "filter[started_at__gte]": twentyFourHoursAgo.toISOString(),
    },
    sort: "-updated_at",
  });

  if (!scansResponse?.data || scansResponse.data.length === 0) {
    return [];
  }

  return scansResponse.data.map((scan: any) => scan.id);
};

const compareProcessedScanIds = (
  currentScanIds: string[],
  processedScanIds: string[],
): boolean => {
  const sortedCurrent = [...currentScanIds].sort();
  const sortedProcessed = [...processedScanIds].sort();

  // Compare lengths first
  if (sortedCurrent.length !== sortedProcessed.length) {
    return false;
  }

  // Compare each element
  for (let i = 0; i < sortedCurrent.length; i++) {
    if (sortedCurrent[i] !== sortedProcessed[i]) {
      return false;
    }
  }

  return true;
};

const getTopFailedFindingsSummary = async (
  scanIds: string[],
  limit: number = 10,
): Promise<FindingSummary[]> => {
  const response = await getLighthouseFindings({
    page: 1,
    pageSize: limit,
    sort: "severity",
    filters: {
      "fields[findings]": "check_id,severity",
      "filter[scan__in]": scanIds.join(","),
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

// Helper function to collect new failed findings across multiple scans
const collectNewFailedFindings = async (
  scanIds: string[],
): Promise<Record<string, FindingSummary[]>> => {
  const findingsByScan: Record<string, FindingSummary[]> = {};

  for (const scanId of scanIds) {
    try {
      const newFailedFindingsSummary =
        await getNewFailedFindingsSummary(scanId);

      if (Object.keys(newFailedFindingsSummary).length > 0) {
        const scanFindings: FindingSummary[] = [];

        // Convert to FindingSummary format
        Object.entries(newFailedFindingsSummary).forEach(
          ([severity, checks]) => {
            Object.entries(checks).forEach(([checkId, summary]) => {
              scanFindings.push({
                checkId,
                severity,
                count: summary.count,
                findingIds: summary.finding_ids,
              });
            });
          },
        );

        if (scanFindings.length > 0) {
          findingsByScan[scanId] = scanFindings;
        }
      }
    } catch (error) {
      console.error(
        `Error fetching new failed findings for scan ${scanId}:`,
        error,
      );
    }
  }

  return findingsByScan;
};

// Helper function to enrich findings with check details
const enrichFindingsWithCheckDetails = async (
  findings: FindingSummary[],
): Promise<Map<string, CheckDetails>> => {
  const uniqueCheckIds = Array.from(new Set(findings.map((f) => f.checkId)));
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

  return checkDetailsMap;
};

// Helper function to sort findings by severity
const sortFindingsBySeverity = (
  findings: FindingSummary[],
): FindingSummary[] => {
  const severityOrder = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3,
    informational: 4,
  };

  return findings.sort(
    (a, b) =>
      severityOrder[a.severity as keyof typeof severityOrder] -
      severityOrder[b.severity as keyof typeof severityOrder],
  );
};

// Helper function to build details for a single finding
const buildSingleFindingDetails = (
  finding: FindingSummary,
  checkDetailsMap: Map<string, CheckDetails>,
): string => {
  const checkDetails = checkDetailsMap.get(finding.checkId);
  let detailsText = "";

  detailsText += `**Title:** ${checkDetails?.title || finding.checkId}\n`;
  detailsText += `**Severity:** ${finding.severity.toUpperCase()}\n`;
  detailsText += `**Check Summary:** ${checkDetails?.description || "Description not available"}\n`;
  detailsText += `**Number of failed findings:** ${finding.count}\n`;
  detailsText += `**Finding IDs:** ${finding.findingIds.join(", ")}\n`;
  detailsText += "**Remediation:**\n";

  const remediation = checkDetails?.remediation;
  if (remediation?.terraform) {
    detailsText += `- Terraform: ${remediation.terraform.description}\n`;
    if (remediation.terraform.reference) {
      detailsText += `  Reference: ${remediation.terraform.reference}\n`;
    }
  }
  if (remediation?.cli) {
    detailsText += `- AWS CLI: ${remediation.cli.description}\n`;
    if (remediation.cli.reference) {
      detailsText += `  Reference: ${remediation.cli.reference}\n`;
    }
  }
  if (remediation?.nativeiac) {
    detailsText += `- Native IAC: ${remediation.nativeiac.description}\n`;
    if (remediation.nativeiac.reference) {
      detailsText += `  Reference: ${remediation.nativeiac.reference}\n`;
    }
  }
  if (remediation?.other) {
    detailsText += `- Other: ${remediation.other.description}\n`;
    if (remediation.other.reference) {
      detailsText += `  Reference: ${remediation.other.reference}\n`;
    }
  }
  if (remediation?.wui) {
    detailsText += `- WUI: ${remediation.wui.description}\n`;
    if (remediation.wui.reference) {
      detailsText += `  Reference: ${remediation.wui.reference}\n`;
    }
  }

  if (
    !remediation?.terraform &&
    !remediation?.cli &&
    !remediation?.nativeiac &&
    !remediation?.other &&
    !remediation?.wui
  ) {
    detailsText += "- No specific remediation commands available\n";
  }

  detailsText += "\n";
  return detailsText;
};

// Generates a summary of failed findings from security scans in last 24 hours
// Returns an empty string if - no scans in 24 hours, no failed findings in any scan, or unexpected error
// Else it returns a string with the summary of the failed findings
export const generateSecurityScanSummary = async (): Promise<string> => {
  try {
    const currentScanIds = await getCompletedScansLast24h();

    if (currentScanIds.length === 0) {
      return "";
    }

    // TODO: Check if these scan IDs were already processed
    // This will be implemented in later steps when we update the cache service

    const scanIds = currentScanIds;

    // Collect new failed findings by scan
    const newFindingsByScan = await collectNewFailedFindings(scanIds);

    // Get top failed findings across all scans
    let topFailedFindings: FindingSummary[] = [];
    try {
      topFailedFindings = await getTopFailedFindingsSummary(scanIds, 10);
    } catch (error) {
      console.error("Error fetching top failed findings:", error);
    }

    // Combine all findings for check details enrichment
    const newFindings = Object.values(newFindingsByScan).flat();
    const allFindings = [...newFindings, ...topFailedFindings];

    // If no findings at all, return empty string
    if (allFindings.length === 0) {
      return "";
    }

    // Enrich all findings with check details
    const checkDetailsMap = await enrichFindingsWithCheckDetails(allFindings);

    // Build the summary
    let summaryText = "";

    // Header
    if (scanIds.length === 1) {
      summaryText += `# Scan ID: ${scanIds[0]}\n\n`;
    } else {
      summaryText += `# Scans processed (${scanIds.length} scans from last 24h)\n`;
      summaryText += `**Scan IDs:** ${scanIds.join(", ")}\n\n`;
    }

    // New findings section (if any)
    if (newFindings.length > 0) {
      summaryText += "## New Failed Findings by Scan\n";
      summaryText += `${newFindings.length} new findings detected.\n\n`;

      Object.entries(newFindingsByScan).forEach(([scanId, scanFindings]) => {
        summaryText += `### Scan ID: ${scanId}\n`;
        const sortedScanFindings = sortFindingsBySeverity(scanFindings);

        for (const finding of sortedScanFindings) {
          summaryText += buildSingleFindingDetails(finding, checkDetailsMap);
        }
        summaryText += "\n";
      });
    }

    // Top findings section
    if (topFailedFindings.length > 0) {
      summaryText += "## Top Failed Findings Across All Scans\n";
      summaryText += `Showing top ${topFailedFindings.length} critical findings.\n\n`;

      const sortedTopFindings = sortFindingsBySeverity(topFailedFindings);
      for (const finding of sortedTopFindings) {
        summaryText += buildSingleFindingDetails(finding, checkDetailsMap);
      }
    }

    return summaryText;
  } catch (error) {
    console.error("Error generating security scan summary:", error);
    return "";
  }
};
