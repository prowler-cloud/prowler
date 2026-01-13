import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";

import { ComplianceWatchlistResponse } from "./compliance-watchlist.types";

export interface EnrichedComplianceWatchlistItem {
  id: string;
  complianceId: string;
  label: string;
  icon: ReturnType<typeof getComplianceIcon>;
  score: number;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  totalRequirements: number;
}

const KNOWN_ACRONYMS = [
  "aws",
  "cis",
  "iso",
  "pci",
  "soc",
  "gdpr",
  "hipaa",
  "nist",
  "ens",
  "rbi",
  "mitre",
  "nis",
  "fedramp",
  "ffiec",
  "gxp",
  "kisa",
  "c5",
  "ccc",
  "cisa",
] as const;

/**
 * Formats compliance_id into a human-readable label
 * e.g., "aws_account_security_onboarding_aws" → "AWS Account Security Onboarding"
 */
function formatComplianceLabel(complianceId: string): string {
  // Remove trailing provider suffix (e.g., "_aws", "_gcp", "_azure")
  const withoutProvider = complianceId
    .replace(/_aws$/i, "")
    .replace(/_gcp$/i, "")
    .replace(/_azure$/i, "")
    .replace(/_kubernetes$/i, "");

  // Split by underscore and capitalize each word
  return withoutProvider
    .split("_")
    .map((word) => {
      // Handle known acronyms
      if (
        KNOWN_ACRONYMS.includes(
          word.toLowerCase() as (typeof KNOWN_ACRONYMS)[number],
        )
      ) {
        return word.toUpperCase();
      }
      // Handle version numbers (e.g., "2" stays as "2", "v1" stays as "v1")
      if (/^\d+$/.test(word) || /^v\d+/.test(word)) {
        return word;
      }
      // Capitalize first letter
      return word.charAt(0).toUpperCase() + word.slice(1).toLowerCase();
    })
    .join(" ");
}

export function adaptComplianceWatchlistResponse(
  response: ComplianceWatchlistResponse | undefined,
): EnrichedComplianceWatchlistItem[] {
  if (!response?.data) {
    return [];
  }

  return response.data.map((item) => {
    const {
      compliance_id,
      requirements_passed,
      requirements_failed,
      requirements_manual,
      total_requirements,
    } = item.attributes;

    // Defensive conversion: API types are number but JSON parsing edge cases may return strings
    const totalReqs = Number(total_requirements) || 0;
    const passedReqs = Number(requirements_passed) || 0;
    const score =
      totalReqs > 0 ? Math.round((passedReqs / totalReqs) * 100) : 0;

    return {
      id: item.id,
      complianceId: compliance_id,
      label: formatComplianceLabel(compliance_id),
      icon: getComplianceIcon(compliance_id),
      score,
      requirementsPassed: requirements_passed,
      requirementsFailed: requirements_failed,
      requirementsManual: requirements_manual,
      totalRequirements: total_requirements,
    };
  });
}
