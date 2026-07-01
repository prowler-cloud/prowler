import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { formatLabel } from "@/lib/categories";

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

/**
 * Formats compliance_id into a human-readable label
 * e.g., "aws_account_security_onboarding_aws" → "AWS Account Security Onboarding"
 *
 * Uses the shared formatLabel utility from lib/categories.ts which handles:
 * - Acronyms (≤3 chars like AWS, CIS, ISO, PCI, SOC, etc.)
 * - Special cases (4+ char acronyms like GDPR, HIPAA, NIST, etc.)
 * - Version patterns (e.g., "v1", "v2")
 */
function formatComplianceLabel(complianceId: string): string {
  // Remove trailing provider suffix (e.g., "_aws", "_gcp", "_azure")
  const withoutProvider = complianceId
    .replace(/_aws$/i, "")
    .replace(/_gcp$/i, "")
    .replace(/_azure$/i, "")
    .replace(/_kubernetes$/i, "");

  return formatLabel(withoutProvider, "_");
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
