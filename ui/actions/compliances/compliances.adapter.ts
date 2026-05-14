import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { MetaDataProps } from "@/types";

import {
  ComplianceOverviewsResponse,
  EnrichedComplianceOverview,
} from "./types";

export type { ComplianceOverviewsResponse, EnrichedComplianceOverview };

/**
 * Formats framework name for display by replacing hyphens with spaces
 * e.g., "FedRAMP-20x-KSI-Low" -> "FedRAMP 20x KSI Low"
 */
function formatFrameworkName(framework: string): string {
  return framework.replace(/-/g, " ");
}

/**
 * Adapts the raw API response to enriched compliance data
 * - Computes score percentage (rounded)
 * - Formats label (framework + version)
 * - Resolves framework icon
 * - Preserves pagination metadata
 *
 * @param response - Raw API response with data and optional pagination
 * @returns Object with enriched compliance data and metadata
 */
export function adaptComplianceOverviewsResponse(
  response: ComplianceOverviewsResponse | undefined,
): {
  data: EnrichedComplianceOverview[];
  metadata?: MetaDataProps;
} {
  if (!response?.data) {
    return { data: [] };
  }

  const enrichedData = response.data.map((compliance) => {
    const { id, attributes } = compliance;
    const {
      framework,
      version,
      requirements_passed,
      requirements_failed,
      requirements_manual,
      total_requirements,
    } = attributes;

    const totalRequirements = Number(total_requirements) || 0;
    const passedRequirements = Number(requirements_passed) || 0;

    const score =
      totalRequirements > 0
        ? Math.round((passedRequirements / totalRequirements) * 100)
        : 0;

    const formattedFramework = formatFrameworkName(framework);
    const label = version
      ? `${formattedFramework} - ${version}`
      : formattedFramework;
    const icon = getComplianceIcon(framework);

    return {
      id,
      framework,
      version,
      requirements_passed,
      requirements_failed,
      requirements_manual,
      total_requirements,
      score,
      label,
      icon,
    };
  });

  const metadata: MetaDataProps | undefined = response.meta?.pagination
    ? {
        pagination: {
          page: response.meta.pagination.page,
          pages: response.meta.pagination.pages,
          count: response.meta.pagination.count,
          itemsPerPage: [10, 25, 50, 100],
        },
        version: "1.0",
      }
    : undefined;

  return { data: enrichedData, metadata };
}

/**
 * Sorts compliances for watchlist display:
 * - Excludes ProwlerThreatScore
 * - Sorted by score ascending (worst/lowest scores first)
 * - Limited to specified count
 *
 * @param data - Enriched compliance data
 * @param limit - Maximum number of items to return (default: 9)
 * @returns Sorted and limited compliance data
 */
export function sortCompliancesForWatchlist(
  data: EnrichedComplianceOverview[],
  limit: number = 9,
): EnrichedComplianceOverview[] {
  return [...data]
    .filter((item) => item.framework !== "ProwlerThreatScore")
    .sort((a, b) => a.score - b.score)
    .slice(0, limit);
}
