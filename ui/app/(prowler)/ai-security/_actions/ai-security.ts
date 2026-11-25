"use server";

import { getCompliancesOverview } from "@/actions/compliances";
import { getLatestFindingGroups } from "@/actions/finding-groups";
import {
  type FindingsSeverityAttributes,
  type FindingsStatusAttributes,
  getCategoryOverview,
  getFindingsBySeverity,
  getFindingsByStatus,
} from "@/actions/overview";
import type { CategoryOverviewAttributes } from "@/actions/overview/risk-radar/types";
import {
  AI_FRAMEWORKS,
  type AiFindingGroup,
  isCloudAi,
  isModelVendor,
  narrowScope,
  TOP_RISKS,
  toAiSecurityOverview,
} from "@/app/(prowler)/ai-security/_lib/overview";
import type { AiSecurityOverview } from "@/app/(prowler)/ai-security/_types";
import {
  apiBaseUrl,
  FINDINGS_SEVERITY_HIGH_FIRST,
  getAuthHeaders,
} from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";

const AI_CATEGORY = "gen-ai";
const FINDINGS_SORT = "-severity,-resources_fail";
const NO_SEVERITY: FindingsSeverityAttributes = {
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  informational: 0,
};

// The actions resolve API errors to objects without `data`; only an array is a list.
const listOf = <T>(response: unknown): T[] => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? (data as T[]) : [];
};

/**
 * The checks of the most severe failed gen-ai findings of the clouds. Finding
 * groups have no category filter, so their checks come from the findings.
 */
async function getCloudAiFailedChecks(
  filters: Record<string, string>,
): Promise<string[]> {
  const url = new URL(`${apiBaseUrl}/findings/latest`);
  // shortcut: only the checks of the 100 most severe findings make the top risks; page on if a cloud's gen-ai failures crowd out less severe checks.
  Object.entries({
    ...filters,
    "filter[category]": AI_CATEGORY,
    "filter[status]": "FAIL",
    "filter[muted]": "false",
    "fields[findings]": "check_id",
    sort: FINDINGS_SEVERITY_HIGH_FIRST,
    "page[size]": "100",
  }).forEach(([key, value]) => url.searchParams.set(key, value));
  try {
    const response = await fetch(url.toString(), {
      headers: await getAuthHeaders({ contentType: false }),
    });
    const findings = listOf<{ attributes: { check_id: string } }>(
      await handleApiResponse(response),
    );
    return Array.from(new Set(findings.map((f) => f.attributes.check_id)));
  } catch (error) {
    console.error("Error fetching cloud AI findings:", error);
    return [];
  }
}

async function getCloudAiFindingGroups(filters: Record<string, string>) {
  const checks = await getCloudAiFailedChecks(filters);
  if (checks.length === 0) return [];
  return listOf<AiFindingGroup>(
    await getLatestFindingGroups({
      pageSize: TOP_RISKS,
      sort: FINDINGS_SORT,
      filters: {
        ...filters,
        "filter[status]": "FAIL",
        "filter[check_id__in]": checks.join(","),
      },
    }),
  );
}

/**
 * The AI Security overview from the latest scans: totals of the provider types
 * the filters select, the stack of every AI-SPM provider. Model vendors count
 * every finding; clouds count their gen-ai findings. Null when the totals
 * could not be loaded.
 */
export async function getAiSecurityOverview(
  filters: Record<string, string>,
  providers: ProviderProps[],
): Promise<AiSecurityOverview | null> {
  const types = Array.from(
    new Set(providers.map((provider) => provider.attributes.provider)),
  );
  const vendorTypes = types.filter(isModelVendor);
  const cloudTypes = types.filter(isCloudAi);
  const vendorScope = narrowScope(filters, isModelVendor);
  const cloudScope = narrowScope(filters, isCloudAi);
  const vendorFailed = vendorScope && {
    ...vendorScope,
    "filter[status]": "FAIL",
  };

  const [
    statuses,
    categories,
    severity,
    compliances,
    vendorGroups,
    cloudGroups,
  ] = await Promise.all([
    Promise.all(
      vendorTypes.map((type) =>
        getFindingsByStatus({
          filters: { ...filters, "filter[provider_type__in]": type },
        }),
      ),
    ),
    Promise.all(
      cloudTypes.map((type) =>
        getCategoryOverview({
          filters: {
            ...filters,
            "filter[provider_type__in]": type,
            "filter[category]": AI_CATEGORY,
          },
        }),
      ),
    ),
    vendorFailed && getFindingsBySeverity({ filters: vendorFailed }),
    vendorScope && getCompliancesOverview({ filters: vendorScope }),
    vendorFailed &&
      getLatestFindingGroups({
        pageSize: TOP_RISKS,
        sort: FINDINGS_SORT,
        filters: vendorFailed,
      }),
    cloudScope ? getCloudAiFindingGroups(cloudScope) : [],
  ]);

  const results: Record<string, FindingsStatusAttributes> = {};
  statuses.forEach((status, index) => {
    const attributes =
      status && "data" in status ? status.data?.attributes : undefined;
    if (attributes) results[vendorTypes[index]] = attributes;
  });
  const cloudResults: Record<string, CategoryOverviewAttributes> = {};
  categories.forEach((category, index) => {
    // No row for gen-ai means no gen-ai findings in the latest scans.
    if (category && "data" in category && Array.isArray(category.data)) {
      cloudResults[cloudTypes[index]] = category.data.find(
        ({ id }) => id === AI_CATEGORY,
      )?.attributes ?? {
        total_findings: 0,
        failed_findings: 0,
        new_failed_findings: 0,
        severity: NO_SEVERITY,
      };
    }
  });
  const severityCounts =
    severity && "data" in severity ? severity.data?.attributes : undefined;
  // Without the totals the page would show a misleading empty posture.
  if (
    (vendorFailed && !severityCounts) ||
    Object.keys(results).length < vendorTypes.length ||
    Object.keys(cloudResults).length < cloudTypes.length
  ) {
    return null;
  }

  return toAiSecurityOverview({
    providers,
    types: filters["filter[provider_type__in]"].split(","),
    results,
    cloudResults,
    severity: severityCounts ?? NO_SEVERITY,
    frameworks: listOf<ComplianceOverviewData>(compliances).filter(
      (compliance) => Object.hasOwn(AI_FRAMEWORKS, compliance.id),
    ),
    findingGroups: [...listOf<AiFindingGroup>(vendorGroups), ...cloudGroups],
  });
}
