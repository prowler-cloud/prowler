"use server";

import { getLatestFindingGroups } from "@/actions/finding-groups";
import {
  type FindingsSeverityAttributes,
  type FindingsStatusAttributes,
  getCategoryOverview,
  getFindingsBySeverity,
  getFindingsByStatus,
} from "@/actions/overview";
import type { CategoryOverviewAttributes } from "@/actions/overview/risk-radar/types";
import { getScans } from "@/actions/scans";
import {
  AI_FRAMEWORK_IDS,
  type AiFindingGroup,
  isCloudAi,
  isModelVendor,
  narrowScope,
  TOP_RISKS,
  toAiSecurityOverview,
} from "@/app/(prowler)/ai-security/_lib/overview";
import type { AiSecurityOverview } from "@/app/(prowler)/ai-security/_types";
import { getCrossProviderComplianceOverview } from "@/app/(prowler)/compliance/_actions/cross-provider";
import { toCrossProviderSummary } from "@/app/(prowler)/compliance/_lib/cross-provider-adapter";
import { loadCrossProviderFrameworks } from "@/app/(prowler)/compliance/_lib/cross-provider-catalog";
import { parseCrossProviderFilters } from "@/app/(prowler)/compliance/_lib/cross-provider-frameworks";
import {
  CROSS_PROVIDER_OVERVIEW_RESULT_STATUS,
  type CrossProviderFrameworkSummary,
} from "@/app/(prowler)/compliance/_types";
import {
  apiBaseUrl,
  FINDINGS_SEVERITY_HIGH_FIRST,
  getAuthHeaders,
} from "@/lib";
import { handleApiResponse } from "@/lib/server-actions-helper";
import { SCAN_STATES } from "@/types/attack-paths";
import type { ProviderProps } from "@/types/providers";

const AI_CATEGORY = "gen-ai";
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
      filters: {
        ...filters,
        "filter[status]": "FAIL",
        "filter[check_id__in]": checks.join(","),
      },
    }),
  );
}

/** Whether any of the providers has a completed scan. */
async function hasCompletedScan(providerIds: string[]): Promise<boolean> {
  const scans = await getScans({
    pageSize: 1,
    fields: { scans: "state" },
    filters: {
      "filter[state]": SCAN_STATES.COMPLETED,
      "filter[provider__in]": providerIds.join(","),
    },
  });
  return listOf(scans).length > 0;
}

/**
 * The AI frameworks as the Compliance page's universal framework cards show
 * them, scoped to the AI-SPM providers the filters select.
 */
export async function getAiFrameworks(
  filters: Record<string, string>,
): Promise<CrossProviderFrameworkSummary[]> {
  const catalog = await loadCrossProviderFrameworks();
  const frameworks = catalog.frameworks.filter(({ complianceId }) =>
    AI_FRAMEWORK_IDS.includes(complianceId),
  );
  const responses = await Promise.all(
    frameworks.map(async (entry) => ({
      entry,
      result: await getCrossProviderComplianceOverview({
        complianceId: entry.complianceId,
        filters: parseCrossProviderFilters(filters),
      }),
    })),
  );
  // A framework that failed to load is left out rather than shown as unscanned.
  return responses
    .filter(
      ({ result }) =>
        result.status === CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS,
    )
    .map(({ entry, result }) => toCrossProviderSummary(entry, result));
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

  const [statuses, categories, scanned, severity, vendorGroups, cloudGroups] =
    await Promise.all([
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
      Promise.all(
        types.map((type) =>
          hasCompletedScan(
            providers
              .filter((provider) => provider.attributes.provider === type)
              .map((provider) => provider.id),
          ),
        ),
      ),
      vendorFailed && getFindingsBySeverity({ filters: vendorFailed }),
      vendorFailed &&
        getLatestFindingGroups({
          pageSize: TOP_RISKS,
          filters: vendorFailed,
        }),
      cloudScope ? getCloudAiFindingGroups(cloudScope) : [],
    ]);

  // Object.fromEntries defines own properties, so a provider type cannot reach the prototype.
  const results: Record<string, FindingsStatusAttributes> = Object.fromEntries(
    statuses.flatMap((status, index) => {
      const attributes =
        status && "data" in status ? status.data?.attributes : undefined;
      return attributes ? [[vendorTypes[index], attributes]] : [];
    }),
  );
  const cloudResults: Record<string, CategoryOverviewAttributes> =
    Object.fromEntries(
      categories.flatMap((category, index) =>
        // No row for gen-ai means no gen-ai findings in the latest scans.
        category && "data" in category && Array.isArray(category.data)
          ? [
              [
                cloudTypes[index],
                category.data.find(({ id }) => id === AI_CATEGORY)
                  ?.attributes ?? {
                  total_findings: 0,
                  failed_findings: 0,
                  new_failed_findings: 0,
                  severity: NO_SEVERITY,
                },
              ],
            ]
          : [],
      ),
    );
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
    scannedTypes: types.filter((_, index) => scanned[index]),
    severity: severityCounts ?? NO_SEVERITY,
    findingGroups: [...listOf<AiFindingGroup>(vendorGroups), ...cloudGroups],
  });
}
