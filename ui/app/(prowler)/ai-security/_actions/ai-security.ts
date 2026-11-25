"use server";

import {
  getComplianceAttributes,
  getComplianceRequirements,
  getCompliancesOverview,
} from "@/actions/compliances";
import { getLatestFindingGroups } from "@/actions/finding-groups";
import {
  type FindingsStatusAttributes,
  getFindingsBySeverity,
  getFindingsByStatus,
} from "@/actions/overview";
import {
  AI_FRAMEWORKS,
  type AiFindingGroup,
  type AiFrameworkSource,
  aiScopeFilters,
  aiSectionChecks,
  toAiRequirements,
  toAiSecurityOverview,
} from "@/app/(prowler)/ai-security/_lib/overview";
import type {
  AiRequirement,
  AiSecurityOverview,
} from "@/app/(prowler)/ai-security/_types";
import { getCrossProviderComplianceOverview } from "@/app/(prowler)/compliance/_actions/cross-provider";
import { CROSS_PROVIDER_OVERVIEW_RESULT_STATUS } from "@/app/(prowler)/compliance/_types";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";

const TOP_RISKS = 6;
// The API's largest page.
const MAX_PAGE_SIZE = 100;

// The actions resolve API errors to objects without `data`; only an array is a list.
const listOf = <T>(response: unknown): T[] => {
  const data = (response as { data?: unknown } | undefined)?.data;
  return Array.isArray(data) ? (data as T[]) : [];
};

async function getFramework(
  overview: ComplianceOverviewData,
  filters: Record<string, string>,
): Promise<AiFrameworkSource> {
  const [requirements, attributes] = await Promise.all([
    getComplianceRequirements({ complianceId: overview.id, filters }),
    getComplianceAttributes(overview.id),
  ]);
  return {
    overview,
    requirements: listOf(requirements),
    attributes: listOf(attributes),
  };
}

/**
 * The AI Security overview from the latest scans: totals of the provider types
 * the filters select, the stack of every AI provider. Null when the findings
 * totals could not be loaded.
 */
export async function getAiSecurityOverview(
  filters: Record<string, string>,
  providers: ProviderProps[],
): Promise<AiSecurityOverview | null> {
  const types = Array.from(
    new Set(providers.map((provider) => provider.attributes.provider)),
  );
  const failed = { ...filters, "filter[status]": "FAIL" };

  const [statuses, severity, compliances, findingGroups] = await Promise.all([
    Promise.all(
      types.map((type) =>
        getFindingsByStatus({
          filters: { ...filters, "filter[provider_type__in]": type },
        }),
      ),
    ),
    getFindingsBySeverity({ filters: failed }),
    getCompliancesOverview({ filters }),
    getLatestFindingGroups({
      pageSize: TOP_RISKS,
      sort: "-severity,-resources_fail",
      filters: failed,
    }),
  ]);

  const severityCounts =
    severity && "data" in severity ? severity.data?.attributes : undefined;
  const results: Record<string, FindingsStatusAttributes> = {};
  statuses.forEach((status, index) => {
    const attributes =
      status && "data" in status ? status.data?.attributes : undefined;
    if (attributes) results[types[index]] = attributes;
  });
  // Without the totals the page would show a misleading empty posture.
  if (!severityCounts || Object.keys(results).length < types.length) {
    return null;
  }

  const frameworks = await Promise.all(
    listOf<ComplianceOverviewData>(compliances)
      .filter((compliance) => Object.hasOwn(AI_FRAMEWORKS, compliance.id))
      .map((compliance) => getFramework(compliance, filters)),
  );

  return toAiSecurityOverview({
    providers,
    types: filters["filter[provider_type__in]"].split(","),
    results,
    severity: severityCounts,
    frameworks,
    findingGroups: listOf<AiFindingGroup>(findingGroups),
  });
}

/**
 * The requirements of one framework section with their checks' results in the
 * latest scans. Loaded when the section is expanded; null when it fails.
 */
export async function getAiSectionRequirements(
  frameworkId: string,
  section: string,
  pageFilters: Record<string, string>,
): Promise<AiRequirement[] | null> {
  const filters = aiScopeFilters(pageFilters);
  if (!filters || !Object.hasOwn(AI_FRAMEWORKS, frameworkId)) return null;

  const overview = await getCrossProviderComplianceOverview({
    complianceId: frameworkId,
    filters: {
      providerTypes: filters["filter[provider_type__in]"],
      providerIds: filters["filter[provider_id__in]"],
      providerGroups: filters["filter[provider_groups__in]"],
    },
  });
  if (overview.status !== CROSS_PROVIDER_OVERVIEW_RESULT_STATUS.SUCCESS) {
    return null;
  }

  const requirements = overview.response.data.attributes.requirements;
  const types = filters["filter[provider_type__in]"].split(",");
  // shortcut: a section with more checks than one page shows the rest as "No findings"; page through if a framework gets there.
  const checks = aiSectionChecks(requirements, section, types).slice(
    0,
    MAX_PAGE_SIZE,
  );
  const findingGroups =
    checks.length > 0
      ? await getLatestFindingGroups({
          pageSize: checks.length,
          filters: { ...filters, "filter[check_id__in]": checks.join(",") },
        })
      : undefined;
  if (checks.length > 0 && !Array.isArray(findingGroups?.data)) return null;

  return toAiRequirements({
    requirements,
    section,
    types,
    findingGroups: listOf<AiFindingGroup>(findingGroups),
  });
}
