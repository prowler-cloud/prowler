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
  toAiSecurityOverview,
} from "@/app/(prowler)/ai-security/_lib/overview";
import type { AiSecurityOverview } from "@/app/(prowler)/ai-security/_types";
import type { ComplianceOverviewData } from "@/types/compliance";
import type { ProviderProps } from "@/types/providers";

const TOP_RISKS = 6;

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
 * The AI Security overview of the AI providers in scope, from the latest scans.
 * Null when the findings totals could not be loaded.
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
    results,
    severity: severityCounts,
    frameworks,
    findingGroups: listOf<AiFindingGroup>(findingGroups),
  });
}
