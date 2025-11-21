import { getCompliancesOverview } from "@/actions/compliances";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { SearchParamsProps } from "@/types";
import { ComplianceOverviewData } from "@/types/compliance";

import { pickFilterParams } from "../../lib/filter-params";
import {
  buildComplianceWatchlistItem,
  ComplianceWatchlist,
} from "./compliance-watchlist";

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const compliancesResponse = await getCompliancesOverview({
    filters,
  });

  const compliances =
    Array.isArray(compliancesResponse?.data) &&
    (compliancesResponse.data as ComplianceOverviewData[]).length > 0
      ? (compliancesResponse.data as ComplianceOverviewData[])
      : [];

  const sorted = compliances
    .map((compliance) => {
      const { attributes } = compliance;
      const { requirements_passed, total_requirements } = attributes;

      const totalRequirements = Number(total_requirements) || 0;
      const passedRequirements = Number(requirements_passed) || 0;
      const score =
        totalRequirements > 0
          ? Math.round((passedRequirements / totalRequirements) * 100)
          : 0;

      return { ...compliance, score };
    })
    .sort((a, b) => {
      const aIsThreat = a.attributes.framework === "ProwlerThreatScore";
      const bIsThreat = b.attributes.framework === "ProwlerThreatScore";

      if (aIsThreat && !bIsThreat) return -1;
      if (bIsThreat && !aIsThreat) return 1;

      return a.score - b.score;
    })
    .slice(0, 9);

  const items = sorted.map((compliance) => {
    const { attributes, id, score } = compliance;
    const { framework, version, requirements_passed, total_requirements } =
      attributes;

    const iconSrc = getComplianceIcon(framework);

    return buildComplianceWatchlistItem({
      id,
      framework,
      version,
      requirements_passed,
      total_requirements,
      icon: iconSrc,
      score,
    });
  });

  return <ComplianceWatchlist items={items} />;
};
