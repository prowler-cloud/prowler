import { getThreatScore } from "@/actions/overview/overview";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { ThreatScore } from "./threat-score";

export const ThreatScoreSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);
  const threatScoreData = await getThreatScore({ filters });

  // Check if provider filters are present
  const hasProviderFilters =
    !!searchParams?.["filter[provider_id__in]"] ||
    !!searchParams?.["filter[provider_type__in]"];

  // If no data, pass undefined score and let component handle empty state
  if (!threatScoreData?.data || threatScoreData.data.length === 0) {
    return <ThreatScore hasProviderFilters={hasProviderFilters} />;
  }

  // Get the first snapshot (aggregated or single provider)
  const snapshot = threatScoreData.data[0];
  const attributes = snapshot.attributes;

  // Parse score from decimal string to number with 2 decimals
  const score = parseFloat(Number(attributes.overall_score).toFixed(2));
  const scoreDelta = attributes.score_delta
    ? parseFloat(Number(attributes.score_delta).toFixed(2))
    : null;

  return (
    <ThreatScore
      score={score}
      scoreDelta={scoreDelta}
      sectionScores={attributes.section_scores}
      criticalRequirements={attributes.critical_requirements}
      hasProviderFilters={hasProviderFilters}
    />
  );
};
