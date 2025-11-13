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

  // If no data, pass undefined score and let component handle empty state
  if (!threatScoreData?.data || threatScoreData.data.length === 0) {
    return <ThreatScore />;
  }

  // Get the first snapshot (aggregated or single provider)
  const snapshot = threatScoreData.data[0];
  const attributes = snapshot.attributes;

  // Parse score from decimal string to number and round to integer
  const score = Math.round(parseFloat(attributes.overall_score));
  const scoreDelta = attributes.score_delta
    ? Math.round(parseFloat(attributes.score_delta))
    : null;

  return (
    <ThreatScore
      score={score}
      scoreDelta={scoreDelta}
      sectionScores={attributes.section_scores}
      criticalRequirements={attributes.critical_requirements}
    />
  );
};
