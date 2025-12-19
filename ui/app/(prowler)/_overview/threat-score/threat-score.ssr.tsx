import { getThreatScore } from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { ThreatScore } from "./_components/threat-score";

export const ThreatScoreSSR = async ({ searchParams }: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);
  const threatScoreData = await getThreatScore({ filters });

  // If no data, pass undefined score and let component handle empty state
  if (!threatScoreData?.data || threatScoreData.data.length === 0) {
    return <ThreatScore />;
  }

  // Get the first snapshot (aggregated or single provider)
  const snapshot = threatScoreData.data[0];
  const attributes = snapshot.attributes;

  // Parse score from decimal string to number
  const score = parseFloat(attributes.overall_score);
  const scoreDelta = attributes.score_delta
    ? parseFloat(attributes.score_delta)
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
