import { getTHREATSCORE } from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { THREATSCORE } from "./_components/threat-score";

export const ThreatScoreSSR = async ({ searchParams }: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);
  const THREATSCOREData = await getTHREATSCORE({ filters });

  // If no data, pass undefined score and let component handle empty state
  if (!THREATSCOREData?.data || THREATSCOREData.data.length === 0) {
    return <THREATSCORE />;
  }

  // Get the first snapshot (aggregated or single provider)
  const snapshot = THREATSCOREData.data[0];
  const attributes = snapshot.attributes;

  // Parse score from decimal string to number
  const score = parseFloat(attributes.overall_score);
  const scoreDelta = attributes.score_delta
    ? parseFloat(attributes.score_delta)
    : null;

  return (
    <THREATSCORE
      score={score}
      scoreDelta={scoreDelta}
      sectionScores={attributes.section_scores}
      criticalRequirements={attributes.critical_requirements}
    />
  );
};
