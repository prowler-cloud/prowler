import { AttributesData, RequirementsData } from "@/types/compliance";

export interface ThreatScoreResult {
  score: number;
}

/**
 * Calculates the ThreatScore for a given provider's compliance data.
 * This function replicates the calculation logic from the server-side getThreatScore
 * but operates on already-fetched attribute and requirement data.
 *
 * @param attributesData - Compliance attributes containing metadata like Weight and LevelOfRisk
 * @param requirementsData - Compliance requirements containing passed and total findings
 * @returns The calculated ThreatScore or null if calculation fails
 */
export function calculateThreatScore(
  attributesData: AttributesData | undefined,
  requirementsData: RequirementsData | undefined,
): ThreatScoreResult | null {
  if (!attributesData?.data || !requirementsData?.data) {
    return null;
  }

  // Create requirements map for fast lookup
  const requirementsMap = new Map();
  for (const req of requirementsData.data) {
    requirementsMap.set(req.id, req);
  }

  // Calculate ThreatScore using the same formula as the server-side version
  let numerator = 0;
  let denominator = 0;
  let hasFindings = false;

  for (const attributeItem of attributesData.data) {
    const id = attributeItem.id;
    const metadataArray = attributeItem.attributes?.attributes
      ?.metadata as any[];
    const attrs = metadataArray?.[0];
    if (!attrs) continue;

    const requirementData = requirementsMap.get(id);
    if (!requirementData) continue;

    const pass_i = requirementData.attributes.passed_findings || 0;
    const total_i = requirementData.attributes.total_findings || 0;

    if (total_i === 0) continue;

    hasFindings = true;
    const rate_i = pass_i / total_i;
    const weight_i = attrs.Weight || 1;
    const levelOfRisk = attrs.LevelOfRisk || 0;
    const rfac_i = 1 + 0.25 * levelOfRisk;

    numerator += rate_i * total_i * weight_i * rfac_i;
    denominator += total_i * weight_i * rfac_i;
  }

  const score = !hasFindings
    ? 100
    : denominator > 0
      ? (numerator / denominator) * 100
      : 0;

  return {
    score: Math.round(score * 100) / 100,
  };
}
