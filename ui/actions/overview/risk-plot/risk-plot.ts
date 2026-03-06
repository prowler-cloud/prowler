"use server";

import { getFindingsBySeverity } from "@/actions/overview/findings";
import { getThreatScore } from "@/actions/overview/threat-score";
import { ProviderProps } from "@/types/providers";

import { ProviderRiskData } from "./types/risk-plot.types";

/**
 * Fetches risk data for a single provider.
 * Combines ThreatScore and Severity data in parallel.
 */
export async function getProviderRiskData(
  provider: ProviderProps,
): Promise<ProviderRiskData> {
  const providerId = provider.id;
  const providerType = provider.attributes.provider;
  const providerName = provider.attributes.alias || provider.attributes.uid;

  // Fetch ThreatScore and Severity in parallel
  const [threatScoreResponse, severityResponse] = await Promise.all([
    getThreatScore({
      filters: {
        provider_id: providerId,
        include: "provider",
      },
    }),
    getFindingsBySeverity({
      filters: {
        "filter[provider_id]": providerId,
        "filter[status]": "FAIL",
      },
    }),
  ]);

  // Extract ThreatScore data
  // When filtering by single provider, API returns array with one item (not aggregated)
  const threatScoreData = threatScoreResponse?.data?.[0]?.attributes;
  const overallScore = threatScoreData?.overall_score
    ? parseFloat(threatScoreData.overall_score)
    : null;
  const failedFindings = threatScoreData?.failed_findings ?? 0;

  // Extract Severity data
  const severityData = severityResponse?.data?.attributes ?? null;

  return {
    providerId,
    providerType,
    providerName,
    overallScore,
    failedFindings,
    severity: severityData,
  };
}

/**
 * Fetches risk data for multiple providers in parallel.
 * Used by the Risk Plot SSR component.
 */
export async function getProvidersRiskData(
  providers: ProviderProps[],
): Promise<ProviderRiskData[]> {
  const riskDataPromises = providers.map((provider) =>
    getProviderRiskData(provider),
  );

  return Promise.all(riskDataPromises);
}
