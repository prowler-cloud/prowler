"use server";

import { getFindingsBySeverity } from "@/actions/overview/findings";
import { getTHREATSCORE } from "@/actions/overview/threat-score";
import { ProviderProps } from "@/types/providers";

import { ProviderRiskData } from "./types/risk-plot.types";

/**
 * Fetches risk data for a single provider.
 * Combines THREATSCORE and Severity data in parallel.
 */
export async function getProviderRiskData(
  provider: ProviderProps,
): Promise<ProviderRiskData> {
  const providerId = provider.id;
  const providerType = provider.attributes.provider;
  const providerName = provider.attributes.alias || provider.attributes.uid;

  // Fetch THREATSCORE and Severity in parallel
  const [THREATSCOREResponse, severityResponse] = await Promise.all([
    getTHREATSCORE({
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

  // Extract THREATSCORE data
  // When filtering by single provider, API returns array with one item (not aggregated)
  const THREATSCOREData = THREATSCOREResponse?.data?.[0]?.attributes;
  const overallScore = THREATSCOREData?.overall_score
    ? parseFloat(THREATSCOREData.overall_score)
    : null;
  const failedFindings = THREATSCOREData?.failed_findings ?? 0;

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
