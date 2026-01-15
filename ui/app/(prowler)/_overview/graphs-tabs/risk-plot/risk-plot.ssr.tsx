import { Info } from "lucide-react";

import {
  adaptToRiskPlotData,
  getProvidersRiskData,
} from "@/actions/overview/risk-plot";
import { getProviders } from "@/actions/providers";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../_lib/filter-params";
import { RiskPlotClient } from "./risk-plot-client";

export async function RiskPlotSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  const providerTypeFilter = filters["filter[provider_type__in]"];
  const providerIdFilter = filters["filter[provider_id__in]"];

  // Fetch all providers
  const providersListResponse = await getProviders({ pageSize: 200 });
  const allProviders = providersListResponse?.data || [];

  // Filter providers based on search params
  let filteredProviders = allProviders;

  if (providerIdFilter) {
    // Filter by specific provider IDs
    const selectedIds = String(providerIdFilter)
      .split(",")
      .map((id) => id.trim());
    filteredProviders = allProviders.filter((p) => selectedIds.includes(p.id));
  } else if (providerTypeFilter) {
    // Filter by provider types
    const selectedTypes = String(providerTypeFilter)
      .split(",")
      .map((t) => t.trim().toLowerCase());
    filteredProviders = allProviders.filter((p) =>
      selectedTypes.includes(p.attributes.provider.toLowerCase()),
    );
  }

  // No providers to show
  if (filteredProviders.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-center">
          <Info size={48} className="text-text-neutral-tertiary" />
          <p className="text-text-neutral-secondary text-sm">
            No providers available for the selected filters
          </p>
        </div>
      </div>
    );
  }

  // Fetch risk data for all filtered providers in parallel
  const providersRiskData = await getProvidersRiskData(filteredProviders);

  // Transform to chart format
  const { points, providersWithoutData } =
    adaptToRiskPlotData(providersRiskData);

  // No data available
  if (points.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-center">
          <Info size={48} className="text-text-neutral-tertiary" />
          <p className="text-text-neutral-secondary text-sm">
            No risk data available for the selected providers
          </p>
          {providersWithoutData.length > 0 && (
            <p className="text-text-neutral-tertiary text-xs">
              {providersWithoutData.length} provider(s) have no completed scans
            </p>
          )}
        </div>
      </div>
    );
  }

  return (
    <div className="w-full flex-1 overflow-visible">
      <RiskPlotClient data={points} />
    </div>
  );
}
