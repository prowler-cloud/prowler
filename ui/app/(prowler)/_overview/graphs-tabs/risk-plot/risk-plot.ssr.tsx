import { Info } from "lucide-react";

import { OVERVIEW_FILTER_PARAM } from "@/actions/overview/overview-filters";
import {
  adaptToRiskPlotData,
  getProvidersRiskData,
} from "@/actions/overview/risk-plot";
import { getAllProviders } from "@/actions/providers";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../_lib/filter-params";
import {
  filterProvidersByScope,
  parseFilterIds,
} from "../../_lib/provider-scope";
import { RiskPlotClient } from "./risk-plot-client";

export async function RiskPlotSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  // Fetch all providers
  const providersListResponse = await getAllProviders();
  const allProviders = providersListResponse?.data || [];

  // Compose every active provider-scope filter with AND so combining e.g. a
  // group and a type narrows to providers matching both.
  const filteredProviders = filterProvidersByScope(allProviders, {
    providerIds: parseFilterIds(filters[OVERVIEW_FILTER_PARAM.PROVIDER_ID]),
    providerTypes: parseFilterIds(filters[OVERVIEW_FILTER_PARAM.PROVIDER_TYPE]),
    providerGroupIds: parseFilterIds(
      filters[OVERVIEW_FILTER_PARAM.PROVIDER_GROUPS],
    ),
  });

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
