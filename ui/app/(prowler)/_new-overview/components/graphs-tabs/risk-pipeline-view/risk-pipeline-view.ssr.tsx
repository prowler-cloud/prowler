import {
  adaptToSankeyData,
  getProvidersSeverityOverview,
  SeverityByProviderType,
} from "@/actions/overview";
import { getProviders } from "@/actions/providers";
import { SankeyChart } from "@/components/graphs/sankey-chart";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../../lib/filter-params";

export async function RiskPipelineViewSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  const providerTypeFilter = filters["filter[provider_type__in]"];
  const providerIdFilter = filters["filter[provider_id__in]"];

  // If accounts are selected, remove provider_type filter since accounts are more specific
  const apiFilters = { ...filters };
  if (providerIdFilter) {
    delete apiFilters["filter[provider_type__in]"];
  }

  // Fetch providers severity data
  // If accounts are filtered, also fetch provider details to know their types
  const [providersSeverityResponse, providersListResponse] = await Promise.all([
    getProvidersSeverityOverview({ filters: apiFilters }),
    // Only fetch providers list if we have account filter (to get their types for zero-data display)
    providerIdFilter
      ? getProviders({ filters: { "filter[id__in]": providerIdFilter } })
      : null,
  ]);

  // Build severityByProviderType from the endpoint response
  const severityByProviderType: SeverityByProviderType = {};

  if (providersSeverityResponse?.data) {
    for (const provider of providersSeverityResponse.data) {
      const providerType = provider.id.toLowerCase();
      severityByProviderType[providerType] = provider.attributes;
    }
  }

  // Determine selected provider types for zero-data display
  let selectedProviderTypes: string[] | undefined;

  if (providerIdFilter && providersListResponse?.data) {
    // Get unique provider types from the selected accounts
    const typesSet = new Set<string>();
    for (const provider of providersListResponse.data) {
      typesSet.add(provider.attributes.provider.toLowerCase());
    }
    selectedProviderTypes = Array.from(typesSet);
  } else if (providerTypeFilter) {
    selectedProviderTypes = String(providerTypeFilter)
      .split(",")
      .map((t) => t.trim().toLowerCase());
  }

  const sankeyData = adaptToSankeyData(
    severityByProviderType,
    selectedProviderTypes,
  );

  // If no chart data and no zero-data providers, show empty state message
  if (
    sankeyData.nodes.length === 0 &&
    sankeyData.zeroDataProviders.length === 0
  ) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <p className="text-text-neutral-tertiary text-sm">
          No findings data available for the selected filters
        </p>
      </div>
    );
  }

  // If no chart data but there are zero-data providers, show only the legend
  if (sankeyData.nodes.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <div className="text-center">
          <p className="text-text-neutral-tertiary mb-4 text-sm">
            No failed findings for the selected accounts
          </p>
          <SankeyChart
            data={sankeyData}
            zeroDataProviders={sankeyData.zeroDataProviders}
            height={100}
          />
        </div>
      </div>
    );
  }

  return (
    <div className="w-full flex-1 overflow-visible">
      <SankeyChart
        data={sankeyData}
        zeroDataProviders={sankeyData.zeroDataProviders}
        height={460}
      />
    </div>
  );
}
