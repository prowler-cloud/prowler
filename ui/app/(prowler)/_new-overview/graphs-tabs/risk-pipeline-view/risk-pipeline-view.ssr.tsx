import {
  adaptProvidersOverviewToSankey,
  getFindingsBySeverity,
  getProvidersOverview,
  SankeyFilters,
} from "@/actions/overview";
import { getProviders } from "@/actions/providers";
import { SankeyChart } from "@/components/graphs/sankey-chart";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../_lib/filter-params";

export async function RiskPipelineViewSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  // Check if any provider/account filter is active
  const providerTypeFilter = filters["filter[provider_type__in]"];
  const providerIdFilter = filters["filter[provider_id__in]"];

  // Fetch data in parallel
  const [providersResponse, severityResponse, providersListResponse] =
    await Promise.all([
      getProvidersOverview({ filters }),
      getFindingsBySeverity({ filters }),
      // Only fetch providers list if we need to look up account IDs
      providerIdFilter && !providerTypeFilter
        ? getProviders({ pageSize: 200 })
        : Promise.resolve(null),
    ]);

  // Determine provider types to show
  let providerTypesToShow: string[] | undefined;

  if (providerTypeFilter) {
    // Provider type filter is set - use it directly
    providerTypesToShow = String(providerTypeFilter)
      .split(",")
      .map((t) => t.trim().toLowerCase());
  } else if (providerIdFilter && providersListResponse?.data) {
    // Account filter is set - look up provider types from account IDs
    const selectedAccountIds = String(providerIdFilter)
      .split(",")
      .map((id) => id.trim());

    const providerTypesSet = new Set<string>();
    for (const accountId of selectedAccountIds) {
      const provider = providersListResponse.data.find(
        (p) => p.id === accountId,
      );
      if (provider) {
        providerTypesSet.add(provider.attributes.provider.toLowerCase());
      }
    }
    providerTypesToShow = Array.from(providerTypesSet);
  }

  // Build sankey filters
  const sankeyFilters: SankeyFilters = {
    providerTypes: providerTypesToShow,
    allSelectedProviderTypes: providerTypesToShow,
  };

  const sankeyData = adaptProvidersOverviewToSankey(
    providersResponse,
    severityResponse,
    sankeyFilters,
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
