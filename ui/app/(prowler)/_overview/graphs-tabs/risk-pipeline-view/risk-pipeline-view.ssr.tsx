import {
  adaptToSankeyData,
  getFindingsBySeverity,
  SeverityByProviderType,
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

  const providerTypeFilter = filters["filter[provider_type__in]"];
  const providerIdFilter = filters["filter[provider_id__in]"];

  // Fetch providers list to know account types
  const providersListResponse = await getProviders({ pageSize: 200 });
  const allProviders = providersListResponse?.data || [];

  // Build severityByProviderType based on filters
  const severityByProviderType: SeverityByProviderType = {};
  let selectedProviderTypes: string[] | undefined;

  if (providerIdFilter) {
    // Case: Accounts are selected - group by provider type and make parallel calls
    const selectedAccountIds = String(providerIdFilter)
      .split(",")
      .map((id) => id.trim());

    // Group selected accounts by provider type
    const accountsByType: Record<string, string[]> = {};
    for (const accountId of selectedAccountIds) {
      const provider = allProviders.find((p) => p.id === accountId);
      if (provider) {
        const type = provider.attributes.provider.toLowerCase();
        if (!accountsByType[type]) {
          accountsByType[type] = [];
        }
        accountsByType[type].push(accountId);
      }
    }

    selectedProviderTypes = Object.keys(accountsByType);

    // Make parallel calls for each provider type
    const severityPromises = Object.entries(accountsByType).map(
      async ([providerType, accountIds]) => {
        const response = await getFindingsBySeverity({
          filters: {
            "filter[provider_id__in]": accountIds.join(","),
            "filter[status]": "FAIL", // Only count failed findings
          },
        });
        return { providerType, data: response?.data?.attributes };
      },
    );

    const severityResults = await Promise.all(severityPromises);

    for (const result of severityResults) {
      if (result.data) {
        severityByProviderType[result.providerType] = result.data;
      }
    }
  } else if (providerTypeFilter) {
    // Case: Provider types are selected - make parallel calls for each type
    selectedProviderTypes = String(providerTypeFilter)
      .split(",")
      .map((t) => t.trim().toLowerCase());

    const severityPromises = selectedProviderTypes.map(async (providerType) => {
      const response = await getFindingsBySeverity({
        filters: {
          ...filters,
          "filter[provider_type__in]": providerType,
          "filter[status]": "FAIL", // Only count failed findings
        },
      });
      return { providerType, data: response?.data?.attributes };
    });

    const severityResults = await Promise.all(severityPromises);

    for (const result of severityResults) {
      if (result.data) {
        severityByProviderType[result.providerType] = result.data;
      }
    }
  } else {
    // Case: No filters - get all provider types and make parallel calls
    const allProviderTypes = Array.from(
      new Set(allProviders.map((p) => p.attributes.provider.toLowerCase())),
    );

    const severityPromises = allProviderTypes.map(async (providerType) => {
      const response = await getFindingsBySeverity({
        filters: {
          ...filters,
          "filter[provider_type__in]": providerType,
          "filter[status]": "FAIL", // Only count failed findings
        },
      });
      return { providerType, data: response?.data?.attributes };
    });

    const severityResults = await Promise.all(severityPromises);

    for (const result of severityResults) {
      if (result.data) {
        severityByProviderType[result.providerType] = result.data;
      }
    }
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
