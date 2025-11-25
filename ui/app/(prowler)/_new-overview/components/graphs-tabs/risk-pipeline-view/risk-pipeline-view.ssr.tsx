import {
  adaptProvidersOverviewToSankey,
  getProvidersOverview,
} from "@/actions/overview";
import { SankeyChart } from "@/components/graphs/sankey-chart";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../../lib/filter-params";

export async function RiskPipelineViewSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  const response = await getProvidersOverview({ filters });
  const sankeyData = adaptProvidersOverviewToSankey(response);

  if (sankeyData.nodes.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <p className="text-text-neutral-tertiary text-sm">
          No provider data available
        </p>
      </div>
    );
  }

  return (
    <div className="w-full flex-1 overflow-visible">
      <SankeyChart data={sankeyData} height={460} />
    </div>
  );
}
