import { Info } from "lucide-react";

import {
  adaptCategoryOverviewToRadarData,
  getCategoryOverview,
} from "@/actions/overview/risk-radar";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../_lib/filter-params";
import { RiskRadarViewClient } from "./risk-radar-view-client";

export async function RiskRadarViewSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);

  // Fetch category overview data
  const categoryResponse = await getCategoryOverview({ filters });

  // Transform to radar chart format
  const radarData = adaptCategoryOverviewToRadarData(categoryResponse);

  // No data available
  if (radarData.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-center">
          <Info size={48} className="text-text-neutral-tertiary" />
          <p className="text-text-neutral-secondary text-sm">
            No category data available for the selected filters
          </p>
        </div>
      </div>
    );
  }

  return <RiskRadarViewClient data={radarData} />;
}
