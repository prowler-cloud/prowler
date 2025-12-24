import {
  adaptRegionsOverviewToThreatMap,
  getRegionsOverview,
} from "@/actions/overview";
import { ThreatMap } from "@/components/graphs/threat-map";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../_lib/filter-params";

export async function ThreatMapViewSSR({
  searchParams,
}: {
  searchParams: SearchParamsProps;
}) {
  const filters = pickFilterParams(searchParams);
  const regionsResponse = await getRegionsOverview({ filters });
  const threatMapData = adaptRegionsOverviewToThreatMap(regionsResponse);

  if (threatMapData.locations.length === 0) {
    return (
      <div className="flex h-[460px] w-full items-center justify-center">
        <p className="text-text-neutral-tertiary text-sm">
          No region data available
        </p>
      </div>
    );
  }

  return (
    <div className="w-full flex-1 overflow-hidden">
      <ThreatMap data={threatMapData} height={460} />
    </div>
  );
}
