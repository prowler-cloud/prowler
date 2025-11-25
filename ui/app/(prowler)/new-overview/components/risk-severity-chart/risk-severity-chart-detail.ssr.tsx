import { getFindingsBySeverity } from "@/actions/overview/overview";
import { getProviders } from "@/actions/providers";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { RiskSeverityChart } from "./risk-severity-chart";

export const RiskSeverityChartDetailSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const [findingsBySeverity, providersData] = await Promise.all([
    getFindingsBySeverity({ filters }),
    getProviders({ page: 1, pageSize: 200 }),
  ]);

  if (!findingsBySeverity) {
    return (
      <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load severity data</p>
      </div>
    );
  }

  const {
    critical = 0,
    high = 0,
    medium = 0,
    low = 0,
    informational = 0,
  } = findingsBySeverity?.data?.attributes || {};

  return (
    <RiskSeverityChart
      critical={critical}
      high={high}
      medium={medium}
      low={low}
      informational={informational}
      providers={providersData?.data}
    />
  );
};
