import { getFindingsBySeverity } from "@/actions/overview";

import { SSRComponentProps } from "../_types";
import { pickFilterParams } from "../_lib/filter-params";
import { RiskSeverityChart } from "./_components/risk-severity-chart";

export const RiskSeverityChartDetailSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const findingsBySeverity = await getFindingsBySeverity({ filters });

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
    />
  );
};
