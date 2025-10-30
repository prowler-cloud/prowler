import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { getFindingsBySeverity } from "@/actions/overview/overview";
import { SearchParamsProps } from "@/types";
import { RiskSeverityChart } from "./risk-severity-chart";

const FILTER_PREFIX = "filter[";

function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export const RiskSeverityChartSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
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
    <BaseCard className="flex h-full flex-col">
      <CardHeader>
        <CardTitle>Risk Severity</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 items-center justify-start px-6">
        <RiskSeverityChart
          critical={critical}
          high={high}
          medium={medium}
          low={low}
          informational={informational}
        />
      </CardContent>
    </BaseCard>
  );
};