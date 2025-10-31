import { getFindingsSeverityTrends } from "@/actions/overview/overview";
import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";
import { SearchParamsProps } from "@/types";

import { FindingSeverityOverTime } from "./finding-severity-over-time";

const FILTER_PREFIX = "filter[";

function pickFilterParams(
  params: SearchParamsProps | undefined | null,
): Record<string, string | string[] | undefined> {
  if (!params) return {};
  return Object.fromEntries(
    Object.entries(params).filter(([key]) => key.startsWith(FILTER_PREFIX)),
  );
}

export const FindingSeverityOverTimeSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const severityTrends = await getFindingsSeverityTrends({ filters });

  if (
    !severityTrends ||
    !severityTrends.data ||
    severityTrends.data.length === 0
  ) {
    return (
      <div className="flex h-[400px] w-full items-center justify-center rounded-xl border border-zinc-900 bg-stone-950">
        <p className="text-zinc-400">Failed to load severity trends data</p>
      </div>
    );
  }

  return (
    <BaseCard className="flex h-full flex-col">
      <CardHeader className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <CardTitle>Finding Severity Over Time</CardTitle>
        </div>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col px-6">
        <FindingSeverityOverTime data={severityTrends.data} />
      </CardContent>
    </BaseCard>
  );
};
