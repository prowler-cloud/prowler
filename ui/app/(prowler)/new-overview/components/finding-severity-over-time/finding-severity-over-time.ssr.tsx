import { getFindingsSeverityTrends } from "@/actions/overview/overview";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import {
  FindingSeverityOverTime,
  FindingSeverityOverTimeSkeleton,
} from "./finding-severity-over-time";

export { FindingSeverityOverTimeSkeleton };

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
    <Card variant="base" className="flex h-full flex-col">
      <CardHeader className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <CardTitle>Finding Severity Over Time</CardTitle>
        </div>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col px-6">
        <FindingSeverityOverTime data={severityTrends.data} />
      </CardContent>
    </Card>
  );
};
