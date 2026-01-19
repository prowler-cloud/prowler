import { getSeverityTrendsByTimeRange } from "@/actions/overview/severity-trends";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { FindingSeverityOverTime } from "./_components/finding-severity-over-time";
import { FindingSeverityOverTimeSkeleton } from "./_components/finding-severity-over-time.skeleton";
import { DEFAULT_TIME_RANGE } from "./_constants/time-range.constants";

export { FindingSeverityOverTimeSkeleton };

const EmptyState = ({ message }: { message: string }) => (
  <Card variant="base" className="flex h-full min-h-[405px] flex-1 flex-col">
    <CardHeader className="flex flex-col gap-4">
      <div className="flex items-center justify-between">
        <CardTitle>Findings Severity Over Time</CardTitle>
      </div>
    </CardHeader>
    <CardContent className="flex flex-1 items-center justify-center">
      <p className="text-text-neutral-tertiary">{message}</p>
    </CardContent>
  </Card>
);

export const FindingSeverityOverTimeSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const result = await getSeverityTrendsByTimeRange({
    timeRange: DEFAULT_TIME_RANGE,
    filters,
  });

  if (result.status === "error") {
    return <EmptyState message="Failed to load severity trends data" />;
  }

  if (result.status === "empty") {
    return <EmptyState message="No severity trends data available" />;
  }

  return (
    <Card variant="base" className="flex h-full flex-1 flex-col">
      <CardHeader className="flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <CardTitle>Findings Severity Over Time</CardTitle>
        </div>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col px-6">
        <FindingSeverityOverTime data={result.data.data} />
      </CardContent>
    </Card>
  );
};
