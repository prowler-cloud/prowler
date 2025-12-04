import { getFindingsSeverityTrends } from "@/actions/overview/severity-trends";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { FindingSeverityOverTime } from "./_components/finding-severity-over-time";

const EmptyState = ({ message }: { message: string }) => (
  <div className="border-border-neutral-primary bg-bg-neutral-secondary flex h-[400px] w-full items-center justify-center rounded-xl border">
    <p className="text-text-neutral-tertiary">{message}</p>
  </div>
);

export const FindingSeverityOverTimeDetailSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);
  const result = await getFindingsSeverityTrends({ filters });

  if (result.status === "error") {
    return <EmptyState message="Failed to load severity trends data" />;
  }

  if (result.status === "empty") {
    return <EmptyState message="No severity trends data available" />;
  }

  return (
    <div className="border-border-neutral-primary bg-bg-neutral-secondary overflow-visible rounded-lg border p-4">
      <h3 className="text-text-neutral-primary mb-4 text-lg font-semibold">
        Finding Severity Over Time
      </h3>
      <FindingSeverityOverTime data={result.data.data} />
    </div>
  );
};
