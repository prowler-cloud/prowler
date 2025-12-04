import { getFindingsSeverityTrends } from "@/actions/overview/severity-trends";

import { SSRComponentProps } from "../_types";
import { pickFilterParams } from "../_lib/filter-params";
import { FindingSeverityOverTime } from "./_components/finding-severity-over-time";

export const FindingSeverityOverTimeDetailSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const severityTrends = await getFindingsSeverityTrends({ filters });

  if (
    !severityTrends ||
    !severityTrends.data ||
    severityTrends.data.length === 0
  ) {
    return (
      <div className="border-border-neutral-primary bg-bg-neutral-secondary flex h-[400px] w-full items-center justify-center rounded-xl border">
        <p className="text-text-neutral-tertiary">
          Failed to load severity trends data
        </p>
      </div>
    );
  }

  return (
    <div className="border-border-neutral-primary bg-bg-neutral-secondary overflow-visible rounded-lg border p-4">
      <h3 className="text-text-neutral-primary mb-4 text-lg font-semibold">
        Finding Severity Over Time
      </h3>
      <FindingSeverityOverTime data={severityTrends.data} />
    </div>
  );
};
