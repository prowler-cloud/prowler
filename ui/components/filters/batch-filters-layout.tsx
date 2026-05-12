import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

interface BatchFiltersLayoutProps {
  controls: ReactNode;
  controlsClassName?: string;
  expandedFilters?: ReactNode;
  expandedFiltersVisible?: boolean;
  appliedSummary?: ReactNode;
  appliedActions?: ReactNode;
  pendingSummary?: ReactNode;
  showAppliedRow?: boolean;
  showPendingRow?: boolean;
  testIdPrefix: string;
}

export const BatchFiltersLayout = ({
  controls,
  controlsClassName,
  expandedFilters,
  expandedFiltersVisible = true,
  appliedSummary,
  appliedActions,
  pendingSummary,
  showAppliedRow = false,
  showPendingRow = false,
  testIdPrefix,
}: BatchFiltersLayoutProps) => (
  <div className="flex flex-col gap-3">
    <div
      data-testid={`${testIdPrefix}-filter-controls`}
      className={cn("flex flex-wrap items-center gap-4", controlsClassName)}
    >
      {controls}
    </div>

    {expandedFilters ? (
      <div
        data-testid={`${testIdPrefix}-expanded-filters`}
        className={expandedFiltersVisible ? undefined : "hidden"}
      >
        {expandedFilters}
      </div>
    ) : null}

    {showAppliedRow ? (
      <div
        data-testid={`${testIdPrefix}-applied-filter-row`}
        className="flex flex-wrap items-start gap-2"
      >
        <div className="min-w-[220px] flex-1">{appliedSummary}</div>
        {appliedActions ? (
          <div
            data-testid={`${testIdPrefix}-applied-filter-actions`}
            className="ml-auto flex flex-wrap items-center gap-2"
          >
            {appliedActions}
          </div>
        ) : null}
      </div>
    ) : null}

    {showPendingRow ? (
      <div
        data-testid={`${testIdPrefix}-pending-filter-row`}
        className="flex flex-wrap items-start gap-2"
      >
        <div className="min-w-[220px] flex-1">{pendingSummary}</div>
      </div>
    ) : null}
  </div>
);
