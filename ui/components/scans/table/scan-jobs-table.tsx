"use client";

import { DataTable } from "@/components/ui/table";
import type { MetaDataProps, ScanJobsTab, ScanProps } from "@/types";
import { SCAN_JOBS_TAB } from "@/types";

import { AutoRefresh } from "../auto-refresh";
import { NoScansEmptyState } from "../no-scans-empty-state";
import { getScanJobsColumns } from "./scan-jobs-columns";

interface ScanJobsTableProps {
  data: ScanProps[];
  meta?: MetaDataProps;
  tab: ScanJobsTab;
  hasFilters?: boolean;
}

const REFRESHING_STATES = ["available", "executing"] as const;

export function ScanJobsTable({
  data,
  meta,
  tab,
  hasFilters = false,
}: ScanJobsTableProps) {
  const hasRefreshingScan = data.some((scan) =>
    REFRESHING_STATES.includes(
      scan.attributes.state as (typeof REFRESHING_STATES)[number],
    ),
  );
  const columns = getScanJobsColumns({ tab });
  const showEmptyState = data.length === 0 && !hasFilters;

  return (
    <>
      <AutoRefresh hasExecutingScan={hasRefreshingScan} />
      {showEmptyState ? (
        <NoScansEmptyState tab={tab} />
      ) : (
        <DataTable
          key={`scan-jobs-${tab}-${meta?.pagination?.page ?? 1}`}
          columns={columns}
          data={data}
          metadata={meta}
          // Anchor the view-first-scan tour's "in-progress" step to the first row of
          // the active (In Progress) tab; absent on other tabs so the tour only points
          // at a running scan.
          getRowAttributes={(row) =>
            row.index === 0 && tab === SCAN_JOBS_TAB.ACTIVE
              ? { "data-tour-id": "view-first-scan-in-progress" }
              : {}
          }
        />
      )}
    </>
  );
}
